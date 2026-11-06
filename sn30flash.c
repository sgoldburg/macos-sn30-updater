// sn30flash: macOS firmware flasher for an 8BitDo controller that enumerates in
// update mode as "8BitDo Receiver Fw" (USB 2dc8:3214).
//
// The protocol follows 8BitDo's SN30_Update.exe, the tool shipped for this device
// ID, and was cross-checked against fwupd's "ebitdo" plugin. Where they differ
// the Windows tool wins: the first four header words are byte-swapped, and no
// "set encode ID" step is sent.
//
// Commands:
//   listen [seconds]      Print input reports. Sends nothing.
//   probe                 Ask for firmware version and verification ID. No flash writes.
//   timing                Measure reply time and the reaction to a poll. No flash writes.
//   dump-wire <file.dat>  Print every report a flash would send. No device needed.
//   selftest <file.dat>   Run the flash logic against a simulated controller.
//   flash <file.dat> --yes  Write the firmware. Hard to undo.
//
// Build: clang -std=c11 -Wall -Wextra -O1 -o sn30flash sn30flash.c \
//          -framework IOKit -framework CoreFoundation

#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/hid/IOHIDManager.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define USB_VID 0x2dc8
#define USB_PID 0x3214
#define PRODUCT_NAME "8BitDo Receiver Fw"
#define REPORT_SIZE 64
#define OUT_REPORT_ID 0x81
#define IN_REPORT_ID 0x02
#define BLOCK_SIZE 0x20
#define FW_HDR_SIZE 0x1c

// The only firmware files this tool has been checked against.
static const struct {
    const char *sha256;
    const char *name;
} KNOWN_FIRMWARE[] = {
    {"fdae29ebcb7434cf262967dfc40ff8f17fa20bbad080af3b021dc185a39cbf30", "1.23 For Analogue Dock (81AD)"},
    {"9823303fe0d82daf1c90b0ca96f9b6428a2d23644e923cd0c116a4bbcf1310e3", "5.06 standard SN30 2.4G Nt"},
};

static const char *known_firmware_name(const char *sha) {
    for (size_t i = 0; i < sizeof(KNOWN_FIRMWARE) / sizeof(KNOWN_FIRMWARE[0]); i++)
        if (strcmp(sha, KNOWN_FIRMWARE[i].sha256) == 0) return KNOWN_FIRMWARE[i].name;
    return NULL;
}

// Matches SN30_Update.exe before the header is sent.
#define POLL_SETUP_MS 200
#define SETUP_DEADLINE_MS 5000

// A deliberate difference from SN30_Update.exe, which polls after 10 ms of silence
// during the transfer. Tested on the real controller, a poll makes it resend its last
// reply, and replies normally take about 8 ms, so frequent polling could produce a
// duplicate ACK that looks like approval for the next block. This tool stays in strict
// lockstep: it polls only after a long silence and discards any duplicates that follow.
#define POLL_QUIET_MS 2000
#define DRAIN_MS 50
#define TRANSFER_WAIT_MS 100
// The Windows tool waits indefinitely. Stopping and reporting is safer here.
#define ACK_DEADLINE_MS 15000
#define AFTER_OK_WAIT_MS 2000

enum { CMD_FW_DATA = 0x00, CMD_FW_HEADER = 0x01, CMD_FW_OK = 0x02, CMD_FW_GET_VERSION = 0x04 };
enum { CMD_ACK = 0x14, CMD_NAK = 0x15, CMD_ABORT = 0x18 };
enum { SUB_UPDATE = 0x16, SUB_VERIFY_ID = 0x19, SUB_GET_VERIFY_ID = 0x1a, SUB_TIMEOUT = 0x1d };

enum { RECV_GONE = -1, RECV_TIMEOUT = 0, RECV_OK = 1 };

typedef struct transport {
    int (*send)(struct transport *t, const uint8_t rpt[REPORT_SIZE]);
    int (*recv)(struct transport *t, uint8_t rpt[REPORT_SIZE], int timeout_ms);
    double (*now_ms)(struct transport *t);
    void *ctx;
    FILE *log;
    bool quiet;
} transport_t;

typedef struct {
    uint8_t *data;
    size_t size;
    size_t hdr_off;
    uint8_t hdr[FW_HDR_SIZE];
    uint32_t version, addr, len;
    const uint8_t *payload;
    size_t blocks;
} firmware_t;

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void log_report(transport_t *t, const char *dir, const uint8_t *r, double ms) {
    if (!t->log) return;
    fprintf(t->log, "%10.1f %s", ms, dir);
    for (int i = 0; i < REPORT_SIZE; i++) fprintf(t->log, " %02x", r[i]);
    fputc('\n', t->log);
    fflush(t->log);
}

static int tx(transport_t *t, const uint8_t r[REPORT_SIZE]) {
    log_report(t, "TX", r, t->now_ms(t));
    return t->send(t, r);
}

static int rx(transport_t *t, uint8_t r[REPORT_SIZE], int timeout_ms) {
    int rc = t->recv(t, r, timeout_ms);
    if (rc == RECV_OK) log_report(t, "RX", r, t->now_ms(t));
    return rc;
}

// ---- Packet building ------------------------------------------------------

// pkt_len, then type(0), subtype, cmd_len(le16)=1, cmd
static void make_simple(uint8_t r[REPORT_SIZE], uint8_t sub, uint8_t cmd) {
    memset(r, 0, REPORT_SIZE);
    r[0] = OUT_REPORT_ID;
    r[1] = 5;
    r[2] = 0;
    r[3] = sub;
    r[4] = 1;
    r[5] = 0;
    r[6] = cmd;
}

// pkt_len, type(0), 0x16, cmd_len(le16)=len+3, cmd, payload_len(le16)=len, payload
static void make_data(uint8_t r[REPORT_SIZE], uint8_t cmd, const uint8_t *data, size_t len) {
    memset(r, 0, REPORT_SIZE);
    r[0] = OUT_REPORT_ID;
    r[1] = (uint8_t)(len + 7);
    r[2] = 0;
    r[3] = SUB_UPDATE;
    r[4] = (uint8_t)(len + 3);
    r[5] = (uint8_t)((len + 3) >> 8);
    r[6] = cmd;
    r[7] = (uint8_t)len;
    r[8] = (uint8_t)(len >> 8);
    memcpy(r + 9, data, len);
}

// SN30_Update.exe byte-swaps the first four 32-bit header words only.
static void wire_header(const firmware_t *fw, uint8_t out[FW_HDR_SIZE]) {
    memcpy(out, fw->hdr, FW_HDR_SIZE);
    for (int w = 0; w < 4; w++) {
        uint8_t *p = out + w * 4, a = p[0], b = p[1];
        p[0] = p[3];
        p[1] = p[2];
        p[2] = b;
        p[3] = a;
    }
}

// ---- Firmware file --------------------------------------------------------

static void sha256_hex(const uint8_t *d, size_t n, char out[65]) {
    uint8_t md[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(d, (CC_LONG)n, md);
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) snprintf(out + i * 2, 3, "%02x", md[i]);
}

// Layout: 16-byte start with magic; bytes 0xC-0xD plus 0x200 give the offset of
// the 0x1C-byte image header; the image payload follows it to the end of the file.
static const char *parse_firmware(firmware_t *fw) {
    static const uint8_t magic[4] = {0xee, 0x66, 0x66, 0xee};
    if (fw->size < 0x10 || memcmp(fw->data, magic, 4) != 0) return "bad file magic";
    if (fw->data[0xc] >= 0x80 || fw->data[0xd] >= 0x80) return "unexpected section offset";
    fw->hdr_off = ((size_t)fw->data[0xc] << 8 | fw->data[0xd]) + 0x200;
    if (fw->hdr_off + FW_HDR_SIZE > fw->size) return "image header is past end of file";
    memcpy(fw->hdr, fw->data + fw->hdr_off, FW_HDR_SIZE);
    fw->version = le32(fw->hdr);
    fw->addr = le32(fw->hdr + 4);
    fw->len = le32(fw->hdr + 8);
    if (memcmp(fw->hdr + 12, magic, 4) != 0) return "image header magic is wrong";
    if (fw->len == 0) return "image is empty";
    if (fw->hdr_off + FW_HDR_SIZE + fw->len != fw->size) return "image length does not match file size";
    fw->payload = fw->data + fw->hdr_off + FW_HDR_SIZE;
    fw->blocks = (fw->len + BLOCK_SIZE - 1) / BLOCK_SIZE;
    return NULL;
}

static bool load_firmware(const char *path, firmware_t *fw) {
    memset(fw, 0, sizeof(*fw));
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return false; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    fw->data = malloc(n > 0 ? (size_t)n : 1);
    fw->size = (size_t)n;
    bool ok = n > 0 && fread(fw->data, 1, fw->size, f) == fw->size;
    fclose(f);
    if (!ok) { fprintf(stderr, "Could not read %s\n", path); return false; }
    const char *err = parse_firmware(fw);
    if (err) { fprintf(stderr, "Firmware file rejected: %s\n", err); return false; }
    return true;
}

static void print_firmware(const firmware_t *fw) {
    printf("Firmware: version %u.%02u, address 0x%x, %u bytes, %zu blocks\n",
           fw->version / 100, fw->version % 100, fw->addr, fw->len, fw->blocks);
}

// ---- Protocol -------------------------------------------------------------

typedef enum { MSG_NONE, MSG_ACK, MSG_NAK, MSG_ABORT, MSG_VERSION, MSG_VERIFY_ID } msg_t;

static msg_t classify(const uint8_t *r) {
    if (r[0] != IN_REPORT_ID || r[2] != 0) return MSG_NONE;
    if (r[3] == SUB_VERIFY_ID) return MSG_VERIFY_ID;
    if (r[3] != SUB_UPDATE) return MSG_NONE;
    switch (r[6]) {
        case CMD_ACK: return MSG_ACK;
        case CMD_NAK: return MSG_NAK;
        case CMD_ABORT: return MSG_ABORT;
        case CMD_FW_GET_VERSION: return MSG_VERSION;
        default: return MSG_NONE;
    }
}

static void send_poll(transport_t *t) {
    uint8_t r[REPORT_SIZE];
    make_simple(r, SUB_TIMEOUT, 0);
    tx(t, r);
}

// Sends the request, then waits for one reply type, polling as the Windows tool does.
static int request(transport_t *t, uint8_t sub, uint8_t cmd, msg_t want, uint8_t reply[REPORT_SIZE]) {
    uint8_t r[REPORT_SIZE];
    make_simple(r, sub, cmd);
    if (tx(t, r) != 0) return RECV_GONE;
    double deadline = t->now_ms(t) + SETUP_DEADLINE_MS;
    while (t->now_ms(t) < deadline) {
        int rc = rx(t, reply, POLL_SETUP_MS);
        if (rc == RECV_GONE) return RECV_GONE;
        if (rc == RECV_OK) {
            if (classify(reply) == want) return RECV_OK;
            continue;
        }
        send_poll(t);
    }
    return RECV_TIMEOUT;
}

typedef enum {
    FLASH_OK = 0,
    FLASH_NO_RESPONSE_BEFORE_WRITE,
    FLASH_REJECTED,
    FLASH_STALLED,
    FLASH_DEVICE_GONE,
} flash_result_t;

static const char *flash_result_text(flash_result_t f) {
    switch (f) {
        case FLASH_OK: return "ok";
        case FLASH_NO_RESPONSE_BEFORE_WRITE: return "no reply before writing started";
        case FLASH_REJECTED: return "controller rejected the update";
        case FLASH_STALLED: return "controller stopped responding";
        case FLASH_DEVICE_GONE: return "controller disconnected";
    }
    return "unknown";
}

// ACK-driven: header, ACK, block 1, ACK ... block N, ACK, then the "update OK" command.
// Any rejection stops all sending at once.
static flash_result_t run_flash(transport_t *t, const firmware_t *fw, size_t *blocks_sent, bool *header_sent) {
    uint8_t r[REPORT_SIZE], reply[REPORT_SIZE];
    *blocks_sent = 0;
    *header_sent = false;

    int rc = request(t, SUB_UPDATE, CMD_FW_GET_VERSION, MSG_VERSION, reply);
    if (rc == RECV_GONE) return FLASH_DEVICE_GONE;
    if (rc != RECV_OK) return FLASH_NO_RESPONSE_BEFORE_WRITE;
    if (!t->quiet) {
        uint32_t v = le32(reply + 9);
        printf("Controller reports version %u.%02u\n", v / 100, v % 100);
    }

    rc = request(t, SUB_GET_VERIFY_ID, 0, MSG_VERIFY_ID, reply);
    if (rc == RECV_GONE) return FLASH_DEVICE_GONE;
    if (rc != RECV_OK) return FLASH_NO_RESPONSE_BEFORE_WRITE;

    uint8_t hdr[FW_HDR_SIZE];
    wire_header(fw, hdr);
    make_data(r, CMD_FW_HEADER, hdr, FW_HDR_SIZE);
    if (tx(t, r) != 0) return FLASH_DEVICE_GONE;
    *header_sent = true;

    size_t next = 0;
    double last_ack = t->now_ms(t), last_tx = last_ack;
    bool polled = false;
    for (;;) {
        rc = rx(t, reply, TRANSFER_WAIT_MS);
        if (rc == RECV_GONE) return FLASH_DEVICE_GONE;
        if (rc == RECV_TIMEOUT) {
            double now = t->now_ms(t);
            if (now - last_ack > ACK_DEADLINE_MS) return FLASH_STALLED;
            if (now - last_tx >= POLL_QUIET_MS) {
                send_poll(t);
                polled = true;
                last_tx = t->now_ms(t);
            }
            continue;
        }
        msg_t m = classify(reply);
        if (m == MSG_NAK || m == MSG_ABORT) return FLASH_REJECTED;
        if (m != MSG_ACK) continue;

        // A poll can produce one more copy of this ACK. Nothing new has been sent, so
        // no real ACK can be pending yet, and it is safe to discard what arrives here.
        if (polled) {
            double until = t->now_ms(t) + DRAIN_MS;
            while (t->now_ms(t) < until) {
                rc = rx(t, reply, DRAIN_MS);
                if (rc == RECV_GONE) return FLASH_DEVICE_GONE;
                if (rc == RECV_OK) {
                    m = classify(reply);
                    if (m == MSG_NAK || m == MSG_ABORT) return FLASH_REJECTED;
                }
            }
            polled = false;
        }
        last_ack = t->now_ms(t);
        last_tx = last_ack;

        if (next == fw->blocks) break;

        size_t off = next * BLOCK_SIZE;
        size_t len = fw->len - off < BLOCK_SIZE ? fw->len - off : BLOCK_SIZE;
        make_data(r, CMD_FW_DATA, fw->payload + off, len);
        if (tx(t, r) != 0) return FLASH_DEVICE_GONE;
        next++;
        *blocks_sent = next;
        if (!t->quiet && (next % 32 == 0 || next == fw->blocks)) {
            printf("\rWriting: %3zu%% (%zu/%zu blocks)", next * 100 / fw->blocks, next, fw->blocks);
            fflush(stdout);
        }
    }
    if (!t->quiet) putchar('\n');

    make_simple(r, SUB_UPDATE, CMD_FW_OK);
    if (tx(t, r) != 0) return FLASH_DEVICE_GONE;

    // The Windows tool does not wait for a reply here, so this only records one for the log.
    double until = t->now_ms(t) + AFTER_OK_WAIT_MS;
    while (t->now_ms(t) < until) {
        rc = rx(t, reply, 100);
        if (rc == RECV_GONE) break;
    }
    return FLASH_OK;
}

// ---- Real HID transport ---------------------------------------------------

#define QUEUE_LEN 256

typedef struct {
    IOHIDManagerRef mgr;
    IOHIDDeviceRef dev;
    uint8_t cb_buf[REPORT_SIZE + 8];
    uint8_t queue[QUEUE_LEN][REPORT_SIZE];
    volatile int head, tail;
    bool gone;
} hid_t;

static void hid_input_cb(void *ctx, IOReturn res, void *sender, IOHIDReportType type,
                         uint32_t id, uint8_t *report, CFIndex len) {
    (void)res; (void)sender; (void)type; (void)id;
    hid_t *h = ctx;
    int next = (h->tail + 1) % QUEUE_LEN;
    if (next == h->head) return;
    memset(h->queue[h->tail], 0, REPORT_SIZE);
    memcpy(h->queue[h->tail], report, len > REPORT_SIZE ? REPORT_SIZE : (size_t)len);
    h->tail = next;
}

static void hid_removed_cb(void *ctx, IOReturn res, void *sender) {
    (void)res; (void)sender;
    ((hid_t *)ctx)->gone = true;
}

static double mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static double hid_now(transport_t *t) { (void)t; return mono_ms(); }

static int hid_send(transport_t *t, const uint8_t r[REPORT_SIZE]) {
    hid_t *h = t->ctx;
    if (h->gone) return -1;
    IOReturn rc = IOHIDDeviceSetReport(h->dev, kIOHIDReportTypeOutput, OUT_REPORT_ID, r, REPORT_SIZE);
    if (rc != kIOReturnSuccess) {
        fprintf(stderr, "\nSending to the controller failed (0x%08x)\n", rc);
        return -1;
    }
    return 0;
}

static int hid_recv(transport_t *t, uint8_t r[REPORT_SIZE], int timeout_ms) {
    hid_t *h = t->ctx;
    double end = mono_ms() + timeout_ms;
    for (;;) {
        if (h->head != h->tail) {
            memcpy(r, h->queue[h->head], REPORT_SIZE);
            h->head = (h->head + 1) % QUEUE_LEN;
            return RECV_OK;
        }
        if (h->gone) return RECV_GONE;
        double left = end - mono_ms();
        if (left <= 0) return RECV_TIMEOUT;
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, left / 1000.0, true);
    }
}

static CFNumberRef cfnum(int v) { return CFNumberCreate(NULL, kCFNumberIntType, &v); }

static void product_name(IOHIDDeviceRef d, char *out, size_t n) {
    out[0] = 0;
    CFTypeRef s = IOHIDDeviceGetProperty(d, CFSTR(kIOHIDProductKey));
    if (s && CFGetTypeID(s) == CFStringGetTypeID()) CFStringGetCString(s, out, (CFIndex)n, kCFStringEncodingUTF8);
    size_t l = strlen(out);
    while (l && out[l - 1] == ' ') out[--l] = 0;
}

static int prop_int(IOHIDDeviceRef d, CFStringRef key) {
    int v = 0;
    CFTypeRef p = IOHIDDeviceGetProperty(d, key);
    if (p && CFGetTypeID(p) == CFNumberGetTypeID()) CFNumberGetValue(p, kCFNumberIntType, &v);
    return v;
}

static bool hid_open(hid_t *h) {
    memset(h, 0, sizeof(*h));
    h->mgr = IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDOptionsTypeNone);
    CFMutableDictionaryRef match = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFNumberRef v = cfnum(USB_VID), p = cfnum(USB_PID);
    CFDictionarySetValue(match, CFSTR(kIOHIDVendorIDKey), v);
    CFDictionarySetValue(match, CFSTR(kIOHIDProductIDKey), p);
    IOHIDManagerSetDeviceMatching(h->mgr, match);
    CFRelease(match); CFRelease(v); CFRelease(p);
    IOReturn rc = IOHIDManagerOpen(h->mgr, kIOHIDOptionsTypeNone);
    if (rc != kIOReturnSuccess) {
        fprintf(stderr, "Could not open the HID system (0x%08x)\n", rc);
        return false;
    }
    CFSetRef set = IOHIDManagerCopyDevices(h->mgr);
    CFIndex count = set ? CFSetGetCount(set) : 0;
    if (count != 1) {
        fprintf(stderr, "Expected one controller in update mode (%04x:%04x), found %ld.\n", USB_VID, USB_PID, (long)count);
        if (set) CFRelease(set);
        return false;
    }
    const void *item = NULL;
    CFSetGetValues(set, &item);
    h->dev = (IOHIDDeviceRef)CFRetain(item);
    CFRelease(set);

    char name[128];
    product_name(h->dev, name, sizeof(name));
    // After a 1.23 flash, update mode reports the name with a suffix: "... Fw V1.23".
    if (strncmp(name, PRODUCT_NAME, strlen(PRODUCT_NAME)) != 0) {
        fprintf(stderr, "Unexpected product name: \"%s\"\n", name);
        return false;
    }
    int out_size = prop_int(h->dev, CFSTR(kIOHIDMaxOutputReportSizeKey));
    int in_size = prop_int(h->dev, CFSTR(kIOHIDMaxInputReportSizeKey));
    if (out_size != REPORT_SIZE || in_size != REPORT_SIZE) {
        fprintf(stderr, "Unexpected report sizes: in %d, out %d\n", in_size, out_size);
        return false;
    }
    rc = IOHIDDeviceOpen(h->dev, kIOHIDOptionsTypeNone);
    if (rc != kIOReturnSuccess) {
        fprintf(stderr, "Could not open the controller (0x%08x)\n", rc);
        return false;
    }
    IOHIDDeviceRegisterInputReportCallback(h->dev, h->cb_buf, sizeof(h->cb_buf), hid_input_cb, h);
    IOHIDDeviceRegisterRemovalCallback(h->dev, hid_removed_cb, h);
    IOHIDDeviceScheduleWithRunLoop(h->dev, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    printf("Found %s (%04x:%04x)\n", name, USB_VID, USB_PID);
    return true;
}

// The Mac updater may talk to the same device, so it must not be running.
static bool other_updater_running(void) {
    return system("pgrep -f '[8]BitDo Firmware Updater.app/Contents/MacOS' >/dev/null 2>&1") == 0;
}

static void print_hex(const char *label, const uint8_t *r, int n) {
    printf("%s", label);
    for (int i = 0; i < n; i++) printf(" %02x", r[i]);
    putchar('\n');
}

static int used_len(const uint8_t *r) {
    int n = REPORT_SIZE;
    while (n > 1 && r[n - 1] == 0) n--;
    return n;
}

// ---- Commands -------------------------------------------------------------

static int cmd_listen(int seconds) {
    hid_t h;
    if (!hid_open(&h)) return 1;
    transport_t t = {.send = hid_send, .recv = hid_recv, .now_ms = hid_now, .ctx = &h};
    printf("Listening for %d s. Nothing is sent to the controller.\n", seconds);
    double end = mono_ms() + seconds * 1000.0;
    int count = 0, last_print = 0;
    uint8_t r[REPORT_SIZE], prev[REPORT_SIZE];
    memset(prev, 0xff, sizeof(prev));
    while (mono_ms() < end) {
        int rc = rx(&t, r, 100);
        if (rc == RECV_GONE) { printf("Controller disconnected.\n"); return 1; }
        if (rc == RECV_OK) {
            count++;
            if (memcmp(r, prev, REPORT_SIZE) != 0 && last_print < 40) {
                print_hex("RX", r, used_len(r));
                memcpy(prev, r, REPORT_SIZE);
                last_print++;
            }
        }
    }
    printf("%d input reports received.\n", count);
    return 0;
}

static int cmd_probe(void) {
    if (other_updater_running()) {
        fprintf(stderr, "Quit 8BitDo Firmware Updater first. It may talk to the same device.\n");
        return 2;
    }
    hid_t h;
    if (!hid_open(&h)) return 1;
    FILE *lg = fopen("sn30flash.log", "a");
    transport_t t = {.send = hid_send, .recv = hid_recv, .now_ms = hid_now, .ctx = &h, .log = lg};
    if (lg) fprintf(lg, "--- probe ---\n");
    uint8_t reply[REPORT_SIZE];
    printf("Asking for firmware version...\n");
    int rc = request(&t, SUB_UPDATE, CMD_FW_GET_VERSION, MSG_VERSION, reply);
    if (rc != RECV_OK) { printf("No version reply (%s).\n", rc == RECV_GONE ? "disconnected" : "timed out"); return 1; }
    uint32_t v = le32(reply + 9);
    print_hex("Reply:", reply, used_len(reply));
    printf("Controller reports version %u.%02u\n", v / 100, v % 100);
    printf("Asking for verification ID...\n");
    rc = request(&t, SUB_GET_VERIFY_ID, 0, MSG_VERIFY_ID, reply);
    if (rc != RECV_OK) { printf("No verification ID reply (%s).\n", rc == RECV_GONE ? "disconnected" : "timed out"); return 1; }
    print_hex("Reply:", reply, used_len(reply));
    printf("Probe finished. No firmware data was sent.\n");
    return 0;
}

// Measures reply time for version queries, then shows how the controller reacts to
// one poll. The Windows tool sends both while idle, and neither carries firmware data.
static int cmd_timing(void) {
    if (other_updater_running()) {
        fprintf(stderr, "Quit 8BitDo Firmware Updater first. It may talk to the same device.\n");
        return 2;
    }
    hid_t h;
    if (!hid_open(&h)) return 1;
    FILE *lg = fopen("sn30flash.log", "a");
    transport_t t = {.send = hid_send, .recv = hid_recv, .now_ms = hid_now, .ctx = &h, .log = lg};
    if (lg) fprintf(lg, "--- timing ---\n");
    uint8_t r[REPORT_SIZE], reply[REPORT_SIZE];
    double lo = 1e9, hi = 0, sum = 0;
    int n = 20;
    for (int i = 0; i < n; i++) {
        make_simple(r, SUB_UPDATE, CMD_FW_GET_VERSION);
        double t0 = mono_ms();
        if (tx(&t, r) != 0) return 1;
        int rc;
        do { rc = rx(&t, reply, POLL_SETUP_MS); } while (rc == RECV_OK && classify(reply) != MSG_VERSION);
        if (rc != RECV_OK) { printf("No reply to query %d.\n", i); return 1; }
        double ms = mono_ms() - t0;
        if (ms < lo) lo = ms;
        if (ms > hi) hi = ms;
        sum += ms;
    }
    printf("Reply time over %d queries: min %.1f ms, avg %.1f ms, max %.1f ms\n", n, lo, sum / n, hi);
    printf("Sending one poll and listening for 1 s...\n");
    send_poll(&t);
    double end = mono_ms() + 1000;
    int replies = 0;
    while (mono_ms() < end) {
        int rc = rx(&t, reply, 100);
        if (rc == RECV_GONE) { printf("Controller disconnected.\n"); return 1; }
        if (rc == RECV_OK) { replies++; print_hex("Reply to poll:", reply, used_len(reply)); }
    }
    printf("%d replies to the poll.\n", replies);
    int rc = request(&t, SUB_UPDATE, CMD_FW_GET_VERSION, MSG_VERSION, reply);
    printf(rc == RECV_OK ? "Controller still answers normally after the poll.\n" : "No answer after the poll.\n");
    return rc == RECV_OK ? 0 : 1;
}

static int cmd_dump_wire(const char *path) {
    firmware_t fw;
    if (!load_firmware(path, &fw)) return 1;
    uint8_t r[REPORT_SIZE], hdr[FW_HDR_SIZE];
    make_simple(r, SUB_UPDATE, CMD_FW_GET_VERSION);
    print_hex("get_version", r, REPORT_SIZE);
    make_simple(r, SUB_GET_VERIFY_ID, 0);
    print_hex("get_verify_id", r, REPORT_SIZE);
    make_simple(r, SUB_TIMEOUT, 0);
    print_hex("poll", r, REPORT_SIZE);
    wire_header(&fw, hdr);
    make_data(r, CMD_FW_HEADER, hdr, FW_HDR_SIZE);
    print_hex("header", r, REPORT_SIZE);
    for (size_t i = 0; i < fw.blocks; i++) {
        size_t off = i * BLOCK_SIZE, len = fw.len - off < BLOCK_SIZE ? fw.len - off : BLOCK_SIZE;
        make_data(r, CMD_FW_DATA, fw.payload + off, len);
        print_hex("block", r, REPORT_SIZE);
    }
    make_simple(r, SUB_UPDATE, CMD_FW_OK);
    print_hex("update_ok", r, REPORT_SIZE);
    return 0;
}

static int cmd_flash(const char *path, bool yes) {
    firmware_t fw;
    if (!load_firmware(path, &fw)) return 1;
    char sha[65];
    sha256_hex(fw.data, fw.size, sha);
    print_firmware(&fw);
    const char *known = known_firmware_name(sha);
    if (!known) {
        fprintf(stderr, "Refusing: this is not a firmware file this tool was checked against.\n  got %s\n", sha);
        return 2;
    }
    printf("File: %s\n", known);
    if (other_updater_running()) {
        fprintf(stderr, "Quit 8BitDo Firmware Updater first. It may talk to the same device.\n");
        return 2;
    }
    if (!yes) {
        fprintf(stderr, "Refusing: flashing is hard to undo, so it needs --yes.\n");
        return 2;
    }
    hid_t h;
    if (!hid_open(&h)) return 1;
    FILE *lg = fopen("sn30flash.log", "a");
    transport_t t = {.send = hid_send, .recv = hid_recv, .now_ms = hid_now, .ctx = &h, .log = lg};
    if (lg) fprintf(lg, "--- flash %s ---\n", sha);

    // An interrupted write can leave the controller unusable.
    signal(SIGINT, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    size_t sent = 0;
    bool header_sent = false;
    flash_result_t res = run_flash(&t, &fw, &sent, &header_sent);
    if (res == FLASH_OK) {
        printf("All %zu blocks were accepted and the update was finalized.\n", fw.blocks);
        printf("Unplug the controller, then hold Start for 3 seconds to turn it off.\n");
        return 0;
    }
    printf("\nStopped: %s, after %zu of %zu blocks.\n", flash_result_text(res), sent, fw.blocks);
    printf(header_sent ? "The firmware may be erased or incomplete. Don't retry yet; check sn30flash.log first.\n"
                       : "Nothing was written: the update header was never sent.\n");
    return 1;
}

// ---- Simulated controller -------------------------------------------------

typedef struct {
    const firmware_t *fw;
    int nak_at, silent_at, gone_at, erase_ms, noise_every, ver_silent;
    int pause_at, pause_ms, lost_ack_at, stale_poll;
    double clock;
    uint8_t queue[64][REPORT_SIZE];
    double ready[64];
    bool is_dup[64];
    bool ack_lost;
    int head, tail;
    uint8_t last_reply[REPORT_SIZE];
    bool have_last, gone, failed, silent;
    size_t blocks;
    uint8_t *image;
    int header_seen, ok_count, polls, version_q, verify_q, errors, sends_after_fail, recvs;
    int real_acks_delivered, lockstep_violations;
} sim_t;

static void sim_enqueue(sim_t *s, const uint8_t *rpt, double delay, bool dup) {
    memcpy(s->queue[s->tail], rpt, REPORT_SIZE);
    s->is_dup[s->tail] = dup;
    double when = s->clock + delay;
    if (s->head != s->tail) {
        double prev = s->ready[(s->tail + 63) % 64];
        if (when < prev) when = prev;
    }
    s->ready[s->tail] = when;
    s->tail = (s->tail + 1) % 64;
}

static void sim_push(sim_t *s, const uint8_t *body, int n, double delay) {
    uint8_t q[REPORT_SIZE] = {0};
    q[0] = IN_REPORT_ID;
    memcpy(q + 1, body, (size_t)n);
    memcpy(s->last_reply, q, REPORT_SIZE);
    s->have_last = true;
    sim_enqueue(s, q, delay, false);
}

static void sim_ack(sim_t *s, uint8_t cmd, double delay) {
    uint8_t b[] = {5, 0, SUB_UPDATE, 1, 0, cmd};
    sim_push(s, b, sizeof(b), delay);
}

static int sim_send(transport_t *t, const uint8_t r[REPORT_SIZE]) {
    sim_t *s = t->ctx;
    s->clock += 1;
    if (s->gone) return -1;
    if (s->failed) s->sends_after_fail++;
    if (r[0] != OUT_REPORT_ID) s->errors++;
    for (int i = r[1] + 2; i < REPORT_SIZE; i++)
        if (r[i]) s->errors++;
    if (r[2] != 0) s->errors++;

    if (r[3] == SUB_TIMEOUT) {
        s->polls++;
        // Measured on the real controller: a poll resends the last reply.
        if (!s->have_last || s->silent) return 0;
        if (s->ack_lost) {
            s->ack_lost = false;
            sim_enqueue(s, s->last_reply, 2, false);
        } else if (s->stale_poll && s->head != s->tail) {
            // Worst case: an old ACK is resent ahead of the real one still pending.
            s->head = (s->head + 63) % 64;
            memcpy(s->queue[s->head], s->queue[(s->head + 1) % 64], REPORT_SIZE);
            s->ready[s->head] = s->clock + 2;
            s->is_dup[s->head] = true;
        } else {
            sim_enqueue(s, s->last_reply, 2, true);
        }
        return 0;
    }
    if (r[3] == SUB_GET_VERIFY_ID) {
        s->verify_q++;
        uint8_t b[] = {9, 0, SUB_VERIFY_ID, 0x0c, 0, 1, 2, 3, 4, 5};
        sim_push(s, b, sizeof(b), 2);
        return 0;
    }
    if (r[3] != SUB_UPDATE) { s->errors++; return 0; }

    switch (r[6]) {
        case CMD_FW_GET_VERSION: {
            s->version_q++;
            if (s->ver_silent) return 0;
            uint8_t b[] = {11, 0, SUB_UPDATE, 7, 0, CMD_FW_GET_VERSION, 4, 0, 100, 0, 0, 0};
            sim_push(s, b, sizeof(b), 2);
            return 0;
        }
        case CMD_FW_HEADER: {
            uint8_t want[FW_HDR_SIZE];
            wire_header(s->fw, want);
            if (s->header_seen || r[1] != 0x23 || r[4] != 0x1f || r[7] != FW_HDR_SIZE || memcmp(r + 9, want, FW_HDR_SIZE) != 0) s->errors++;
            s->header_seen++;
            sim_ack(s, CMD_ACK, s->erase_ms);
            return 0;
        }
        case CMD_FW_DATA: {
            if (!s->header_seen || s->ok_count) s->errors++;
            size_t off = s->blocks * BLOCK_SIZE;
            if (r[1] != r[7] + 7 || r[7] > BLOCK_SIZE || off + r[7] > s->fw->len) { s->errors++; return 0; }
            // A real ACK for each earlier step must have reached the host first.
            if ((int)s->blocks + 1 > s->real_acks_delivered) s->lockstep_violations++;
            memcpy(s->image + off, r + 9, r[7]);
            s->blocks++;
            int n = (int)s->blocks;
            if (s->gone_at && n == s->gone_at) { s->gone = true; return 0; }
            if (s->silent_at && n == s->silent_at) { s->silent = true; return 0; }
            if (s->nak_at && n == s->nak_at) { s->failed = true; sim_ack(s, CMD_NAK, 2); return 0; }
            if (s->lost_ack_at && n == s->lost_ack_at) {
                // The ACK never arrives, but it is what a poll will resend.
                uint8_t q[REPORT_SIZE] = {IN_REPORT_ID, 5, 0, SUB_UPDATE, 1, 0, CMD_ACK};
                memcpy(s->last_reply, q, REPORT_SIZE);
                s->ack_lost = true;
                return 0;
            }
            sim_ack(s, CMD_ACK, s->pause_at && n == s->pause_at ? s->pause_ms : 8);
            return 0;
        }
        case CMD_FW_OK:
            s->ok_count++;
            if (s->blocks != s->fw->blocks) s->errors++;
            return 0;
        default:
            s->errors++;
            return 0;
    }
}

static int sim_recv(transport_t *t, uint8_t r[REPORT_SIZE], int timeout_ms) {
    sim_t *s = t->ctx;
    if (s->gone) return RECV_GONE;
    s->recvs++;
    if (s->noise_every && s->recvs % s->noise_every == 0) {
        memset(r, 0, REPORT_SIZE);
        r[0] = 1;        // gamepad report, must be ignored
        r[2] = 0;
        r[3] = SUB_UPDATE;
        r[6] = CMD_NAK;  // would abort the flash if report IDs were not checked
        return RECV_OK;
    }
    if (s->head != s->tail && s->ready[s->head] <= s->clock + timeout_ms) {
        if (s->ready[s->head] > s->clock) s->clock = s->ready[s->head];
        memcpy(r, s->queue[s->head], REPORT_SIZE);
        if (r[3] == SUB_UPDATE && r[6] == CMD_ACK && !s->is_dup[s->head]) s->real_acks_delivered++;
        s->head = (s->head + 1) % 64;
        return RECV_OK;
    }
    s->clock += timeout_ms;
    return RECV_TIMEOUT;
}

static double sim_now(transport_t *t) { return ((sim_t *)t->ctx)->clock; }

static int g_failures = 0;

static void expect(const char *scenario, const char *what, bool ok) {
    if (!ok) { g_failures++; printf("  FAIL %s: %s\n", scenario, what); }
}

static flash_result_t sim_run(sim_t *s, const firmware_t *fw, size_t *sent) {
    bool header_sent;
    s->fw = fw;
    s->image = calloc(1, fw->len);
    transport_t t = {.send = sim_send, .recv = sim_recv, .now_ms = sim_now, .ctx = s, .quiet = true};
    return run_flash(&t, fw, sent, &header_sent);
}

static int cmd_selftest(const char *path) {
    firmware_t fw;
    if (!load_firmware(path, &fw)) return 1;
    print_firmware(&fw);
    size_t sent;

    {   const char *n = "normal";
        sim_t s = {0};
        flash_result_t r = sim_run(&s, &fw, &sent);
        expect(n, "result ok", r == FLASH_OK);
        expect(n, "all blocks", s.blocks == fw.blocks && sent == fw.blocks);
        expect(n, "image identical", memcmp(s.image, fw.payload, fw.len) == 0);
        expect(n, "one header", s.header_seen == 1);
        expect(n, "one OK", s.ok_count == 1);
        expect(n, "queries sent", s.version_q == 1 && s.verify_q == 1);
        expect(n, "no protocol errors", s.errors == 0);
        expect(n, "no polls when replies arrive", s.polls == 0);
        expect(n, "strict lockstep", s.lockstep_violations == 0);
        printf("  normal: %zu blocks, identical image, %d polls\n", s.blocks, s.polls);
    }
    {   const char *n = "erase under poll limit";
        sim_t s = {.erase_ms = 1500};
        flash_result_t r = sim_run(&s, &fw, &sent);
        expect(n, "result ok", r == FLASH_OK);
        expect(n, "no polls", s.polls == 0);
        expect(n, "image identical", memcmp(s.image, fw.payload, fw.len) == 0);
        printf("  1.5 s erase: no polls needed\n");
    }
    {   const char *n = "slow erase with poll";
        sim_t s = {.erase_ms = 3000};
        flash_result_t r = sim_run(&s, &fw, &sent);
        expect(n, "result ok", r == FLASH_OK);
        expect(n, "polled once", s.polls == 1);
        expect(n, "image identical", memcmp(s.image, fw.payload, fw.len) == 0);
        expect(n, "no protocol errors", s.errors == 0);
        printf("  3 s erase: %d poll, finished\n", s.polls);
    }
    {   const char *n = "duplicate ACK from poll";
        sim_t s = {.pause_at = 150, .pause_ms = 2500};
        flash_result_t r = sim_run(&s, &fw, &sent);
        expect(n, "result ok", r == FLASH_OK);
        expect(n, "polled", s.polls == 1);
        expect(n, "duplicate discarded, strict lockstep", s.lockstep_violations == 0);
        expect(n, "image identical", memcmp(s.image, fw.payload, fw.len) == 0);
        expect(n, "no protocol errors", s.errors == 0);
        printf("  duplicate ACK: discarded, stayed in lockstep\n");
    }
    {   const char *n = "stale ACK ahead of real one";
        sim_t s = {.pause_at = 150, .pause_ms = 2500, .stale_poll = 1};
        flash_result_t r = sim_run(&s, &fw, &sent);
        expect(n, "result ok", r == FLASH_OK);
        expect(n, "image identical, in order", memcmp(s.image, fw.payload, fw.len) == 0);
        expect(n, "OK sent after every block", s.ok_count == 1);
        expect(n, "no protocol errors", s.errors == 0);
        printf("  stale ACK: data stayed in order, image identical\n");
    }
    {   const char *n = "lost ACK";
        sim_t s = {.lost_ack_at = 400};
        flash_result_t r = sim_run(&s, &fw, &sent);
        expect(n, "result ok", r == FLASH_OK);
        expect(n, "recovered by one poll", s.polls == 1);
        expect(n, "strict lockstep", s.lockstep_violations == 0);
        expect(n, "image identical", memcmp(s.image, fw.payload, fw.len) == 0);
        printf("  lost ACK: recovered with one poll\n");
    }
    {   const char *n = "gamepad noise";
        sim_t s = {.noise_every = 3};
        flash_result_t r = sim_run(&s, &fw, &sent);
        expect(n, "result ok", r == FLASH_OK);
        expect(n, "image identical", memcmp(s.image, fw.payload, fw.len) == 0);
        expect(n, "no protocol errors", s.errors == 0);
        printf("  gamepad noise: other report IDs ignored\n");
    }
    {   const char *n = "nak";
        sim_t s = {.nak_at = 100};
        flash_result_t r = sim_run(&s, &fw, &sent);
        expect(n, "reported rejected", r == FLASH_REJECTED);
        expect(n, "stopped at block", sent == 100);
        expect(n, "sent nothing after NAK", s.sends_after_fail == 0);
        expect(n, "no OK", s.ok_count == 0);
        printf("  rejection: stopped at block %zu, sent nothing more\n", sent);
    }
    {   const char *n = "stall";
        sim_t s = {.silent_at = 200};
        flash_result_t r = sim_run(&s, &fw, &sent);
        expect(n, "reported stall", r == FLASH_STALLED);
        expect(n, "no more blocks", s.blocks == 200);
        expect(n, "no OK", s.ok_count == 0);
        printf("  stall: stopped at block %zu after %d ms limit\n", sent, ACK_DEADLINE_MS);
    }
    {   const char *n = "unplug";
        sim_t s = {.gone_at = 300};
        flash_result_t r = sim_run(&s, &fw, &sent);
        expect(n, "reported gone", r == FLASH_DEVICE_GONE);
        expect(n, "no OK", s.ok_count == 0);
        printf("  unplug: reported at block %zu\n", sent);
    }
    {   const char *n = "no reply before write";
        sim_t s = {.ver_silent = 1};
        flash_result_t r = sim_run(&s, &fw, &sent);
        expect(n, "reported", r == FLASH_NO_RESPONSE_BEFORE_WRITE);
        expect(n, "nothing written", s.header_seen == 0 && s.blocks == 0);
        printf("  silent controller: gave up before writing anything\n");
    }
    {   const char *n = "file checks";
        firmware_t b;
        uint8_t *copy = malloc(fw.size);
        memcpy(copy, fw.data, fw.size);
        b = (firmware_t){.data = copy, .size = fw.size - 1};
        expect(n, "truncated file rejected", parse_firmware(&b) != NULL);
        b = (firmware_t){.data = copy, .size = fw.size};
        copy[0] ^= 1;
        expect(n, "bad magic rejected", parse_firmware(&b) != NULL);
        copy[0] ^= 1;
        copy[fw.hdr_off + 12] ^= 1;
        expect(n, "bad image magic rejected", parse_firmware(&b) != NULL);
        copy[fw.hdr_off + 12] ^= 1;
        copy[fw.hdr_off + 8] ^= 1;
        expect(n, "bad length rejected", parse_firmware(&b) != NULL);
        copy[fw.hdr_off + 8] ^= 1;
        expect(n, "unchanged copy accepted", parse_firmware(&b) == NULL);
        char sha[65];
        copy[fw.size - 1] ^= 1;
        sha256_hex(copy, fw.size, sha);
        expect(n, "changed byte fails hash pin", known_firmware_name(sha) == NULL);
        printf("  file checks: damaged files rejected\n");
    }
    {   char sha[65];
        sha256_hex(fw.data, fw.size, sha);
        const char *known = known_firmware_name(sha);
        expect("hash pin", "real file matches pin", known != NULL);
        printf("  hash pin: %s\n", known ? known : "not recognized");
    }
    printf(g_failures ? "SELFTEST FAILED: %d problem(s)\n" : "All selftests passed.\n", g_failures);
    return g_failures ? 1 : 0;
}

static int usage(void) {
    fprintf(stderr,
            "Usage:\n"
            "  sn30flash listen [seconds]\n"
            "  sn30flash probe\n"
            "  sn30flash timing\n"
            "  sn30flash dump-wire <file.dat>\n"
            "  sn30flash selftest <file.dat>\n"
            "  sn30flash flash <file.dat> --yes\n");
    return 64;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc < 2) return usage();
    const char *c = argv[1];
    if (!strcmp(c, "listen")) return cmd_listen(argc > 2 ? atoi(argv[2]) : 5);
    if (!strcmp(c, "probe")) return cmd_probe();
    if (!strcmp(c, "timing")) return cmd_timing();
    if (!strcmp(c, "dump-wire") && argc == 3) return cmd_dump_wire(argv[2]);
    if (!strcmp(c, "selftest") && argc == 3) return cmd_selftest(argv[2]);
    if (!strcmp(c, "flash") && argc >= 3) return cmd_flash(argv[2], argc == 4 && !strcmp(argv[3], "--yes"));
    return usage();
}
