#!/bin/bash
# Read-only watcher: logs any USB-C port, USB bus, external disk, volume or HID change.
# Exits SETTLE seconds after the first change, or after MAX seconds with no change.
OUT="$1"; SETTLE="${2:-30}"; MAX="${3:-1800}"
mkdir -p "$OUT"
LOG="$OUT/events.log"; : > "$LOG"

ports() {
  ioreg -rlw0 -c AppleHPMInterfaceType10 2>/dev/null \
    | grep -E '"PortDescription"|"ConnectionActive"|"TransportsActive"|"PlugOrientation"|"ActiveCable"' \
    | sed -E 's/^[ |]+//'
}
usb()   { ioreg -p IOUSB -w 0 2>/dev/null | sed -E 's/<class ([^,]+),.*/\1/'; }
disks() { diskutil list external physical 2>/dev/null; }
vols()  { ls -1 /Volumes 2>/dev/null | grep -vE '^(Backups of|\.timemachine|com\.apple|Macintosh HD)'; }
hid()   { hidutil list 2>/dev/null | awk 'NR>2 {print $1, $2, $NF}' | sort -u; }

snapshot() {
  echo "## ports"; ports
  echo "## usb";   usb
  echo "## disks"; disks
  echo "## vols";  vols
  echo "## hid";   hid
}

details() {
  echo "--- USB device properties ---"
  ioreg -p IOUSB -l -w 0 2>/dev/null | grep -E '^[ |]*\+-o|"idVendor"|"idProduct"|"bcdDevice"|"USB Product Name"|"USB Vendor Name"|"kUSBProductString"|"kUSBVendorString"|"kUSBSerialNumberString"|"bDeviceClass"|"bDeviceSubClass"|"USBSpeed"'
  echo "--- system_profiler ---"; system_profiler SPUSBDataType 2>/dev/null
  echo "--- diskutil ---"; diskutil list external physical 2>/dev/null
  echo "--- volumes ---"; ls -la /Volumes 2>/dev/null
}

/usr/bin/log stream --style compact --predicate 'eventMessage CONTAINS[c] "usb" OR eventMessage CONTAINS[c] "accessory" OR process == "usbd" OR process == "accessoryd"' > "$OUT/system_log.txt" 2>&1 &
LOGPID=$!
trap 'kill $LOGPID 2>/dev/null' EXIT

PREV="$(snapshot)"
echo "$PREV" > "$OUT/start_state.txt"
echo "$(date +%T) watching" >> "$LOG"
START=$(date +%s); FIRST=0
while :; do
  NOW=$(date +%s)
  [ "$FIRST" -gt 0 ] && [ $((NOW-FIRST)) -ge "$SETTLE" ] && break
  [ "$FIRST" -eq 0 ] && [ $((NOW-START)) -ge "$MAX" ] && { echo "$(date +%T) timed out with no change" >> "$LOG"; break; }
  CUR="$(snapshot)"
  if [ "$CUR" != "$PREV" ]; then
    {
      echo; echo "===== $(date +%T) CHANGE ====="
      diff <(echo "$PREV") <(echo "$CUR")
      details
    } >> "$LOG"
    PREV="$CUR"
    [ "$FIRST" -eq 0 ] && FIRST=$(date +%s)
  fi
  sleep 0.5
done
echo "$(date +%T) done" >> "$LOG"
