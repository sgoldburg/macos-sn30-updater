# macos-sn30-updater

`sn30flash` is a native macOS command-line tool that updates the firmware on an 8BitDo SN30 2.4G controller whose update mode appears as `8BitDo Receiver Fw` (USB ID `2dc8:3214`).

8BitDo's instructions say update mode should show up as a USB drive. On this hardware it presents one HID interface and no storage interface, so no drive appears, and 8BitDo's Mac updater doesn't list this ID. The updater that does support it is a Windows program. This tool uses the same protocol directly from a Mac, with no Windows or virtual machine.

> [!WARNING]
> This is an unofficial tool, not affiliated with or endorsed by 8BitDo. Flashing can leave a controller unusable. Use it at your own risk.

## Status

| | |
|---|---|
| **Tested on** | One SN30 2.4G controller labelled 81AF, on macOS 15.7 with Apple silicon |
| **Worked** | Flashing 5.06 to 1.23: all 624 blocks accepted in about 7 seconds, and the version read back as 1.23. The controller then paired with an Analogue Dock running the latest firmware |
| **Not tested** | Going back from 1.23 to 5.06, other controllers, other Macs |

## Before you flash

Run `./sn30flash probe` first to see which version you have. The test controller already had 5.06, the newest standard version 8BitDo lists for the SN30 2.4G Nt. Version 1.23 is not an upgrade from that: it is a separate build for the Analogue Dock.

- **Dock only:** 8BitDo labels the 1.23 firmware "For Analogue Dock only" and says to return to standard firmware for other systems.
- **Receiver:** [one forum report](https://forum.core-electronics.com.au/t/problems-with-controller-sn30-81af-of-the-8bitdo/24114) says this file stopped an 81AF controller working with its receiver. Expect the same.
- **Model match:** the test controller is labelled 81AF and the 1.23 file is for 81AD. 8BitDo's Dock page lists 81AD and 81AB but not 81AF, so the match is unconfirmed.
- **No model check:** I found no model check in the Windows tool, and this tool has none.

## Firmware

Firmware is not included in this repo. Download it from 8BitDo and unzip it. `flash` accepts only these two files, identified by SHA-256:

| Version | Download | File | SHA-256 |
|---|---|---|---|
| 1.23 for Analogue Dock (81AD) | [zip](https://download.8bitdo.com/Firmware/analogue/Dock/2.4g/SN30_Fw_V1_23_81AD_For_Analogue.zip) | `SN30_Fw_V1_23_81AD_For_Analogue.dat` | `fdae29ebcb7434cf262967dfc40ff8f17fa20bbad080af3b021dc185a39cbf30` |
| 5.06 standard SN30 2.4G Nt | [zip](https://download.8bitdo.com/Firmware/Controller/SN30-2.4g/SN30_24G_GamePad_V506.zip) | `SN30_24G_GamePad_V5_06.dat` | `9823303fe0d82daf1c90b0ca96f9b6428a2d23644e923cd0c116a4bbcf1310e3` |

## Build

This needs the Xcode Command Line Tools.

```bash
clang -std=c11 -Wall -Wextra -O1 -o sn30flash sn30flash.c -framework IOKit -framework CoreFoundation
```

## Usage

1. Quit 8BitDo Firmware Updater if it's running.
2. Turn the controller off by holding Start for 3 seconds.
3. Hold L + R and press Start. The blue and yellow LEDs start to blink.
4. Connect it by USB. If macOS asks whether to allow the accessory, click **Allow**.

Check the connection and current version:

```bash
./sn30flash probe
```

Flash, leaving the cable and controller alone until it finishes:

```bash
./sn30flash flash SN30_Fw_V1_23_81AD_For_Analogue.dat --yes
```

The controller restarts by itself. To confirm the new version, unplug it, repeat steps 2 to 4, and run `probe` again.

On 1.23, the test controller appeared as `8BitDo SN30 Wireless Controller` (`2dc8:3000`) after restarting, and macOS treated it as a new accessory. Its update mode was named `8BitDo Receiver Fw V1.23`.

| Command | What it does | Sends to controller |
|---|---|---|
| `listen [seconds]` | Prints input reports | Nothing |
| `probe` | Reads the firmware version and requests the verification ID | Queries only |
| `timing` | Measures reply time and the reaction to one poll | Queries only |
| `dump-wire <file.dat>` | Prints every report a flash would send | No device needed |
| `selftest <file.dat>` | Runs the flash logic against a simulated controller | No device needed |
| `flash <file.dat> --yes` | Writes the firmware | **Writes flash** |

`probe`, `timing` and `flash` append every report they send and receive to `sn30flash.log` in the current folder.

### If a flash stops partway

The tool stops immediately and reports how many blocks were sent. Check `sn30flash.log` before trying again. The image is written from address `0x3000`, which suggests the update-mode code sits below it and isn't overwritten, so a failed write may be recoverable. That hasn't been tested.

## Safeguards

- `flash` refuses any file that isn't one of the two listed above, and it requires `--yes`.
- It refuses to run if 8BitDo Firmware Updater is open.
- It expects exactly one matching controller, with the expected name and 64-byte reports.
- It stops all sending if the controller rejects anything, disconnects, or goes silent for 15 seconds.
- Ctrl-C is ignored during a flash, because an interrupted write can leave the controller unusable.

## Tests

This test doesn't need a controller.

**Simulated controller.** This covers normal flashes, slow erases, duplicate, out-of-date and lost ACKs, unrelated reports, rejection, stalling, unplugging, a silent controller and damaged files. The simulator is based on the protocol as understood here, so it can't prove how real hardware will behave.

```bash
./sn30flash selftest SN30_Fw_V1_23_81AD_For_Analogue.dat
```

## Diagnostics

`watch_usb.sh` records USB-C port, USB, disk, volume and HID changes while you connect a device, and it sends nothing to the device. It stops 30 seconds after the first change by default, or after 30 minutes with no change.

```bash
./watch_usb.sh usb-watch
```

Results are written to `usb-watch/events.log` and `usb-watch/system_log.txt`.

## Credits

- The protocol was worked out from 8BitDo's `SN30_Update.exe` and cross-checked against the [`ebitdo` plugin in fwupd](https://github.com/fwupd/fwupd/tree/main/plugins/ebitdo).
- [fran-fz/8bitdo_update](https://github.com/fran-fz/8bitdo_update) pointed the way to fwupd.

## License

[MIT](LICENSE). This covers the code in this repo, not 8BitDo's firmware or tools.
