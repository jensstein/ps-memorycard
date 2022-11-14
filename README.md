# ps3 memory card adapter

This is the beginning of a kind of fork of jimmikaelkael's ps3mca-tool.
That project is not available on Github due to a DMCA takedown notice
from Sony regarding the emulation of the mechacon authentication process: <https://github.com/github/dmca/blob/master/2011/2011-06-21-sony.markdown>.

This project will not include the MagicGate keys to send to the device
for authentication, only a framework for authenticating if you already
possess the required keys. Thereby Sony's copyright should not be
violated.

## MagicGate keys
In order to use this program with PS2 cards you must supply your own
MagicGate keys. You need two 16 byte files: k1.bin, k2.bin, and two 8
byte files: iv1.bin, and iv2.bin.

k1 and k2 are hash keys used for the Triple DES procedure (each file
should contain two 8 byte keys).

iv1 and iv2 are initial vectors to be used with the corresponding keys.

## Help
```
$ ./ps-memorycard --help
Usage: ps-memorycard <keys-directory> <COMMAND>

Commands:
  specs       Prints card info
  dump-image  Dumps the entire card to an image file
  help        Print this message or the help of the given subcommand(s)

Arguments:
  <keys-directory>  Directory with MagicGate keys. Should contain iv1.bin, iv2.bin, k1.bin, k2.bin

Options:
  -h, --help     Print help information
  -V, --version  Print version information
```

## Examples
- `specs` prints some info about the card.
```bash
$ ./ps-memorycard card-keys specs
page size: 512 bytes
block size: 32 pages
card size: 64 MB
```
- `dump-image` reads all the data sequentially from the card and writes
  it to a file.
```bash
$ ./ps-memorycard card-keys dump-image memorycard.img
Dumping image to memorycard.img
[16m] ████████████████████████████████████████ 64.00 MiB/64.00 MiB
```

## Tests
- To run tests with a physical PS2 card connected, use `cargo test --features test-ps2-card`

## USB monitoring
On linux you can monitor the traffic between the host and a USB device
by loading the `usbmon` kernel module:
```
modprobe usbmon
# Find which bus the device is on - you can also just use the `lsusb` tool. If you look at the devices file, the bus is listed in the T line.
cat /sys/kernel/debug/usb/devices
# If the device is on bus 001, its traffic will be present in the 1u file.
cat /sys/kernel/debug/usb/usbmon/1u
```
- <https://www.kernel.org/doc/Documentation/usb/usbmon.txt>

## Links
- <https://github.com/MechaResearch/MechaPwn>
- <https://github.com/vpelletier/ps3-memorycard-adapter/blob/master/nbd/memory_card_reader.py>
- <https://github.com/ShendoXT/memcardrex/blob/master/MemcardRex/Hardware/PS3MemCardAdaptor.cs>
- <https://github.com/paolo-caroni/ps3mca-ps1/blob/master/src/ps3mca-ps1-driver.h>
- <https://www.psdevwiki.com/ps3/Card_Adapter>
- <https://github.com/PCSX2/pcsx2/pull/4274>
- <https://archive.org/details/Magicgate>
- <https://archive.fosdem.org/2021/schedule/event/pcsx2/attachments/slides/4422/export/events/attachments/pcsx2/slides/4422/pcsx2_fosdem.pdf>
- <https://psi-rockin.github.io/ps2tek/#sio2ps2memcards>
