# ESP32 Wi-Fi Sensing Lab

Three ESP-IDF firmwares for a single ESP32-WROOM-32, exploring what a $3 Wi-Fi
chip can actually see — from channel state information to device tracking — plus
the Python tools used to visualise the data on a PC.

Everything here was measured on real hardware, and the notes below record what
turned out to be possible and what turned out to be physically impossible.

## Hardware

| | |
|---|---|
| Module | ESP32-WROOM-32, ESP32-D0WD-V3 rev 3.1 |
| Flash | 4 MB, no PSRAM |
| Serial | CH340G USB bridge (`VID_1A86:PID_7523`) |
| Toolchain | ESP-IDF v5.4 |
| Console | 460800 baud on UART0 |

## Projects

### `csi_presence/` — presence detection from channel state information

Captures 802.11 channel state information (64 subcarriers at 20 MHz) from the
frames of an associated access point and streams it as text over UART. The
station pings its gateway at 100 Hz so there is a steady supply of frames.

### `wifi_scanner/` — station-mode Wi-Fi scanner with a browser UI

Joins an existing network, actively scans all 13 channels for access points, and
listens promiscuously on its own channel for client frames. Serves a dark
single-page UI on port 80 with live tables, a scan button, and pause.

### `ap_scanner/` — the board *is* the access point

Runs as a WPA2 SoftAP (`ESP32-SCANNER`) on APSTA so it can also scan, and:

- lists the access points it finds, per channel;
- lists its own connected clients;
- sweeps channels 1–13 to inventory nearby devices, dropping the AP for ~20 s;
- resolves vendor names from a generated IEEE MA-L prefix table;
- detects randomised MAC addresses (the locally-administered bit).

### `tools/` — PC-side Python

| File | Purpose |
|---|---|
| `csi_presence.py` | reads CSI from the serial port, runs the presence detector |
| `csi_sim.py` | synthetic CSI generator for developing without hardware |
| `dashboard.py` | live dashboard, `--source serial` or simulated |
| `selftest_synthetic.py` | checks the detector against known synthetic input |

## What this experiment established

**A scan finds networks, not devices.** Access points announce themselves with
beacons, so a scan enumerates them across every channel. Client devices announce
nothing: they are only visible if the radio *sits on their channel* and captures
their frames, and one radio listens on one channel at a time. That is why device
inventory requires a channel sweep, and why a sweep costs you the AP for its
duration.

**On someone else's WPA2 network you get metadata only.** Every client's data
frames are encrypted with a per-client key (PTK) the sniffer does not hold, so
the payloads — where DHCP hostnames and mDNS names live — are opaque. From a
sweep you get MAC, frame type, signal strength and channel. You do **not** get
names, and no amount of parsing changes that.

**Device names are only available if the board is the access point.** As the AP
it issues each client's key, so their DHCP and mDNS traffic becomes readable.
That is the only reliable path on WPA2, and it is why `ap_scanner` exists.

**Randomised MACs are unidentifiable by design.** iOS and Android generate a
private address per network; the locally-administered bit marks them. No vendor
lookup applies and no name can be resolved. This is the intended behaviour.

**Channels overlap more than the channel number suggests.** With HT40 the
station spans two 20 MHz channels, so one phone legitimately appears on several
adjacent channels during a sweep.

## Building

```sh
. $IDF_PATH/export.sh
cd csi_presence      # or wifi_scanner / ap_scanner
idf.py set-target esp32
idf.py -p <PORT> flash
```

`csi_presence` and `wifi_scanner` prompt for the SSID and password over the
serial console at boot. **No credentials are stored in this repository or in
the firmware image** — they are read from stdin, kept in RAM only, and gone on
reset. `ap_scanner` needs no credentials at all; it creates its own network.

## Licence

MIT.
