# AXIOM Firmware

**AXIOM** is an ESP32‑S3 Wi‑Fi/BLE lab controller with a premium web dashboard and a 1.3"
SH1106 OLED status display. It exposes a set of REST + WebSocket endpoints for network
monitoring, hardware diagnostics, and **authorized** wireless security testing on equipment
you own.

This repository archives the firmware's version history **v1 – v17** as a GitHub Release per
version — each release carries its changelog and the flashable `.ino` sketch as a downloadable
asset. Newer builds (v18+) are still **under testing** and are not published here yet — see
[Roadmap](#roadmap).

- **Target board:** ESP32‑S3 DevKitM‑1
- **UI:** Web dashboard (`http://192.168.4.1` / `http://axiom.local`) + on‑device OLED
- **License:** Proprietary — all rights reserved ([LICENSE](LICENSE))
- **Latest release:** [v17](../../releases/tag/v17)

---

## Contents
- [Features](#features)
- [Hardware](#hardware)
- [Software & libraries](#software--libraries)
- [Getting started](#getting-started)
- [Web API overview](#web-api-overview)
- [Version history (v1–v17)](#version-history-v1v17)
- [Roadmap](#roadmap)
- [Legal — authorized use only](#legal--authorized-use-only)
- [License](#license)

---

## Features

**Monitoring & diagnostics**
- Full GPIO map for all usable pins, live read/write, PWM output
- Master JSON telemetry stream (`/data`) + lightweight/full status polling
- CPU frequency scaling (80/160/240 MHz) and deep‑sleep control
- NeoPixel status LED (GPIO 48), mDNS (`axiom.local`)

**Wireless analysis** *(authorized lab use only)*
- Wi‑Fi scanner + station connect, saved‑AP config in NVS
- BLE scanner with OUI / manufacturer lookup
- Wireshark‑style packet sniffer with channel map + channel hopping
- Kismet‑style AP + client mapper
- Deauthentication **detector** (promiscuous), beacon‑flood detector, evil‑twin detector
- PMKID capture (lab/authorized), ARP + port scanner
- Wi‑Fi → AP NAT bridge for upstream passthrough *(v14+)*

**Interface**
- Responsive web dashboard (cyber theme) served straight from the device
- 1.3" SH1106 OLED status pages, web‑navigable (`/display/*`) *(v6+)*
- LAN chat over WebSocket

---

## Hardware
| Component | Detail |
|-----------|--------|
| MCU board | **ESP32‑S3 DevKitM‑1** |
| Display   | 1.3" **SH1106** OLED, hardware SPI (CS 10, DC 9, MOSI 11, SCK 12, RST 14) |
| LED       | On‑board NeoPixel (GPIO 48) |

## Software & libraries
Install via the Arduino Library Manager:
- **arduinoWebSockets** — Markus Sattler
- **ArduinoJson** — Benoît Blanchon (v7.x recommended)
- **Adafruit NeoPixel** — Adafruit
- **U8g2** — oliver (olikraus) *(SH1106 OLED; earlier builds used Adafruit SH110X)*

---

## Getting started

1. Download the sketch for the version you want from its
   [Release](../../releases) (asset `AXIOM_v<N>.ino`), or clone this repo and open
   `AXIOM_v<N>/AXIOM_v<N>.ino`.
2. In the Arduino IDE install the **ESP32** board package, then select
   **ESP32S3 Dev Module**, enable **USB CDC On Boot**, and pick the correct port.
3. **Upload.** On boot AXIOM starts a Wi‑Fi access point:
   - **SSID:** `AXIOM-Controller`  •  **Password:** `axiom1234` *(change this before real use)*
4. Join that AP and open **`http://192.168.4.1`** or **`http://axiom.local`**.

---

## Web API overview
A selection of endpoints (the exact set grows across versions):

| Endpoint | Purpose |
|----------|---------|
| `/` | Web dashboard |
| `/status`, `/status/full` | Device status (lightweight / detailed) |
| `/data` | Master JSON telemetry stream |
| `/wifi`, `/wifi/scan`, `/wifi/connect` | Wi‑Fi info / scan / join |
| `/gpio`, `/gpio/pin`, `/gpio/pwm` | GPIO state & control |
| `/bluetooth` (`/bt`), `/ble/scan` | BLE data / scan |
| `/sniffer`, `/kismet`, `/pmkid`, `/recon` | Capture & mapping tools |
| `/display/next`, `/display/prev`, `/display/page` | OLED navigation *(v6+)* |
| `/wifi/nat` | NAT bridge control *(v17)* |

---

## Version history (v1–v17)

Each row links to its GitHub Release (changelog + downloadable `.ino`).

| Version | Highlight |
|---------|-----------|
| [v1](../../releases/tag/v1)  | Initial tracked build — full web dashboard (Wi‑Fi/BLE/GPIO, sniffer, kismet, PMKID, deauth detector, LAN chat, mDNS) |
| [v2](../../releases/tag/v2)  | n8n HTTP reverse proxy (`/n8n/*`); zero‑lag split status polling |
| [v3](../../releases/tag/v3)  | Slimmed back to the core sniffer + dashboard |
| [v4](../../releases/tag/v4)  | REST data‑panel endpoints — `/data`, `/wifi`, `/gpio`, `/bt` |
| [v5](../../releases/tag/v5)  | CyberTech edition; minor tweaks |
| [v6](../../releases/tag/v6)  | 1.3" SH1106 OLED status display + web‑navigable pages |
| [v7](../../releases/tag/v7)  | OLED layout helpers + richer multi‑page panel |
| [v8](../../releases/tag/v8)  | Compact experimental build |
| [v9](../../releases/tag/v9)  | Glitch‑free OLED redraw path |
| [v10](../../releases/tag/v10) | OLED recovery (`forceOledNormal`) + Wi‑Fi‑event hook |
| [v11](../../releases/tag/v11) | Merged dashboard + `/display/cycle`,`/refresh` + anti‑invert‑glitch handling |
| [v12](../../releases/tag/v12) | Self‑healing OLED draw (full reinit) + `/display/scroll` |
| [v13](../../releases/tag/v13) | `gpioLabel`/`gpioValue` helpers + display scroll/cycle/refresh |
| [v14](../../releases/tag/v14) | Wi‑Fi → AP **NAT bridge** + async BLE scan + pin‑in‑use guard |
| [v15](../../releases/tag/v15) | Touch‑threshold tuning + tightened endpoint guards |
| [v16](../../releases/tag/v16) | Single `AXIOM_VERSION` define + optional auth token + ArduinoJson responses |
| [v17](../../releases/tag/v17) | `/wifi/nat` endpoint; reverted to classic string handlers **(latest)** |

Every sketch also lives in‑tree at `AXIOM_v<N>/AXIOM_v<N>.ino`.

---

## Roadmap

Newer builds exist but are **under active testing** and are **not yet released** in this
repository. They move to a larger "bundled UI" architecture (compressed single‑page web app)
and add automation‑oriented tooling. Planned / testing status:

| Version | Status | Focus |
|---------|--------|-------|
| **v18** | 🧪 Under testing | Bundled/compressed web UI; automatic Wi‑Fi→AP NAT bridge with DNS offer + boot self‑test |
| **v19** | 🧪 Under testing | Stability cleanup (self‑test removed) |
| **v20** | 🧪 Under testing | Minor UI / handler refinements |
| **v21** | 🧪 Under testing | Further bundled‑UI refinements |
| **v22** | 🧪 Under testing | Automation API — `/sniff` (cursor‑based capture) + `/stream` (pipeline health) *(unverified build)* |
| **v23** | 🧪 Under testing | Passive threat‑hunt detector + saved‑network credential store |

> These versions will be published as releases once verified on hardware. Scope and dates may
> change; nothing in the roadmap is a supported release yet.

---

## Legal — authorized use only

AXIOM includes wireless capabilities (packet capture, PMKID collection, deauthentication
detection, and related tooling) intended **solely** for use on networks and devices that you
own or have **explicit written authorization** to test. Unauthorized use against systems you do
not own is illegal and strictly prohibited. You are solely responsible for complying with all
applicable laws and regulations. The firmware is provided **as‑is**, for research and education,
**without warranty of any kind**.

## License

**Proprietary** — Copyright © 2026 Aditya Kadam. All rights reserved. See [LICENSE](LICENSE).
No use, copying, modification, or redistribution without prior written permission.
