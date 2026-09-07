# AXIOM Firmware

ESP32-S3 (DevKitM-1) Wi-Fi/BLE lab controller with a premium web dashboard and a 1.3" SH1106
OLED status display. AXIOM exposes REST/WebSocket endpoints for network monitoring,
diagnostics, and authorized wireless security testing on hardware you own.

This repository archives the firmware version history **v1 – v17** as a GitHub Release per
version. Each release carries its changelog and the flashable `.ino` sketch as an asset.

## Versions

| Version | Highlight |
|---------|-----------|
| [v1](../../releases/tag/v1) | initial tracked version — ESP32-S3 premium web dashboard with WiFi/BLE/GPIO, packet sniffer,… |
| [v2](../../releases/tag/v2) | n8n HTTP reverse proxy (/n8n/*) — phone stays on AXIOM AP while the MacBook runs n8n locally |
| [v3](../../releases/tag/v3) | slimmed back to the core sniffer + web dashboard |
| [v4](../../releases/tag/v4) | REST data-panel endpoints — /data, /wifi, /gpio, /bt (JSON) |
| [v5](../../releases/tag/v5) | changed: CyberTech boot banner/edition; minor tweaks (near-identical to v4) |
| [v6](../../releases/tag/v6) | 1.3" SH1106 OLED status display (U8g2 HW SPI) + OLED pin defines |
| [v7](../../releases/tag/v7) | OLED layout helpers — oledHeader/oledFooter/oledKV, truncateStr, formatTime; richer multi-pa… |
| [v8](../../releases/tag/v8) | changed: compact experimental build — trimmed dashboard HTML/footer |
| [v9](../../releases/tag/v9) | fixed: OLED display glitches — glitch-free redraw path |
| [v10](../../releases/tag/v10) | forceOledNormal() OLED recovery + onAxiomWifiEvent() WiFi-event hook |
| [v11](../../releases/tag/v11) | v6 CyberTech stable web dashboard / REST endpoints |
| [v12](../../releases/tag/v12) | fixed: self-healing OLED draw — drawOled() does a full reinit before every draw so a desynced SH110… |
| [v13](../../releases/tag/v13) | gpioLabel()/gpioValue() helpers |
| [v14](../../releases/tag/v14) | WiFi->AP NAT bridge (enableBridgeNAPT) for internet passthrough |
| [v15](../../releases/tag/v15) | changed: TOUCH_THRESHOLD 40000 -> 30000 (documented raw-value semantics) |
| [v16](../../releases/tag/v16) | single AXIOM_VERSION #define so banner/boot/JSON agree |
| [v17](../../releases/tag/v17) | /wifi/nat endpoint (handleNatBridge) with enable/disableBridgeNAPT |

The **latest** release is **v17**. Each sketch lives under `AXIOM_v<N>/AXIOM_v<N>.ino`.

## Target hardware
- **Board:** ESP32-S3 DevKitM-1
- **Display:** 1.3" SH1106 OLED (hardware SPI) — added in v6+
- **Libraries:** arduinoWebSockets, ArduinoJson, Adafruit NeoPixel, U8g2

## Flashing
1. Open `AXIOM_v<N>/AXIOM_v<N>.ino` in the Arduino IDE (ESP32 board package installed).
2. Select **ESP32S3 Dev Module**, enable USB-CDC, choose the right port.
3. Upload. On boot the device serves the dashboard at `http://192.168.4.1`
   (AP SSID `AXIOM-Controller`) or `http://axiom.local`.

## ⚠ Legal notice — AUTHORIZED LAB USE ONLY

AXIOM includes packet capture, PMKID collection, and deauthentication **detection**
capabilities intended **only** for use on networks you own or have explicit written
permission to test. Unauthorized use against networks or devices you do not own is illegal.
You are solely responsible for complying with all applicable laws. Provided as-is, for
research and education, with no warranty.

## License

Proprietary — Copyright (c) 2026 Aditya Kadam. All rights reserved. See [LICENSE](LICENSE).
No use, copying, modification, or redistribution without prior written permission.
