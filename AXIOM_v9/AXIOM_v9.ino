/*
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║                                AXIOM  v9                                 ║
 * ║              ESP32-S3 DevKitM-1 · Cyber Intelligence Controller          ║
 * ║                                                                          ║
 * ║  Full GPIO Map (all usable pins)   WiFi REST Data (/wifi)                ║
 * ║  BLE Data Endpoint (/bluetooth)    GPIO REST Data (/gpio)                ║
 * ║  Master JSON Stream (/data)        Packet Sniffer (Wireshark-style)      ║
 * ║  BLE Scanner + OUI + Mfr           Kismet AP+Client Mapper               ║
 * ║  PMKID Capture (lab/authorized)    Beacon Flood Detector                 ║
 * ║  Evil Twin Detector                ARP + Port Scanner                    ║
 * ║  Channel Map                       LAN Chat (WebSocket)                  ║
 * ║  AP Config (NVS)                   CPU Scaling + Deep Sleep              ║
 * ║  NeoPixel LED (GPIO 48)            mDNS (axiom.local)                    ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 *
 *  REQUIRED LIBRARIES  (Arduino Library Manager):
 *    WebSockets          by Markus Sattler  (arduinoWebSockets)
 *    ArduinoJson         by Benoit Blanchon
 *    Adafruit NeoPixel   by Adafruit
 *    U8g2                by oliver (olikraus)  (1.3" SH1106 OLED, hardware SPI)
 *
 *  CHANGES in v9:
 *    - FIXED:   OLED display glitches — glitch-free redraw path.
 *    - ADDED:   restored full REST handler set + promiscuous sniffer helpers.
 *
 *  CONNECT:
 *    WiFi → AXIOM-Controller  |  Pass: axiom1234
 *    URL  → http://192.168.4.1  OR  http://axiom.local
 *
 *  ⚠  LEGAL NOTICE:
 *    Packet capture, PMKID collection, and deauth detection are for
 *    AUTHORIZED LAB USE ONLY on networks you own or have explicit
 *    written permission to test. Unauthorized use is illegal.
 */

#include <Adafruit_NeoPixel.h>
#include <Arduino.h>
#include <ArduinoJson.h>
#include <BLEAdvertisedDevice.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <ESPmDNS.h>
#include <HTTPClient.h>
#include <Preferences.h>
#include <SPI.h>
#include <U8g2lib.h>
#include <WebServer.h>
#include <WebSocketsServer.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <WiFiClientSecure.h>
#include <driver/ledc.h>
#include <driver/touch_sensor.h>
#include <esp_netif.h>
#include <esp_sleep.h>
#include <esp_timer.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <stdarg.h>
#include <time.h>

// ─── NEOPIXEL ────────────────────────────────────────────────────────────────
#define NEO_PIN 48
#define NEO_COUNT 1
Adafruit_NeoPixel neo(NEO_COUNT, NEO_PIN, NEO_GRB + NEO_KHZ800);

// ─── OLED DISPLAY — 1.3" SH1106, 128x64, SPI
// ────────────────────────────────── Hardware SPI — match user's working sample
#define OLED_MOSI_PIN 11 // -> display SDA / DIN
#define OLED_SCK_PIN 12  // -> display SCK / CLK
#define OLED_DC_PIN 9    // -> display DC
#define OLED_RST_PIN 14  // -> display RES
#define OLED_CS_PIN 10   // -> display CS
#define OLED_W 128
#define OLED_H 64
U8G2_SH1106_128X64_NONAME_F_4W_HW_SPI oled(U8G2_R0, OLED_CS_PIN, OLED_DC_PIN,
                                           OLED_RST_PIN);

enum OledPage {
  PG_HOME = 0,
  PG_WIFI,
  PG_SNIFFER,
  PG_KISMET,
  PG_PMKID,
  PG_GPIO,
  PG_COUNT
};
const char *oledPageNames[PG_COUNT] = {"HOME",   "WIFI",  "SNIFFER",
                                       "KISMET", "PMKID", "GPIO"};
int oledPage = PG_HOME;
bool oledReady = false;
volatile bool oledDirty = true;      // force first draw
volatile bool oledDrawing = false;   // re-entrancy guard
unsigned long lastContrastReset = 0;
const uint8_t OLED_CONTRAST = 0xCF; // stable contrast for SH1106
const unsigned long OLED_LIVE_INTERVAL = 3000;  // live data refresh: 3s (not 1s)
const unsigned long CONTRAST_RESET_INTERVAL = 10000; // re-send contrast every 10s

// ─── GPIO MAP
// ─────────────────────────────────────────────────────────────────
static const int OUT_PINS[] = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12,
                               13, 14, 17, 18, 21, 38, 39, 40, 41, 42, 45, 46};
static const int OUT_COUNT = 24;
static const int IN_PINS[] = {1,  2,  3,  4,  5,  6,  7,  8,  9,
                              10, 11, 12, 13, 14, 15, 16, 17, 18};
static const int IN_COUNT = 18;
static const int ADC_PINS[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
static const int ADC_COUNT = 10;

// GPIO output state — indexed by position in OUT_PINS[]
bool gpioStates[24] = {};
// Lookup: pin number → index in OUT_PINS
int pinIndex(int pin) {
  for (int i = 0; i < OUT_COUNT; i++)
    if (OUT_PINS[i] == pin)
      return i;
  return -1;
}

// PWM
#define GPIO_OUT_1 4
#define GPIO_OUT_2 5
#define GPIO_OUT_3 6
uint8_t pwmDuty[3] = {0, 0, 0};
bool pwmMode[3] = {false, false, false};
#define PWM_FREQ 5000
#define PWM_RES 8

// ─── AP CONFIG
// ────────────────────────────────────────────────────────────────
#define DEFAULT_AP_SSID "AXIOM-Controller"
#define DEFAULT_AP_PASS "axiom1234"
#define MDNS_HOST "axiom"
const IPAddress AP_IP(192, 168, 4, 1);
const IPAddress AP_GW(192, 168, 4, 1);
const IPAddress AP_SN(255, 255, 255, 0);

// ─── SERVERS
// ──────────────────────────────────────────────────────────────────
WebServer http(80);
WebSocketsServer wsChat(81);
Preferences prefs;

String apSSID, apPass;

// ─── RUNTIME STATE
// ────────────────────────────────────────────────────────────
String bleResults = "[]";
bool bleScanning = false;
String staConnStatus = "disconnected";
String staSSID = "";
unsigned long staTimeout = 0;
unsigned long lastHeartbeat = 0;
unsigned long lastTouchPoll = 0;

uint32_t touchVal[2] = {0, 0};
bool touchActive[2] = {false, false};
bool prevTouch[2] = {false, false};
String touchAction[2] = {"none", "none"};
#define TOUCH_THRESHOLD 40000

// ─── PACKET SNIFFER STATE
// ─────────────────────────────────────────────────────
#define MAX_PKT_LOG 60
struct PktEntry {
  char srcMAC[18];
  char dstMAC[18];
  uint8_t type;
  uint8_t subtype;
  int8_t rssi;
  uint8_t channel;
  char info[32];
  uint32_t ts;
};
PktEntry pktLog[MAX_PKT_LOG];
volatile int pktHead = 0;
volatile int pktTotal = 0;
bool snifferActive = false;
bool deauthMode = false;
bool kismetMode = false;
bool pmkidMode = false;
int snifferChan = 1;
unsigned long lastChanHop = 0;
bool chanHopping = false;

volatile int _deauthCnt = 0;
volatile char _deauthMAC[20] = "--";
int deauthCnt = 0;
int deauthChan = 1;
String deauthLast = "--";

int beaconCnt = 0;
char beaconSSID[33] = "--";
unsigned long beaconWindow = 0;
int beaconBurst = 0;

// Kismet
#define MAX_AP 20
#define MAX_CLI 30
struct APRecord {
  char bssid[18];
  char ssid[33];
  int8_t rssi;
  uint8_t ch;
  uint8_t enc;
  bool valid;
  uint32_t ts;
};
struct CLIRecord {
  char mac[18];
  char bssid[18];
  int8_t rssi;
  uint32_t ts;
  bool valid;
};
APRecord kisAPs[MAX_AP] = {};
CLIRecord kisCLIs[MAX_CLI] = {};

// PMKID
#define MAX_PMKID 10
struct PMKIDEntry {
  char bssid[18];
  char client[18];
  char pmkid[40];
  uint32_t ts;
};
PMKIDEntry pmkidLog[MAX_PMKID] = {};
int pmkidCount = 0;

// Probe
#define MAX_PROBE 20
struct ProbeEntry {
  char mac[18];
  char ssid[33];
  uint32_t ts;
};
ProbeEntry probeLog[MAX_PROBE] = {};
int probeCount = 0;

// ─── OUI TABLE
// ────────────────────────────────────────────────────────────────
struct OuiEntry {
  uint8_t p[3];
  const char *v;
};
static const OuiEntry OUI[] = {
    {{0xDC, 0xA6, 0x32}, "Raspberry Pi"}, {{0xB8, 0x27, 0xEB}, "Raspberry Pi"},
    {{0xE4, 0x5F, 0x01}, "Raspberry Pi"}, {{0xD8, 0x3A, 0xDD}, "Apple"},
    {{0x00, 0x17, 0xF2}, "Apple"},        {{0xAC, 0xDE, 0x48}, "Apple"},
    {{0xF0, 0x18, 0x98}, "Apple"},        {{0x18, 0xDB, 0xF2}, "Espressif"},
    {{0xA4, 0xCF, 0x12}, "Espressif"},    {{0x24, 0x6F, 0x28}, "Espressif"},
    {{0x00, 0x23, 0xDF}, "Samsung"},      {{0xC4, 0x73, 0x1E}, "Samsung"},
    {{0x00, 0x50, 0xF2}, "Microsoft"},    {{0x7C, 0xED, 0x8D}, "Intel"},
    {{0xEC, 0x62, 0x60}, "Amazon"},       {{0x28, 0xD2, 0x44}, "Google"},
    {{0x00, 0x17, 0x88}, "Philips Hue"},  {{0x00, 0x30, 0xBD}, "Cisco"},
    {{0x00, 0x00, 0x00}, nullptr}};
const char *lookupOUI(const uint8_t *m) {
  for (int i = 0; OUI[i].v; i++)
    if (m[0] == OUI[i].p[0] && m[1] == OUI[i].p[1] && m[2] == OUI[i].p[2])
      return OUI[i].v;
  return "?";
}

// ─── PORT SCANNER (non-blocking friendly: short timeout) ─────────────────────
struct PortEntry {
  int port;
  const char *svc;
};
static const PortEntry PORTS[] = {{80, "HTTP"},   {443, "HTTPS"}, {22, "SSH"},
                                  {1883, "MQTT"}, {8080, "Alt"},  {5900, "VNC"},
                                  {21, "FTP"},    {0, nullptr}};
String scanPorts(const String &ip) {
  WiFiClient c;
  String out = "[";
  bool first = true;
  for (int i = 0; PORTS[i].svc; i++) {
    if (c.connect(ip.c_str(), PORTS[i].port, 80)) {
      if (!first)
        out += ",";
      out += "{\"p\":" + String(PORTS[i].port) + ",\"s\":\"" + PORTS[i].svc +
             "\"}";
      first = false;
      c.stop();
    }
  }
  return out + "]";
}

// ─── CLIENT TRACKER
// ───────────────────────────────────────────────────────────
struct ClientRec {
  uint8_t mac[6];
  uint32_t joinMs;
  bool valid;
};
ClientRec clientLog[8] = {};
void logClient(const uint8_t *m) {
  for (int i = 0; i < 8; i++)
    if (!clientLog[i].valid) {
      memcpy(clientLog[i].mac, m, 6);
      clientLog[i].joinMs = millis();
      clientLog[i].valid = true;
      return;
    }
}
uint32_t clientAge(const uint8_t *m) {
  for (int i = 0; i < 8; i++)
    if (clientLog[i].valid && memcmp(clientLog[i].mac, m, 6) == 0)
      return (millis() - clientLog[i].joinMs) / 1000;
  return 0;
}

// ─── HELPERS
// ──────────────────────────────────────────────────────────────────
String jb(bool v) { return v ? "true" : "false"; }
String esc(String s) {
  s.replace("\\", "\\\\");
  s.replace("\"", "\\\"");
  s.replace("\n", "\\n");
  s.replace("\r", "\\r");
  s.replace("\t", "\\t");
  return s;
}
String macStr(const uint8_t *m) {
  char b[18];
  snprintf(b, 18, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4],
           m[5]);
  return b;
}
String hexStr(const uint8_t *d, int len) {
  String s = "";
  char h[3];
  for (int i = 0; i < len && i < 32; i++) {
    snprintf(h, 3, "%02X", d[i]);
    s += h;
  }
  return s;
}
String nowTs() {
  unsigned long s = millis() / 1000, m = (s / 60) % 60, h = (s / 3600) % 24;
  char b[10];
  snprintf(b, 10, "%02lu:%02lu:%02lu", h, m, s % 60);
  return b;
}

void setNeo(uint8_t r, uint8_t g, uint8_t b) {
  neo.setPixelColor(0, neo.Color(r, g, b));
  neo.show();
}
void broadcastChat(String j) { wsChat.broadcastTXT(j); }

// ─── PROMISCUOUS CALLBACK
// ─────────────────────────────────────────────────────
void IRAM_ATTR promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (!snifferActive && !deauthMode && !kismetMode && !pmkidMode)
    return;
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  const uint8_t *pl = pkt->payload;
  uint8_t fc = pl[0];
  uint8_t ftyp = (fc >> 2) & 0x03;
  uint8_t fsub = (fc >> 4) & 0x0F;
  int8_t rssi = pkt->rx_ctrl.rssi;
  uint8_t ch = pkt->rx_ctrl.channel;

  // ── DEAUTH DETECTION ──
  if (ftyp == 0 && (fsub == 12 || fsub == 10)) {
    _deauthCnt++;
    if (pkt->rx_ctrl.sig_len >= 16)
      snprintf((char *)_deauthMAC, 20, "%02X:%02X:%02X:%02X:%02X:%02X", pl[10],
               pl[11], pl[12], pl[13], pl[14], pl[15]);
  }

  // ── BEACON ──
  if (ftyp == 0 && fsub == 8 && pkt->rx_ctrl.sig_len > 36) {
    uint8_t bssid[6];
    memcpy(bssid, pl + 16, 6);
    const uint8_t *tags = pl + 36;
    int tlen = pkt->rx_ctrl.sig_len - 36;
    char ssid[33] = {0};
    for (int i = 0; i < tlen - 2;) {
      if (tags[i] == 0) {
        int sl = tags[i + 1];
        if (sl > 32)
          sl = 32;
        memcpy(ssid, tags + i + 2, sl);
        ssid[sl] = 0;
        break;
      }
      i += 2 + tags[i + 1];
    }
    if (kismetMode) {
      bool found = false;
      for (int i = 0; i < MAX_AP; i++) {
        if (kisAPs[i].valid &&
            memcmp(kisAPs[i].bssid, macStr(bssid).c_str(), 17) == 0) {
          kisAPs[i].rssi = rssi;
          kisAPs[i].ts = millis();
          found = true;
          break;
        }
      }
      if (!found)
        for (int i = 0; i < MAX_AP; i++)
          if (!kisAPs[i].valid) {
            strncpy(kisAPs[i].bssid, macStr(bssid).c_str(), 17);
            strncpy(kisAPs[i].ssid, ssid, 32);
            kisAPs[i].rssi = rssi;
            kisAPs[i].ch = ch;
            kisAPs[i].enc = 0;
            kisAPs[i].valid = true;
            kisAPs[i].ts = millis();
            break;
          }
    }
    if (millis() - beaconWindow > 2000) {
      beaconWindow = millis();
      beaconBurst = 0;
    }
    beaconBurst++;
    if (beaconBurst > 50)
      strncpy(beaconSSID, ssid, 32);
    beaconCnt = beaconBurst;
  }

  // ── PROBE REQUESTS ──
  if (ftyp == 0 && fsub == 4 && pkt->rx_ctrl.sig_len > 24) {
    uint8_t src[6];
    memcpy(src, pl + 10, 6);
    const uint8_t *tags = pl + 24;
    int tlen = pkt->rx_ctrl.sig_len - 24;
    char ssid[33] = {0};
    for (int i = 0; i < tlen - 2;) {
      if (tags[i] == 0) {
        int sl = tags[i + 1];
        if (sl > 0 && sl <= 32) {
          memcpy(ssid, tags + i + 2, sl);
          ssid[sl] = 0;
        }
        break;
      }
      i += 2 + tags[i + 1];
    }
    if (strlen(ssid) > 0) {
      bool found = false;
      for (int i = 0; i < probeCount; i++)
        if (memcmp(probeLog[i].mac, macStr(src).c_str(), 17) == 0 &&
            strcmp(probeLog[i].ssid, ssid) == 0) {
          probeLog[i].ts = millis();
          found = true;
          break;
        }
      if (!found && probeCount < MAX_PROBE) {
        strncpy(probeLog[probeCount].mac, macStr(src).c_str(), 17);
        strncpy(probeLog[probeCount].ssid, ssid, 32);
        probeLog[probeCount].ts = millis();
        probeCount++;
      }
    }
  }

  // ── PMKID ──
  if (pmkidMode && ftyp == 2 && pkt->rx_ctrl.sig_len > 80) {
    const uint8_t *data = pl + 32;
    int dlen = pkt->rx_ctrl.sig_len - 32;
    if (dlen > 32 && data[0] == 0x02 && data[1] == 0x03) {
      uint8_t keyinfo2 = data[6];
      bool ack = (keyinfo2 >> 7) & 1, mic = (keyinfo2 >> 0) & 1;
      if (ack && !mic && dlen > 116) {
        const uint8_t *pmkid_ptr = data + 88;
        if (pmkid_ptr[0] == 0xdd && pmkid_ptr[1] == 0x14) {
          uint8_t src[6], dst[6];
          memcpy(src, pl + 10, 6);
          memcpy(dst, pl + 4, 6);
          if (pmkidCount < MAX_PMKID) {
            strncpy(pmkidLog[pmkidCount].bssid, macStr(src).c_str(), 17);
            strncpy(pmkidLog[pmkidCount].client, macStr(dst).c_str(), 17);
            strncpy(pmkidLog[pmkidCount].pmkid,
                    hexStr(pmkid_ptr + 6, 16).c_str(), 33);
            pmkidLog[pmkidCount].ts = millis();
            pmkidCount++;
          }
        }
      }
    }
  }

  // ── SNIFFER LOG ──
  if (snifferActive) {
    int idx = pktHead % MAX_PKT_LOG;
    if (pkt->rx_ctrl.sig_len >= 16) {
      snprintf(pktLog[idx].srcMAC, 18, "%02X:%02X:%02X:%02X:%02X:%02X", pl[10],
               pl[11], pl[12], pl[13], pl[14], pl[15]);
      snprintf(pktLog[idx].dstMAC, 18, "%02X:%02X:%02X:%02X:%02X:%02X", pl[4],
               pl[5], pl[6], pl[7], pl[8], pl[9]);
    }
    pktLog[idx].type = ftyp;
    pktLog[idx].subtype = fsub;
    pktLog[idx].rssi = rssi;
    pktLog[idx].channel = ch;
    pktLog[idx].ts = millis();
    static const char *mnames[16] = {"ASSOC_REQ",
                                     "ASSOC_RSP",
                                     "REASSOC_REQ",
                                     "REASSOC_RSP",
                                     "PROBE_REQ",
                                     "PROBE_RSP",
                                     "",
                                     "",
                                     "BEACON",
                                     "ATIM",
                                     "DISASSOC",
                                     "AUTH",
                                     "DEAUTH",
                                     "ACTION",
                                     "",
                                     "?"};
    if (ftyp == 0)
      snprintf(pktLog[idx].info, 32, "MGMT/%s", mnames[fsub & 15]);
    else if (ftyp == 1)
      snprintf(pktLog[idx].info, 32, "CTRL/0x%X", fsub);
    else if (ftyp == 2)
      snprintf(pktLog[idx].info, 32, "DATA/0x%X", fsub);
    else
      snprintf(pktLog[idx].info, 32, "EXT/0x%X", fsub);
    pktHead++;
    if (pktTotal < MAX_PKT_LOG)
      pktTotal++;
  }
}

// ─── BLE
// ──────────────────────────────────────────────────────────────────────
class AxiomBLECb : public BLEAdvertisedDeviceCallbacks {
public:
  String json = "[";
  int cnt = 0;
  void onResult(BLEAdvertisedDevice d) {
    if (cnt > 0)
      json += ",";
    String nm = d.haveName() ? d.getName().c_str() : "Unknown";
    nm.replace("\"", "'");
    String mfr = "";
    if (d.haveManufacturerData()) {
      String raw = d.getManufacturerData().c_str();
      if (raw.length() >= 2) {
        uint16_t id = (uint8_t)raw[1] << 8 | (uint8_t)raw[0];
        if (id == 0x004C)
          mfr = "Apple";
        else if (id == 0x0006)
          mfr = "Microsoft";
        else if (id == 0x02E5)
          mfr = "Espressif";
        else if (id == 0x0075)
          mfr = "Samsung";
        else {
          char h[8];
          snprintf(h, 8, "0x%04X", id);
          mfr = h;
        }
      }
    }
    json += "{\"n\":\"" + nm + "\",\"a\":\"" +
            String(d.getAddress().toString().c_str()) +
            "\",\"r\":" + String(d.getRSSI()) + ",\"m\":\"" + mfr + "\"}";
    cnt++;
  }
};
AxiomBLECb *bleCb = nullptr;
BLEScan *pBLEScan = nullptr;

// ─── WEBSOCKET CHAT
// ───────────────────────────────────────────────────────────
void wsEvent(uint8_t num, WStype_t type, uint8_t *pl, size_t len) {
  switch (type) {
  case WStype_CONNECTED:
    broadcastChat("{\"t\":\"sys\",\"msg\":\"User joined\",\"n\":" +
                  String(wsChat.connectedClients()) + "}");
    break;
  case WStype_DISCONNECTED:
    broadcastChat("{\"t\":\"sys\",\"msg\":\"User left\",\"n\":" +
                  String(wsChat.connectedClients()) + "}");
    break;
  case WStype_TEXT: {
    StaticJsonDocument<300> doc;
    if (deserializeJson(doc, (char *)pl))
      return;
    if (String((const char *)doc["t"]) == "chat") {
      String nm = String((const char *)doc["n"]).substring(0, 16);
      String tx = String((const char *)doc["m"]).substring(0, 200);
      nm.replace("\"", "'");
      tx.replace("\"", "'");
      broadcastChat("{\"t\":\"chat\",\"n\":\"" + nm + "\",\"m\":\"" + tx +
                    "\",\"ts\":\"" + nowTs() + "\"}");
    }
    break;
  }
  default:
    break;
  }
}

void startPromiscuous() {
  if (!snifferActive && !deauthMode && !kismetMode && !pmkidMode)
    return;
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&promisc_cb);
}
void stopPromiscuous() {
  if (snifferActive || deauthMode || kismetMode || pmkidMode)
    return;
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(nullptr);
}

// ══════════════════════════════════════════════════════════════════════════════
//  HTML — AXIOM v9 DASHBOARD
// ══════════════════════════════════════════════════════════════════════════════
const char HTML[] PROGMEM = R"RAWHTML(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1"/>
<title>AXIOM v12</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0c0a14;--bg1:#13101e;--bg2:#1a1628;
  --bd:rgba(120,100,220,.12);--bd2:rgba(120,100,220,.25);
  --accent:#836FFF;--mint:#15F5BA;--red:#ff6b6b;--amber:#fbbf24;
  --tx:#d4d0e8;--tx2:#9892b0;--dim:#4a4660;
}
html{font-size:16px}
body{background:var(--bg);color:var(--tx);font-family:'Courier New',monospace;min-height:100vh}
.shell{max-width:820px;margin:0 auto;padding:10px 12px 24px}

/* Header */
.hdr{display:flex;align-items:center;justify-content:space-between;padding:10px 16px;
  margin-bottom:10px;background:var(--bg1);border:1px solid var(--bd2);border-radius:10px}
.logo{font-weight:700;font-size:1.1rem;letter-spacing:5px;color:var(--accent)}
.hdr-r{display:flex;align-items:center;gap:6px;font-size:.55rem;color:var(--dim)}
.hdr-ip{color:var(--mint);letter-spacing:1px}
.pill{padding:2px 8px;border-radius:12px;font-size:.5rem;letter-spacing:1.5px;font-weight:700;white-space:nowrap}
.p-on{background:rgba(21,245,186,.1);color:var(--mint);border:1px solid rgba(21,245,186,.25)}
.p-off{background:rgba(74,70,96,.15);color:var(--dim);border:1px solid rgba(74,70,96,.25)}
.p-v{background:rgba(131,111,255,.1);color:var(--accent);border:1px solid rgba(131,111,255,.25)}
.p-rd{background:rgba(255,107,107,.1);color:var(--red);border:1px solid rgba(255,107,107,.25)}

/* Tabs */
.tabs{display:flex;gap:4px;margin-bottom:10px;overflow-x:auto;scrollbar-width:none;-webkit-overflow-scrolling:touch}
.tabs::-webkit-scrollbar{display:none}
.tab{padding:7px 10px;border:1px solid transparent;border-radius:7px;background:transparent;
  color:var(--dim);font-size:.55rem;letter-spacing:1px;cursor:pointer;white-space:nowrap;
  font-family:inherit;transition:color .15s,border-color .15s}
.tab.active{border-color:var(--bd2);color:var(--accent);background:rgba(131,111,255,.08)}
.tab:hover:not(.active){color:var(--tx2)}
.page{display:none}.page.active{display:block}

/* Cards */
.g{background:var(--bg1);border:1px solid var(--bd);border-radius:10px;padding:14px;margin-bottom:10px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:10px}
.sp{grid-column:1/-1}

.ct{font-size:.5rem;letter-spacing:3px;color:var(--dim);text-transform:uppercase;margin-bottom:10px;
  display:flex;align-items:center;gap:8px}
.ct::after{content:'';flex:1;height:1px;background:var(--bd)}

.ir{display:flex;justify-content:space-between;font-size:.65rem;color:var(--dim);
  padding:4px 0;border-bottom:1px solid rgba(255,255,255,.02)}
.ir span:last-child{color:var(--tx);text-align:right;max-width:55%}
.ir.nb{border-bottom:none}

/* Buttons */
.btn{width:100%;padding:8px;border-radius:8px;font-family:inherit;
  font-size:.55rem;letter-spacing:1.5px;cursor:pointer;transition:opacity .15s;margin-top:6px}
.btn:hover{opacity:.85}
.btn:disabled{opacity:.3;cursor:not-allowed}
.bv{background:rgba(131,111,255,.1);border:1px solid rgba(131,111,255,.25);color:var(--accent)}
.bm{background:rgba(21,245,186,.1);border:1px solid rgba(21,245,186,.25);color:var(--mint)}
.bo{background:rgba(251,191,36,.1);border:1px solid rgba(251,191,36,.25);color:var(--amber)}
.br{background:rgba(255,107,107,.08);border:1px solid rgba(255,107,107,.22);color:var(--red)}

/* Form fields */
.fld{margin-bottom:8px}
.fld label{display:block;font-size:.48rem;color:var(--dim);letter-spacing:2px;margin-bottom:3px}
.fld input,.fld select,.fld textarea{width:100%;background:var(--bg);border:1px solid var(--bd);
  border-radius:7px;padding:7px 10px;color:var(--tx);font-family:inherit;font-size:.65rem;outline:none}
.fld input:focus,.fld select:focus{border-color:rgba(131,111,255,.4)}
.fld select option{background:var(--bg1)}

/* Sliders */
.slk{padding:7px 10px;background:var(--bg);border:1px solid var(--bd);border-radius:7px;margin-bottom:7px}
.slbl{font-size:.48rem;color:var(--dim);letter-spacing:1.5px;margin-bottom:3px}
.slider{width:100%;-webkit-appearance:none;height:3px;border-radius:2px;background:rgba(255,255,255,.06);outline:none}
.slider::-webkit-slider-thumb{-webkit-appearance:none;width:14px;height:14px;border-radius:50%;
  background:var(--accent);cursor:pointer}

/* Badges */
.badge{padding:2px 7px;border-radius:12px;font-size:.5rem;letter-spacing:1.5px;display:inline-block}
.bv2{background:rgba(131,111,255,.08);color:var(--accent);border:1px solid rgba(131,111,255,.2)}
.bm2{background:rgba(21,245,186,.08);color:var(--mint);border:1px solid rgba(21,245,186,.2)}
.br2{background:rgba(255,107,107,.08);color:var(--red);border:1px solid rgba(255,107,107,.2)}
.bx2{background:rgba(74,70,96,.1);color:var(--dim);border:1px solid rgba(74,70,96,.15)}

/* Table */
.tbl{width:100%;border-collapse:collapse;font-size:.6rem;margin-top:6px}
.tbl th{color:var(--dim);letter-spacing:1.5px;padding:4px 5px;border-bottom:1px solid var(--bd);text-align:left;font-weight:400}
.tbl td{color:var(--dim);padding:4px 5px;border-bottom:1px solid rgba(255,255,255,.015);vertical-align:top}
.tbl tr:hover td{color:var(--tx2)}

/* Signal bars */
.sig{height:4px;border-radius:2px;display:inline-block;min-width:3px;vertical-align:middle}
.sv{background:linear-gradient(90deg,var(--accent),#5a4bd1)}
.sigs{display:flex;align-items:flex-end;gap:2px;height:13px}
.sb{width:3px;border-radius:1px;background:rgba(255,255,255,.08)}
.sb.on{background:var(--mint)}

/* GPIO grid */
.gpio-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(68px,1fr));gap:5px;margin-top:6px}
.gpio-btn{padding:6px 3px;border-radius:7px;border:1px solid var(--bd);background:var(--bg);
  cursor:pointer;text-align:center;transition:border-color .15s;font-family:inherit}
.gpio-btn .gn{font-size:.5rem;color:var(--dim);letter-spacing:1px;display:block;margin-bottom:2px}
.gpio-btn .gs{font-size:.58rem;font-weight:700}
.gpio-btn.off .gs{color:var(--dim)}
.gpio-btn.on{border-color:rgba(21,245,186,.3);background:rgba(21,245,186,.04)}
.gpio-btn.on .gs{color:var(--mint)}
.gpio-btn.adc{border-color:rgba(131,111,255,.12)}
.gpio-btn.adc .gn::after{content:' ADC';color:rgba(131,111,255,.35);font-size:.42rem}
.gpio-btn:hover{border-color:rgba(131,111,255,.25)}

/* Network list */
.net-item{display:flex;align-items:center;justify-content:space-between;padding:7px 9px;
  border-radius:7px;border:1px solid var(--bd);background:var(--bg);margin-bottom:4px;
  cursor:pointer;transition:border-color .15s}
.net-item:hover{border-color:rgba(21,245,186,.25)}
.net-item.sel{border-color:rgba(21,245,186,.4)}
.net-n{font-size:.65rem;color:var(--tx)}
.net-m{display:flex;align-items:center;gap:6px}

/* Status box */
.stabox{background:var(--bg);border:1px solid var(--bd);border-radius:7px;padding:8px 10px;margin-top:7px}
.sts{display:flex;justify-content:space-between;padding:3px 0;font-size:.6rem}
.stk{color:var(--dim)}.stv{color:var(--tx2)}
.stv.g{color:var(--mint)}.stv.o{color:var(--amber)}.stv.r{color:var(--red)}

/* Modal */
.mbg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:300;
  align-items:center;justify-content:center}
.mbg.show{display:flex}
.modal{background:var(--bg1);border:1px solid var(--bd2);border-radius:12px;padding:18px;
  width:min(320px,90vw)}
.modal h3{font-size:.65rem;letter-spacing:2px;color:var(--mint);margin-bottom:10px}
.mbns{display:flex;gap:6px;margin-top:6px}.mbns .btn{margin-top:0;flex:1}
#mSt{font-size:.52rem;letter-spacing:1px;display:block;margin-bottom:6px;min-height:12px}

/* Log viewers */
#evtLog,#pktLog{background:var(--bg);border:1px solid var(--bd);border-radius:7px;
  padding:7px;overflow-y:auto;font-size:.55rem;line-height:1.8}
#evtLog{height:90px}
#pktLog{height:200px}
.le{color:rgba(131,111,255,.4)}.le.w{color:rgba(251,191,36,.4)}.le.g{color:rgba(21,245,186,.4)}.le.r{color:rgba(255,107,107,.4)}
.pk-m{color:rgba(131,111,255,.65)}.pk-d{color:rgba(21,245,186,.55)}.pk-c{color:rgba(251,191,36,.55)}.pk-x{color:rgba(255,107,107,.5)}

/* Toggle */
.row{display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;
  padding:6px 9px;border-radius:7px;border:1px solid rgba(131,111,255,.06);background:var(--bg)}
.lbl{font-size:.65rem;color:var(--tx2)}
.tog{width:40px;height:20px;border-radius:10px;border:none;cursor:pointer;position:relative;
  transition:background .2s;background:rgba(131,111,255,.12);flex-shrink:0}
.tog.on{background:var(--mint)}
.tog::after{content:'';position:absolute;width:14px;height:14px;border-radius:50%;
  background:#fff;top:3px;left:3px;transition:transform .2s}
.tog.on::after{transform:translateX(20px)}

/* LED dots */
.rgbrow{display:flex;gap:7px;flex-wrap:wrap;padding:6px 0}
.dot{width:34px;height:34px;border-radius:50%;cursor:pointer;border:2px solid transparent;
  transition:transform .15s;display:flex;align-items:center;justify-content:center;
  font-size:.48rem;font-weight:700;letter-spacing:1px}
.dot:hover{transform:scale(1.1)}

/* Gauge bars */
.gr{display:flex;align-items:center;gap:8px;margin-bottom:5px}
.gb{flex:1;height:3px;background:rgba(255,255,255,.04);border-radius:2px;overflow:hidden}
.gf{height:100%;border-radius:2px;transition:width .6s}

/* Touch orb */
.torb{width:56px;height:56px;border-radius:50%;border:2px solid var(--bd);
  display:flex;align-items:center;justify-content:center;font-size:.55rem;color:var(--dim);transition:all .3s}
.torb.on{border-color:rgba(131,111,255,.45);background:rgba(131,111,255,.06);color:var(--accent)}

/* Channel canvas */
#chCv{width:100%;height:80px;display:block;margin-top:5px}

/* Deauth counter */
.dan{font-size:2.5rem;font-weight:700;line-height:1;text-align:center;letter-spacing:3px;color:var(--accent)}
.dal{font-size:.48rem;color:var(--dim);letter-spacing:2px;text-align:center;margin-top:2px}
.daa{font-size:.58rem;color:var(--red);letter-spacing:2px;text-align:center;margin-top:5px;display:none}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}

/* Warning box */
.warn-box{background:rgba(255,107,107,.05);border:1px solid rgba(255,107,107,.15);
  border-radius:7px;padding:8px 10px;margin-bottom:8px;font-size:.55rem;color:rgba(255,107,107,.7);line-height:1.6}

footer{text-align:center;margin-top:16px;font-size:.44rem;color:rgba(255,255,255,.06);letter-spacing:2px;padding-bottom:8px}
</style>
</head>
<body>
<div class="shell">

<!-- Header -->
<div class="hdr">
  <div class="logo">AXIOM</div>
  <div class="hdr-r">
    <span class="hdr-ip" id="hIP">192.168.4.1</span>
    <span class="pill p-on">AP</span>
    <span class="pill p-off" id="staPill" style="display:none">STA</span>
    <span class="pill p-rd" id="cyberPill" style="display:none">CYBER</span>
  </div>
</div>

<!-- Tabs -->
<div class="tabs">
  <button class="tab active"          onclick="P('wifi',this)">WIFI</button>
  <button class="tab"                 onclick="P('gpio',this)">GPIO</button>
  <button class="tab"                 onclick="P('ble',this)">BLE</button>
  <button class="tab"                 onclick="P('datapanel',this)">DATA</button>
  <button class="tab"                 onclick="P('sniffer',this)">SNIFFER</button>
  <button class="tab"                 onclick="P('kismet',this)">KISMET</button>
  <button class="tab"                 onclick="P('pmkid',this)">PMKID</button>
  <button class="tab"                 onclick="P('deauth',this)">RF INTEL</button>
  <button class="tab"                 onclick="P('recon',this)">RECON</button>
  <button class="tab"                 onclick="P('chat',this)">CHAT</button>
  <button class="tab"                 onclick="P('system',this)">SYSTEM</button>
  <button class="tab"                 onclick="P('display',this)">DISPLAY</button>
</div>

<!-- WIFI -->
<div class="page active" id="wifiPage">
  <div class="grid">
    <div class="g sp">
      <div class="ct">WIFI SCANNER
        <span id="wBridge" class="pill p-off" style="margin-left:auto">STA OFF</span>
      </div>
      <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-bottom:8px">
        <button class="btn bm" id="wSB" onclick="wScan()" style="width:auto;margin:0;padding:6px 14px">SCAN</button>
        <span id="wSS" style="font-size:.55rem;color:var(--dim);letter-spacing:1.5px"></span>
      </div>
      <div id="netList"><div style="color:var(--dim);font-size:.58rem;text-align:center;padding:12px">Scan to see networks</div></div>
    </div>
    <div class="g">
      <div class="ct">UPLINK (STA)</div>
      <div class="ir"><span>STATUS</span><span id="staSt">--</span></div>
      <div class="ir"><span>NETWORK</span><span id="staS">--</span></div>
      <div class="ir"><span>IP</span><span id="staI">--</span></div>
      <div class="ir nb"><span>RSSI</span><span id="staR">--</span></div>
      <button class="btn br" id="discBtn" onclick="wDisc()" style="display:none">DISCONNECT</button>
    </div>
    <div class="g">
      <div class="ct">RGB LED (GPIO 48)</div>
      <div class="rgbrow">
        <div class="dot" style="background:#ef4444;color:#fff" onclick="setLED(255,0,0)">R</div>
        <div class="dot" style="background:#22c55e;color:#fff" onclick="setLED(0,255,0)">G</div>
        <div class="dot" style="background:#3b82f6;color:#fff" onclick="setLED(0,0,255)">B</div>
        <div class="dot" style="background:#15F5BA;color:#000" onclick="setLED(21,245,186)">M</div>
        <div class="dot" style="background:#836FFF;color:#fff" onclick="setLED(131,111,255)">V</div>
        <div class="dot" style="background:#1e1b34;color:#555;border:1px solid #334155" onclick="setLED(0,0,0)">OFF</div>
      </div>
      <div class="stabox">
        <div class="sts"><span class="stk">NET</span><span class="stv" id="sbNet">--</span></div>
        <div class="sts"><span class="stk">SIGNAL</span><span class="stv" id="sbSig">--</span></div>
        <div class="sts"><span class="stk">STATUS</span><span class="stv" id="sbSt">IDLE</span></div>
        <div class="sts"><span class="stk">IP</span><span class="stv" id="sbIP">--</span></div>
      </div>
    </div>
    <div class="g sp">
      <div class="ct">AP CONFIG (FLASH)</div>
      <div class="grid" style="grid-template-columns:1fr 1fr;gap:8px">
        <div><div class="fld"><label>SSID</label><input type="text" id="nSsid" maxlength="32"/></div></div>
        <div><div class="fld"><label>PASSWORD (8+)</label><input type="password" id="nPass" maxlength="64"/></div></div>
      </div>
      <div class="fld"><label>CONFIRM</label><input type="password" id="nPassC" maxlength="64"/></div>
      <span id="apSt" style="font-size:.52rem;color:var(--dim);display:block;margin-top:3px"></span>
      <button class="btn bm" onclick="saveAP()">SAVE & REBOOT</button>
    </div>
  </div>
</div>

<!-- GPIO -->
<div class="page" id="gpioPage">
  <div class="grid">
    <div class="g sp">
      <div class="ct">OUTPUT PINS</div>
      <div class="gpio-grid" id="gpioGrid"></div>
    </div>
    <div class="g">
      <div class="ct">PWM</div>
      <div class="slk"><div class="slbl">GPIO 4 CH0 <span id="d0">0</span>/255</div>
        <input type="range" class="slider" min="0" max="255" value="0" oninput="setPWM(0,this.value)"/>
        <button class="btn bv" style="margin-top:3px;padding:3px;font-size:.48rem" onclick="togPWM(0)" id="pm0">ENABLE</button></div>
      <div class="slk"><div class="slbl">GPIO 5 CH1 <span id="d1">0</span>/255</div>
        <input type="range" class="slider" min="0" max="255" value="0" oninput="setPWM(1,this.value)"/>
        <button class="btn bv" style="margin-top:3px;padding:3px;font-size:.48rem" onclick="togPWM(1)" id="pm1">ENABLE</button></div>
      <div class="slk"><div class="slbl">GPIO 6 CH2 <span id="d2">0</span>/255</div>
        <input type="range" class="slider" min="0" max="255" value="0" oninput="setPWM(2,this.value)"/>
        <button class="btn bv" style="margin-top:3px;padding:3px;font-size:.48rem" onclick="togPWM(2)" id="pm2">ENABLE</button></div>
    </div>
    <div class="g">
      <div class="ct">INPUTS</div>
      <div class="row"><span class="lbl">GPIO 7 IN1</span><span class="badge bx2" id="in0">--</span></div>
      <div class="row"><span class="lbl">GPIO 8 IN2</span><span class="badge bx2" id="in1">--</span></div>
      <div class="ct" style="margin-top:10px">TOUCH</div>
      <div style="display:flex;gap:14px;justify-content:center;padding:8px 0">
        <div style="text-align:center"><div class="torb" id="tc0">T1</div>
          <div style="font-size:.48rem;color:var(--dim);margin-top:3px">GPIO 1</div>
          <div style="font-size:.5rem;color:var(--dim);margin-top:1px" id="tv0">--</div></div>
        <div style="text-align:center"><div class="torb" id="tc1">T2</div>
          <div style="font-size:.48rem;color:var(--dim);margin-top:3px">GPIO 2</div>
          <div style="font-size:.5rem;color:var(--dim);margin-top:1px" id="tv1">--</div></div>
      </div>
      <div class="fld"><label>T1 ACTION</label>
        <select id="ta0"><option value="none">None</option><option value="gpio0">Toggle GPIO 4</option>
          <option value="gpio1">Toggle GPIO 5</option><option value="gpio2">Toggle GPIO 6</option>
          <option value="sleep">Deep Sleep</option></select></div>
      <div class="fld"><label>T2 ACTION</label>
        <select id="ta1"><option value="none">None</option><option value="gpio0">Toggle GPIO 4</option>
          <option value="gpio1">Toggle GPIO 5</option><option value="gpio2">Toggle GPIO 6</option>
          <option value="sleep">Deep Sleep</option></select></div>
      <button class="btn bm" onclick="saveTouchAct()">SAVE TOUCH</button>
    </div>
    <div class="g sp"><div class="ct">EVENT LOG</div>
      <div id="evtLog"><span style="color:var(--dim)">Waiting...</span></div></div>
  </div>
</div>

<!-- BLE -->
<div class="page" id="blePage">
  <div class="g">
    <div class="ct">BLE SCANNER</div>
    <div style="display:flex;gap:6px;align-items:center;margin-bottom:8px">
      <button class="btn bv" id="bSB" onclick="bScan()" style="width:auto;margin:0;padding:6px 14px">SCAN</button>
      <span id="bSS" style="font-size:.55rem;color:var(--dim);letter-spacing:1.5px"></span>
    </div>
    <table class="tbl">
      <thead><tr><th>NAME</th><th>MAC</th><th>VENDOR</th><th>RSSI</th><th>SIG</th></tr></thead>
      <tbody id="bT"><tr><td colspan="5" style="color:var(--dim);text-align:center;padding:12px">Scan to find BLE devices</td></tr></tbody>
    </table>
  </div>
</div>

<!-- SNIFFER -->
<div class="page" id="snifferPage">
  <div class="warn-box">Authorized lab use only. Capturing 802.11 frames on networks you do not own is illegal.</div>
  <div class="grid">
    <div class="g sp">
      <div class="ct">PACKET SNIFFER</div>
      <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-bottom:8px">
        <button class="btn bm" id="snifBtn" onclick="togSniffer()" style="width:auto;margin:0;padding:6px 14px">START</button>
        <button class="btn bv" onclick="clearPkts()" style="width:auto;margin:0;padding:6px 10px">CLEAR</button>
        <span id="snifSt" style="font-size:.55rem;color:var(--dim);letter-spacing:1.5px"></span>
        <label style="font-size:.5rem;color:var(--dim);margin-left:auto">
          <input type="checkbox" id="hopCb" onchange="setHop(this.checked)" style="margin-right:3px"/>HOP</label>
        <select id="chanSel" style="background:var(--bg);border:1px solid var(--bd);border-radius:6px;
          padding:3px 6px;color:var(--tx);font-family:inherit;font-size:.55rem">
          <option value="0">ALL</option>
          <option value="1">CH1</option><option value="6">CH6</option><option value="11">CH11</option>
          <option value="2">CH2</option><option value="3">CH3</option><option value="4">CH4</option>
          <option value="5">CH5</option><option value="7">CH7</option><option value="8">CH8</option>
          <option value="9">CH9</option><option value="10">CH10</option><option value="13">CH13</option>
        </select>
      </div>
      <div id="pktLog"><span style="color:var(--dim)">Start capture...</span></div>
      <div style="display:flex;justify-content:space-between;margin-top:5px;font-size:.5rem;color:var(--dim)">
        <span>TOTAL: <span id="pktTotal" style="color:var(--accent)">0</span></span>
        <span>MGMT: <span id="pktMgmt" style="color:var(--accent)">0</span></span>
        <span>DATA: <span id="pktData" style="color:var(--mint)">0</span></span>
        <span>CTRL: <span id="pktCtrl" style="color:var(--amber)">0</span></span>
      </div>
    </div>
  </div>
</div>

<!-- KISMET -->
<div class="page" id="kismetPage">
  <div class="warn-box">Authorized lab use only. Passively maps APs, clients, and probes.</div>
  <div class="grid">
    <div class="g sp">
      <div class="ct">KISMET MAPPER</div>
      <div style="display:flex;gap:6px;align-items:center;margin-bottom:8px;flex-wrap:wrap">
        <button class="btn bm" id="kisBtn" onclick="togKismet()" style="width:auto;margin:0;padding:6px 14px">START</button>
        <button class="btn bv" onclick="clearKismet()" style="width:auto;margin:0;padding:6px 10px">CLEAR</button>
        <span id="kisSt" style="font-size:.55rem;color:var(--dim);letter-spacing:1.5px"></span>
      </div>
      <div class="ct">ACCESS POINTS</div>
      <table class="tbl">
        <thead><tr><th>BSSID</th><th>SSID</th><th>CH</th><th>RSSI</th><th>SIG</th><th>AGE</th></tr></thead>
        <tbody id="kApT"><tr><td colspan="6" style="color:var(--dim);text-align:center;padding:10px">Start to discover APs</td></tr></tbody>
      </table>
    </div>
    <div class="g sp">
      <div class="ct">PROBE REQUESTS</div>
      <table class="tbl">
        <thead><tr><th>CLIENT</th><th>SSID</th><th>AGE</th></tr></thead>
        <tbody id="kProbeT"><tr><td colspan="3" style="color:var(--dim);text-align:center;padding:10px">No probes</td></tr></tbody>
      </table>
    </div>
  </div>
</div>

<!-- PMKID -->
<div class="page" id="pmkidPage">
  <div class="warn-box">Authorized lab use only. PMKID capture for WPA2 offline analysis.</div>
  <div class="g sp">
    <div class="ct">PMKID CAPTURE</div>
    <div style="display:flex;gap:6px;align-items:center;margin-bottom:8px;flex-wrap:wrap">
      <button class="btn bm" id="pmkBtn" onclick="togPMKID()" style="width:auto;margin:0;padding:6px 14px">START</button>
      <span id="pmkSt" style="font-size:.55rem;color:var(--dim);letter-spacing:1.5px"></span>
    </div>
    <table class="tbl">
      <thead><tr><th>AP BSSID</th><th>CLIENT</th><th>PMKID</th><th>TIME</th></tr></thead>
      <tbody id="pmkT"><tr><td colspan="4" style="color:var(--dim);text-align:center;padding:12px">No PMKID captured</td></tr></tbody>
    </table>
  </div>
</div>

<!-- RF INTEL -->
<div class="page" id="deauthPage">
  <div class="grid">
    <div class="g">
      <div class="ct">DEAUTH DETECTOR</div>
      <div style="text-align:center;padding:8px 0">
        <div class="dan" id="dCnt">0</div>
        <div class="dal">DEAUTH / DISASSOC FRAMES</div>
        <div class="daa" id="dAlert">ATTACK DETECTED</div>
      </div>
      <div class="ir"><span>LAST MAC</span><span id="dMac" style="color:var(--red);font-size:.55rem">--</span></div>
      <div class="ir nb"><span>CHANNEL</span><span id="dChan">--</span></div>
      <button class="btn bo" id="dBtn" onclick="togDeauth()">START</button>
    </div>
    <div class="g">
      <div class="ct">CHANNEL MAP</div>
      <div style="display:flex;gap:6px;margin-bottom:5px">
        <button class="btn bm" onclick="scanCh()" style="width:auto;margin:0;padding:5px 12px">SCAN</button>
        <span id="chSt" style="font-size:.55rem;color:var(--dim);letter-spacing:1.5px;align-self:center"></span>
      </div>
      <canvas id="chCv"></canvas>
      <div class="ir" style="margin-top:4px"><span>BEST CH</span><span id="bestCh" class="badge bm2">--</span></div>
    </div>
    <div class="g">
      <div class="ct">BEACON FLOOD</div>
      <div style="text-align:center;padding:8px 0">
        <div style="font-size:2.2rem;font-weight:700;color:var(--amber)" id="bfCnt">0</div>
        <div style="font-size:.48rem;color:var(--dim);letter-spacing:2px;margin-top:1px">BEACONS / 2s</div>
        <div id="bfAlert" style="font-size:.55rem;color:var(--red);letter-spacing:1.5px;margin-top:4px;display:none;animation:blink 1s infinite">FLOOD DETECTED</div>
      </div>
      <div class="ir nb"><span>SSID</span><span id="bfSSID" style="color:var(--amber);font-size:.55rem">--</span></div>
    </div>
    <div class="g">
      <div class="ct">EVIL TWIN</div>
      <p style="font-size:.55rem;color:var(--dim);line-height:1.7;margin-bottom:6px">Detects duplicate SSIDs with different BSSIDs.</p>
      <button class="btn bm" onclick="detectEvilTwin()" style="width:auto;margin:0;padding:5px 12px">DETECT</button>
      <div id="etResults" style="font-size:.55rem;color:var(--dim);margin-top:6px">Scan first, then detect.</div>
    </div>
  </div>
</div>

<!-- RECON -->
<div class="page" id="reconPage">
  <div class="g sp">
    <div class="ct">CLIENT RECON</div>
    <div style="display:flex;gap:6px;align-items:center;margin-bottom:8px;flex-wrap:wrap">
      <button class="btn bo" id="rBtn" onclick="doRecon()">SCAN CLIENTS</button>
      <span id="rSt" style="font-size:.55rem;color:var(--dim);letter-spacing:1.5px"></span>
    </div>
    <table class="tbl">
      <thead><tr><th>VENDOR</th><th>IP</th><th>MAC</th><th>PORTS</th><th>AGE</th></tr></thead>
      <tbody id="rT"><tr><td colspan="5" style="color:var(--dim);text-align:center;padding:12px">No scan yet</td></tr></tbody>
    </table>
  </div>
</div>

<!-- CHAT -->
<div class="page" id="chatPage">
  <div style="display:flex;flex-direction:column;height:calc(100vh - 190px);min-height:320px">
    <div style="background:var(--bg1);border:1px solid var(--bd2);border-radius:10px 10px 0 0;padding:8px 12px;
      display:flex;align-items:center;justify-content:space-between">
      <span style="font-size:.55rem;letter-spacing:3px;color:var(--dim)">LAN CHAT</span>
      <div style="display:flex;gap:6px">
        <span id="onl" style="font-size:.48rem;color:var(--mint);letter-spacing:1.5px">0 ONLINE</span>
        <span class="pill p-off" id="wsp">OFFLINE</span>
      </div>
    </div>
    <div id="cMsgs" style="flex:1;background:var(--bg);border-left:1px solid var(--bd);
      border-right:1px solid var(--bd);padding:9px;overflow-y:auto;min-height:160px">
      <div style="text-align:center;font-size:.48rem;color:var(--dim);letter-spacing:2px;margin:5px 0">-- AXIOM LOCAL NETWORK --</div>
    </div>
    <div style="display:flex;gap:4px;background:var(--bg1);border:1px solid var(--bd2);
      border-radius:0 0 10px 10px;padding:7px">
      <input id="nIn" type="text" placeholder="NAME" maxlength="16" style="width:80px;background:var(--bg);
        border:1px solid var(--bd);border-radius:6px;padding:5px 8px;color:var(--tx);font-family:inherit;font-size:.6rem;outline:none;color:var(--dim)"/>
      <input id="mIn" type="text" placeholder="Message..." maxlength="200" style="flex:1;background:var(--bg);
        border:1px solid var(--bd);border-radius:6px;padding:5px 8px;color:var(--tx);font-family:inherit;font-size:.6rem;outline:none"
        onkeydown="if(event.key==='Enter')sChat()"/>
      <button onclick="sChat()" style="background:rgba(21,245,186,.1);border:1px solid rgba(21,245,186,.25);
        color:var(--mint);border-radius:6px;padding:5px 10px;font-family:inherit;font-size:.52rem;cursor:pointer;letter-spacing:1px">SEND</button>
    </div>
  </div>
</div>

<!-- SYSTEM -->
<div class="page" id="systemPage">
  <div class="grid">
    <div class="g">
      <div class="ct">ESP32-S3 INFO</div>
      <div class="ir"><span>UPTIME</span><span id="upt">--</span></div>
      <div class="ir"><span>FREE HEAP</span><span id="hp">--</span></div>
      <div class="ir"><span>CHIP TEMP</span><span id="tmp">--</span></div>
      <div class="ir"><span>CPU FREQ</span><span id="cpu">--</span></div>
      <div class="ir"><span>FLASH</span><span id="fl">--</span></div>
      <div class="ir"><span>PSRAM</span><span id="ps">--</span></div>
      <div class="ir"><span>CHIP ID</span><span id="cid">--</span></div>
      <div class="ir nb"><span>AP CLIENTS</span><span id="sCl">--</span></div>
    </div>
    <div class="g">
      <div class="ct">RESOURCE GAUGES</div>
      <div class="gr"><span style="font-size:.5rem;color:var(--dim);width:45px">HEAP</span>
        <div class="gb"><div class="gf" id="hBar" style="width:0%;background:linear-gradient(90deg,var(--accent),var(--mint))"></div></div>
        <span id="hPct" style="font-size:.48rem;color:var(--dim);width:28px;text-align:right">0%</span></div>
      <div class="gr"><span style="font-size:.5rem;color:var(--dim);width:45px">TEMP</span>
        <div class="gb"><div class="gf" id="tBar" style="width:0%;background:linear-gradient(90deg,var(--amber),var(--red))"></div></div>
        <span id="tPct" style="font-size:.48rem;color:var(--dim);width:28px;text-align:right">--</span></div>
    </div>
    <div class="g">
      <div class="ct">CPU SCALING</div>
      <div class="fld"><label>FREQUENCY</label>
        <select id="cpuF">
          <option value="240">240 MHz</option>
          <option value="160">160 MHz</option>
          <option value="80">80 MHz</option>
          <option value="40">40 MHz</option>
        </select></div>
      <button class="btn bv" onclick="setCPU()">SET FREQUENCY</button>
    </div>
    <div class="g">
      <div class="ct">POWER</div>
      <div class="fld"><label>DEEP SLEEP (SEC)</label>
        <input type="number" id="slpS" value="30" min="5" max="3600"/></div>
      <button class="btn bo" onclick="doSleep()">DEEP SLEEP</button>
      <button class="btn br" onclick="doReboot()" style="margin-top:10px">REBOOT</button>
      <div id="slpCd" style="display:none;text-align:center;font-size:.6rem;color:var(--amber);margin-top:8px"></div>
    </div>
  </div>
</div>

<!-- DATA PANEL -->
<div class="page" id="datapanelPage">
  <div class="grid">
    <div class="g sp">
      <div class="ct">REST ENDPOINTS
        <span id="dpStatus" class="pill p-on" style="margin-left:auto">LIVE</span>
      </div>
      <div style="display:flex;gap:5px;flex-wrap:wrap;margin-bottom:10px">
        <button class="btn bm" onclick="fetchApiData('/data')" style="width:auto;margin:0;padding:5px 10px">/data</button>
        <button class="btn bv" onclick="fetchApiData('/gpio')" style="width:auto;margin:0;padding:5px 10px">/gpio</button>
        <button class="btn bv" onclick="fetchApiData('/wifi')" style="width:auto;margin:0;padding:5px 10px">/wifi</button>
        <button class="btn bv" onclick="fetchApiData('/bluetooth')" style="width:auto;margin:0;padding:5px 10px">/bluetooth</button>
        <button class="btn bo" onclick="fetchApiData('/status?full=1')" style="width:auto;margin:0;padding:5px 10px">/status</button>
      </div>
      <div style="background:var(--bg);border:1px solid var(--bd);border-radius:8px;padding:10px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
          <span style="font-size:.55rem;color:var(--mint);letter-spacing:1.5px" id="apiEndpointTitle">/data</span>
          <div style="display:flex;gap:5px">
            <button onclick="autoRefreshToggle()" id="autoRefBtn" class="pill p-v" style="cursor:pointer">AUTO: ON</button>
            <span id="apiStatusBadge" class="badge bm2">200</span>
          </div>
        </div>
        <pre id="jsonViewer" style="background:var(--bg);color:var(--mint);padding:10px;border-radius:6px;font-size:.55rem;line-height:1.4;max-height:300px;overflow:auto;white-space:pre-wrap;word-break:break-all;border:1px solid var(--bd)">Loading...</pre>
      </div>
    </div>
    <div class="g">
      <div class="ct">SYSTEM</div>
      <div class="ir"><span>UPTIME</span><span id="dpUpt">--</span></div>
      <div class="ir"><span>HEAP</span><span id="dpHeap">--</span></div>
      <div class="ir"><span>CPU</span><span id="dpCpu">--</span></div>
      <div class="ir nb"><span>CHIP</span><span id="dpChip">--</span></div>
    </div>
    <div class="g">
      <div class="ct">WIFI</div>
      <div class="ir"><span>AP SSID</span><span id="dpApSsid">--</span></div>
      <div class="ir"><span>CLIENTS</span><span id="dpApClients">--</span></div>
      <div class="ir"><span>STA</span><span id="dpStaSt">--</span></div>
      <div class="ir nb"><span>STA IP</span><span id="dpStaIp">--</span></div>
    </div>
  </div>
</div>

<!-- DISPLAY -->
<div class="page" id="displayPage">
  <div class="grid">
    <div class="g sp">
      <div class="ct">OLED SH1106 (SPI)</div>
      <div class="ir"><span>PAGE</span><span id="oledPg">--</span></div>
      <div class="rgbrow" style="margin-top:6px;flex-wrap:nowrap">
        <button class="btn" style="flex:1;margin-top:0" onclick="oledNav('prev')">PREV</button>
        <button class="btn" style="flex:1;margin-top:0" onclick="oledNav('next')">NEXT</button>
      </div>
      <div class="ct" style="margin-top:10px">JUMP TO PAGE</div>
      <div class="gpio-grid" id="oledPages"></div>
    </div>
  </div>
</div>

</div><!-- /shell -->
<footer>AXIOM v12 · ESP32-S3</footer>

<!-- CONNECT MODAL -->
<div class="mbg" id="cModal">
  <div class="modal">
    <h3>CONNECT TO NETWORK</h3>
    <div class="fld"><label>SSID</label><input type="text" id="mSSID" readonly style="color:var(--mint)"/></div>
    <div class="fld"><label>PASSWORD</label><input type="password" id="mPw" placeholder="Password..."/></div>
    <span id="mSt"></span>
    <div class="mbns">
      <button class="btn bm" onclick="doConn()">CONNECT</button>
      <button class="btn br" onclick="closeM()">CANCEL</button>
    </div>
  </div>
</div>

<script>
// ── Utils ──
const $=id=>document.getElementById(id);
function set(id,v){const e=$(id);if(e)e.textContent=v;}
function xss(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function escJ(s){return String(s).replace(/\\/g,'\\\\').replace(/'/g,"\\'");}
function addLog(msg,cls=''){
  const l=$('evtLog'),ph=l.querySelector('span');if(ph)ph.remove();
  const t=new Date().toTimeString().slice(0,8),e=document.createElement('div');
  e.className='le '+cls;e.textContent='['+t+'] '+msg;l.appendChild(e);l.scrollTop=l.scrollHeight;}
void sigBars(int rssi){
  const p=Math.min(100,Math.max(0,(rssi+100)*2)),b=Math.round(p/25);
  return '<div class="sigs">'+[1,2,3,4].map(i=>'<div class="sb '+(i<=b?'on':'')+'" style="height:'+(i*3+2)+'px"></div>').join('')+'</div>';}

// ── Page switch ──
int P(int n, int el){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  $(n+'Page').classList.add('active');
  if(el)el.classList.add('active');
  if(n==='chat'&&!ws)initWS();
}

// ── Status poll (1s lightweight) ──
let pollCycle=0;
void poll(){
  pollCycle++;
  const url=(pollCycle%5===0)?'/status?full=1':'/status';
  fetch(url).then(r=>r.json()).then(d=>{
    const s=Math.floor(d.uptime/1000),m=Math.floor(s/60),h=Math.floor(m/60);
    set('upt',h+'h '+(m%60)+'m '+(s%60)+'s');
    set('hp',(d.heap/1024).toFixed(1)+' KB');
    set('tmp',d.temp.toFixed(1)+' C');
    set('cpu',d.cpu+' MHz');
    set('sCl',d.clients);
    const hp=Math.round((1-d.heap/(320*1024))*100);
    $('hBar').style.width=hp+'%';set('hPct',hp+'%');
    const tp=Math.min(100,Math.round((d.temp-20)/70*100));
    $('tBar').style.width=tp+'%';set('tPct',d.temp.toFixed(0)+'C');
    // STA
    const c=d.sta==='connected',stP=$('staPill');
    if(c){
      stP.style.display='block';stP.className='pill p-on';stP.textContent='STA: '+(d.staSSID||'');
      $('staSt').innerHTML='<span class="badge bm2">CONNECTED</span>';
      set('staS',d.staSSID||'--');set('staI',d.staIp||'--');set('staR',d.staRSSI+' dBm');
      $('wBridge').className='pill p-on';$('wBridge').textContent='STA ON';
      $('discBtn').style.display='block';
      $('sbSt').className='stv g';$('sbSt').textContent='CONNECTED';
      set('sbIP',d.staIp||'--');set('sbNet',d.staSSID||'--');
    }else{
      stP.style.display='none';
      $('staSt').innerHTML='<span class="badge bx2">'+(d.sta||'--').toUpperCase()+'</span>';
      set('staS','--');set('staI','--');set('staR','--');
      $('wBridge').className='pill p-off';$('wBridge').textContent='STA OFF';
      $('discBtn').style.display='none';
      if(d.sta==='connecting'){$('sbSt').className='stv o';$('sbSt').textContent='CONNECTING...';}
      else if(d.sta==='failed'){$('sbSt').className='stv r';$('sbSt').textContent='FAILED';}
      else{$('sbSt').className='stv';$('sbSt').textContent='IDLE';}
      set('sbIP','--');
    }
    set('dCnt',d.deauth||0);set('dMac',d.deauthMac||'--');set('dChan','CH '+(d.deauthChan||1));
    if($('dAlert'))$('dAlert').style.display=(d.deauth>0)?'block':'none';
    set('bfCnt',d.beaconCnt||0);set('bfSSID',d.beaconSSID||'--');
    if($('bfAlert'))$('bfAlert').style.display=(d.beaconCnt>50)?'block':'none';
    const cyberOn=d.snifferOn||d.kismetOn||d.pmkidOn||d.deauthOn;
    $('cyberPill').style.display=cyberOn?'block':'none';
    if(d.flash!==undefined){
      set('fl',(d.flash/1024/1024).toFixed(0)+' MB');
      set('ps',d.psram?(d.psram/1024/1024).toFixed(0)+' MB':'N/A');
      set('cid',d.chipId);}
    if(d.inputs){['in0','in1'].forEach((id,i)=>{
      const e=$(id);if(!e)return;
      e.textContent=d.inputs[i]?'HIGH':'LOW';
      e.className='badge '+(d.inputs[i]?'bm2':'bx2');});}
    if(d.pwm){for(let i=0;i<3;i++)set('d'+i,d.pwm[i]);}
    if(d.touch){for(let i=0;i<2;i++){
      set('tv'+i,d.touch[i]);
      $('tc'+i).className='torb'+(d.touchActive[i]?' on':'');}}
  }).catch(()=>{});}
poll();setInterval(poll,1000);

// ── WiFi ──
let lastNets=[];
function wScan(){$('wSB').disabled=true;set('wSS','SCANNING...');fetch('/wifi/scan').then(()=>setTimeout(wRes,5500));}
function wRes(){fetch('/wifi/results').then(r=>r.json()).then(d=>{
  if(d.status==='scanning'){setTimeout(wRes,1500);return;}
  $('wSB').disabled=false;set('wSS',d.networks.length+' FOUND');lastNets=d.networks;
  const nl=$('netList');
  if(!d.networks.length){nl.innerHTML='<div style="color:var(--dim);text-align:center;padding:12px">None found</div>';return;}
  nl.innerHTML=d.networks.map(n=>'<div class="net-item" onclick="selNetwork(\''+escJ(n.ssid)+'\','+n.enc+','+n.rssi+')">'
    +'<div><div class="net-n">'+(xss(n.ssid)||'<em style="color:var(--dim)">Hidden</em>')+'</div>'
    +'<div style="font-size:.48rem;color:var(--dim);margin-top:1px">CH'+n.channel+' '+n.rssi+'dBm '+(n.enc?'WPA':'OPEN')+'</div></div>'
    +'<div class="net-m">'+sigBars(n.rssi)+'<span style="font-size:.48rem;color:var(--dim)">'+n.rssi+'</span></div></div>').join('');});}
function selNetwork(ssid,enc,rssi){
  selNet=ssid;selEnc=enc;
  document.querySelectorAll('.net-item').forEach(e=>e.classList.remove('sel'));
  if(event&&event.currentTarget)event.currentTarget.classList.add('sel');
  set('sbNet',ssid);set('sbSig',rssi+' dBm');openM(ssid);$('mPw').value='';}
function openM(s){$('mSSID').value=s;$('mPw').value='';$('mSt').textContent='';$('cModal').classList.add('show');setTimeout(()=>$('mPw').focus(),100);}
function closeM(){$('cModal').classList.remove('show');}
function doConn(){
  const st=$('mSt');st.textContent='Connecting...';st.style.color='var(--amber)';
  fetch('/wifi/connect',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'ssid='+encodeURIComponent($('mSSID').value)+'&pass='+encodeURIComponent($('mPw').value)})
  .then(r=>r.json()).then(d=>{
    if(d.status==='connecting'){st.textContent='Sent!';st.style.color='var(--mint)';
      set('sbNet',$('mSSID').value);$('sbSt').className='stv o';$('sbSt').textContent='CONNECTING...';
      setTimeout(closeM,6000);}
    else{st.textContent='Error: '+d.msg;st.style.color='var(--red)';}});}
function wDisc(){if(!confirm('Disconnect?'))return;fetch('/wifi/disconnect').then(()=>{addLog('Disconnected','w');set('sbSt','IDLE');set('sbIP','--');});}

// ── OLED Display ──
const OLED_PAGES=['HOME','WIFI','SNIFFER','KISMET','PMKID','GPIO'];
function buildOledPages(){
  $('oledPages').innerHTML=OLED_PAGES.map((n,i)=>
    '<button class="gpio-btn'+(i===0?' on':'')+'" onclick="oledGoto('+i+')"><span class="gn">'+n+'</span></button>').join('');}
function highlightOledPage(id){document.querySelectorAll('#oledPages .gpio-btn').forEach((b,i)=>b.classList.toggle('on',i===id));}
function oledNav(dir){
  fetch('/display/'+dir).then(r=>r.json()).then(d=>{set('oledPg',d.name);highlightOledPage(d.page);});}
function oledGoto(id){
  fetch('/display/page?id='+id).then(r=>r.json()).then(d=>{set('oledPg',d.name);highlightOledPage(d.page);});}
buildOledPages();
fetch('/display/status').then(r=>r.json()).then(d=>{set('oledPg',d.name);highlightOledPage(d.page);}).catch(()=>{});

// ── LED ──
function setLED(r,g,b){fetch('/led?r='+r+'&g='+g+'&b='+b).then(()=>addLog('LED rgb('+r+','+g+','+b+')','g'));}

// ── GPIO ──
const OUT_PINS=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,17,18,21,38,39,40,41,42,45,46];
const ADC_PINS=[1,2,3,4,5,6,7,8,9,10];
const gpioState={};
function buildGPIOGrid(){
  const g=document.getElementById('gpioGrid');g.innerHTML='';
  OUT_PINS.forEach(p=>{gpioState[p]=false;const isADC=ADC_PINS.includes(p);
    const d=document.createElement('div');
    d.className='gpio-btn off'+(isADC?' adc':'');d.id='gp'+p;
    d.innerHTML='<span class="gn">GPIO '+p+'</span><span class="gs">LOW</span>';
    d.onclick=()=>toggleGPIO(p);g.appendChild(d);});}
function toggleGPIO(pin){
  fetch('/gpio/pin?pin='+pin+'&state='+(gpioState[pin]?0:1))
    .then(r=>r.json()).then(d=>{gpioState[pin]=d.state;
      const el=document.getElementById('gp'+pin);
      el.className='gpio-btn '+(d.state?'on':'off')+(ADC_PINS.includes(pin)?' adc':'');
      el.querySelector('.gs').textContent=d.state?'HIGH':'LOW';
      addLog('GPIO '+pin+' -> '+(d.state?'HIGH':'LOW'));});}
buildGPIOGrid();
function setPWM(ch,v){set('d'+ch,v);fetch('/gpio/pwm?ch='+ch+'&duty='+v);}
function togPWM(ch){fetch('/gpio/pwmmode?ch='+ch).then(r=>r.json()).then(d=>{
  const b=$('pm'+ch);b.textContent=d.pwm?'DISABLE':'ENABLE';
  b.className=d.pwm?'btn br':'btn bv';addLog('GPIO '+(ch+4)+' -> '+(d.pwm?'PWM':'DIGITAL'));});}

// ── BLE ──
function bScan(){$('bSB').disabled=true;set('bSS','SCANNING...');fetch('/ble/scan').then(()=>setTimeout(bRes,7000));}
function bRes(){fetch('/ble/results').then(r=>r.json()).then(d=>{
  if(d.status==='scanning'){setTimeout(bRes,1000);return;}
  $('bSB').disabled=false;set('bSS',d.devices.length+' FOUND');
  const tb=$('bT');
  if(!d.devices.length){tb.innerHTML='<tr><td colspan="5" style="color:var(--dim);text-align:center;padding:12px">No devices</td></tr>';return;}
  tb.innerHTML=d.devices.map(v=>'<tr><td>'+xss(v.n)+'</td><td style="font-size:.52rem;color:var(--dim)">'+v.a+'</td>'
    +'<td>'+(v.m?'<span class="badge bv2">'+xss(v.m)+'</span>':'<span style="color:var(--dim)">--</span>')+'</td>'
    +'<td>'+v.r+' dBm</td><td><span class="sig sv" style="width:'+Math.max(3,Math.round(Math.min(100,Math.max(0,(v.r+100)*2))*.42))+'px;opacity:.6"></span></td></tr>').join('');});}

// ── Sniffer ──
let snifOn=false,pktMgmt=0,pktData=0,pktCtrl=0,snifPoll=null;
function togSniffer(){
  snifOn=!snifOn;const ch=parseInt($('chanSel').value)||0;
  fetch('/sniffer?active='+snifOn+'&ch='+ch).then(r=>r.json()).then(d=>{
    $('snifBtn').textContent=snifOn?'STOP':'START';
    $('snifBtn').className=snifOn?'btn br':'btn bm';
    set('snifSt',snifOn?'CAPTURING':'STOPPED');
    if(snifOn){snifPoll=setInterval(fetchPkts,800);}else{clearInterval(snifPoll);}});}
function clearPkts(){pktMgmt=0;pktData=0;pktCtrl=0;set('pktTotal',0);set('pktMgmt',0);set('pktData',0);set('pktCtrl',0);
  $('pktLog').innerHTML='<span style="color:var(--dim)">Cleared</span>';fetch('/sniffer/clear');}
function setHop(v){fetch('/sniffer/hop?v='+v);}
function fetchPkts(){
  fetch('/sniffer/log').then(r=>r.json()).then(d=>{
    if(!d.pkts||!d.pkts.length)return;
    const log=$('pktLog'),ph=log.querySelector('span');if(ph)ph.remove();
    d.pkts.forEach(p=>{const e=document.createElement('div');
      let cls='pk-m';if(p.t===2)cls='pk-d';else if(p.t===1)cls='pk-c';else if(p.t===3)cls='pk-x';
      if(p.t===0)pktMgmt++;else if(p.t===2)pktData++;else if(p.t===1)pktCtrl++;
      e.className=cls;
      e.textContent='['+String(p.ts).padStart(8)+'ms] '+p.info.padEnd(22)+' '+p.src+' -> '+p.dst+' CH'+p.ch+' '+p.rssi+'dBm';
      log.appendChild(e);});
    log.scrollTop=log.scrollHeight;
    set('pktTotal',d.total);set('pktMgmt',pktMgmt);set('pktData',pktData);set('pktCtrl',pktCtrl);});}

// ── Kismet ──
let kisOn=false,kisPoll=null;
function togKismet(){
  kisOn=!kisOn;fetch('/kismet?active='+kisOn).then(r=>r.json()).then(d=>{
    $('kisBtn').textContent=kisOn?'STOP':'START';
    $('kisBtn').className=kisOn?'btn br':'btn bm';
    set('kisSt',kisOn?'MAPPING':'STOPPED');
    if(kisOn){kisPoll=setInterval(fetchKismet,2000);}else{clearInterval(kisPoll);}});}
function clearKismet(){fetch('/kismet/clear');
  $('kApT').innerHTML='<tr><td colspan="6" style="color:var(--dim);text-align:center;padding:10px">Cleared</td></tr>';
  $('kProbeT').innerHTML='<tr><td colspan="3" style="color:var(--dim);text-align:center;padding:10px">Cleared</td></tr>';}
function fetchKismet(){
  fetch('/kismet/data').then(r=>r.json()).then(d=>{
    const tb=$('kApT');
    if(!d.aps||!d.aps.length){tb.innerHTML='<tr><td colspan="6" style="color:var(--dim);text-align:center;padding:10px">No APs</td></tr>';return;}
    tb.innerHTML=d.aps.map(a=>'<tr><td style="font-size:.52rem;color:var(--accent)">'+a.b+'</td>'
      +'<td>'+(a.s||'<em style="color:var(--dim)">hidden</em>')+'</td><td>'+a.c+'</td><td>'+a.r+' dBm</td>'
      +'<td><span class="sig sv" style="width:'+Math.max(3,Math.round(Math.min(100,Math.max(0,(a.r+100)*2))*.42))+'px;opacity:.6"></span></td>'
      +'<td style="font-size:.48rem;color:var(--dim)">'+a.t+'ms</td></tr>').join('');
    const pt=$('kProbeT');
    if(!d.probes||!d.probes.length){pt.innerHTML='<tr><td colspan="3" style="color:var(--dim);text-align:center;padding:10px">No probes</td></tr>';return;}
    pt.innerHTML=d.probes.map(p=>'<tr><td style="font-size:.52rem;color:var(--accent)">'+p.m+'</td>'
      +'<td style="color:var(--mint)">'+xss(p.s)+'</td>'
      +'<td style="font-size:.48rem;color:var(--dim)">'+p.t+'ms</td></tr>').join('');});}

// ── PMKID ──
let pmkOn=false,pmkPoll=null;
function togPMKID(){
  pmkOn=!pmkOn;fetch('/pmkid?active='+pmkOn).then(r=>r.json()).then(d=>{
    $('pmkBtn').textContent=pmkOn?'STOP':'START';
    $('pmkBtn').className=pmkOn?'btn br':'btn bm';
    set('pmkSt',pmkOn?'LISTENING':'STOPPED');
    if(pmkOn){pmkPoll=setInterval(fetchPMKID,3000);}else{clearInterval(pmkPoll);}});}
function fetchPMKID(){
  fetch('/pmkid/data').then(r=>r.json()).then(d=>{
    const tb=$('pmkT');
    if(!d.entries||!d.entries.length){tb.innerHTML='<tr><td colspan="4" style="color:var(--dim);text-align:center;padding:12px">No PMKID</td></tr>';return;}
    tb.innerHTML=d.entries.map(e=>'<tr><td style="font-size:.52rem;color:var(--accent)">'+e.b+'</td>'
      +'<td style="font-size:.52rem;color:var(--dim)">'+e.c+'</td>'
      +'<td style="font-size:.48rem;color:var(--mint);word-break:break-all">'+e.p+'</td>'
      +'<td style="font-size:.48rem;color:var(--dim)">'+e.t+'ms</td></tr>').join('');});}

// ── Deauth ──
let dRun=false;
function togDeauth(){dRun=!dRun;fetch('/rf/deauth?active='+dRun);
  $('dBtn').textContent=dRun?'STOP':'START';
  $('dBtn').className=dRun?'btn br':'btn bo';}

// ── Channel Map ──
function scanCh(){set('chSt','SCANNING...');fetch('/wifi/scan').then(()=>setTimeout(drawCh,5500));}
function drawCh(){fetch('/wifi/results').then(r=>r.json()).then(d=>{
  if(d.status==='scanning'){setTimeout(drawCh,1500);return;}
  set('chSt',d.networks.length+' NETS');
  const cnt=new Array(14).fill(0);d.networks.forEach(n=>{if(n.channel>=1&&n.channel<=13)cnt[n.channel]++;});
  const mx=Math.max(1,...cnt.slice(1));let best=1;for(let i=2;i<=13;i++)if(cnt[i]<cnt[best])best=i;
  set('bestCh','CH '+best);$('bestCh').className='badge bm2';
  const cv=$('chCv'),ctx=cv.getContext('2d');cv.width=cv.offsetWidth||380;cv.height=80;ctx.clearRect(0,0,cv.width,cv.height);
  const bw=Math.floor((cv.width-14)/13);
  for(let c=1;c<=13;c++){const x=7+(c-1)*bw,h=cnt[c]?Math.max(3,Math.round(cnt[c]/mx*50)):1,y=cv.height-h-12;
    ctx.fillStyle=(c===best)?'rgba(21,245,186,.7)':'rgba(131,111,255,.5)';
    ctx.fillRect(x,y,bw-2,h);
    ctx.fillStyle='rgba(255,255,255,.1)';ctx.font='7px monospace';ctx.textAlign='center';
    ctx.fillText(c,x+bw/2-1,cv.height-2);
    if(cnt[c]){ctx.fillStyle='rgba(131,111,255,.7)';ctx.fillText(cnt[c],x+bw/2-1,y-2);}}});}

// ── Evil Twin ──
function detectEvilTwin(){
  if(!lastNets.length){$('etResults').textContent='Scan first.';return;}
  const ssidMap={};lastNets.forEach(n=>{if(!ssidMap[n.ssid])ssidMap[n.ssid]=[];ssidMap[n.ssid].push(n);});
  const twins=Object.entries(ssidMap).filter(([s,ns])=>ns.length>1&&s);
  if(!twins.length){$('etResults').innerHTML='<span style="color:var(--mint)">No evil twin detected</span>';return;}
  $('etResults').innerHTML=twins.map(([s,ns])=>'<div style="margin-bottom:6px;padding:6px;background:rgba(255,107,107,.04);border:1px solid rgba(255,107,107,.15);border-radius:6px">'
    +'<div style="color:var(--red);font-size:.6rem;margin-bottom:3px">DUPLICATE: "'+xss(s)+'"</div>'
    +ns.map(n=>'<div style="font-size:.52rem;color:var(--dim);padding:1px 0">CH'+n.channel+' '+n.rssi+'dBm</div>').join('')+'</div>').join('');}

// ── Recon ──
function doRecon(){$('rBtn').disabled=true;set('rSt','SCANNING...');
  fetch('/recon').then(r=>r.json()).then(d=>{
    $('rBtn').disabled=false;set('rSt',d.clients.length+' CLIENT(S)');
    const tb=$('rT');
    if(!d.clients.length){tb.innerHTML='<tr><td colspan="5" style="color:var(--dim);text-align:center;padding:12px">No clients</td></tr>';return;}
    tb.innerHTML=d.clients.map(c=>{
      const pts=c.ports.length?c.ports.map(p=>'<span class="badge bv2" style="margin:1px;font-size:.44rem">'+p.p+':'+p.s+'</span>').join(''):'<span style="color:var(--dim);font-size:.48rem">none</span>';
      return '<tr><td>'+c.vendor+'</td><td style="color:var(--mint)">'+c.ip+'</td>'
        +'<td style="font-size:.48rem;color:var(--dim)">'+c.mac+'</td><td>'+pts+'</td>'
        +'<td style="font-size:.5rem;color:var(--dim)">'+c.age+'</td></tr>';}).join('');
  }).catch(()=>{$('rBtn').disabled=false;set('rSt','Error');});}

// ── System ──
function setCPU(){fetch('/system/cpu?freq='+$('cpuF').value).then(r=>r.json()).then(d=>addLog('CPU -> '+d.freq+' MHz','g'));}
function saveAP(){
  const ss=$('nSsid').value.trim(),pw=$('nPass').value,pc=$('nPassC').value,st=$('apSt');
  if(!ss){st.textContent='SSID empty';st.style.color='var(--red)';return;}
  if(pw.length<8){st.textContent='Password 8+ chars';st.style.color='var(--red)';return;}
  if(pw!==pc){st.textContent='Passwords mismatch';st.style.color='var(--red)';return;}
  st.textContent='Saving...';st.style.color='var(--amber)';
  fetch('/ap/config',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'ssid='+encodeURIComponent(ss)+'&pass='+encodeURIComponent(pw)})
  .then(r=>r.json()).then(d=>{
    if(d.status==='saved'){st.textContent='Saved! Rebooting...';st.style.color='var(--mint)';}
    else{st.textContent='Error: '+(d.msg||'?');st.style.color='var(--red)';}});}
function doSleep(){const s=parseInt($('slpS').value)||30;if(!confirm('Deep sleep '+s+'s?'))return;
  $('slpCd').style.display='block';let c=3;
  const iv=setInterval(()=>{$('slpCd').textContent=c--;if(c<0){clearInterval(iv);fetch('/system/sleep?sec='+s);}},1000);}
function doReboot(){if(confirm('Reboot?'))fetch('/system/reboot').then(()=>addLog('Rebooting...','w'));}
function saveTouchAct(){fetch('/touch/actions?t1='+$('ta0').value+'&t2='+$('ta1').value).then(()=>addLog('Touch saved','g'));}

// ── Chat (WebSocket) ──
let ws=null,myN='';
function initWS(){
  ws=new WebSocket('ws://'+location.hostname+':81');
  ws.onopen=()=>{set('wsp','ONLINE');$('wsp').className='pill p-on';addSys('Connected');};
  ws.onclose=()=>{set('wsp','OFFLINE');$('wsp').className='pill p-off';ws=null;setTimeout(initWS,3000);};
  ws.onmessage=e=>{try{const d=JSON.parse(e.data);
    if(d.t==='chat')apMsg(d.n,d.m,d.ts,d.n===myN);
    else if(d.t==='sys'){addSys(d.msg);set('onl',d.n+' ONLINE');}}catch(e){}};}
function sChat(){const n=$('nIn').value.trim()||'ANON',t=$('mIn').value.trim();myN=n;
  if(!t||!ws||ws.readyState!==1)return;ws.send(JSON.stringify({t:'chat',n,m:t}));$('mIn').value='';}
function apMsg(nm,tx,ts,mine){const b=$('cMsgs'),d=document.createElement('div');
  d.style.cssText='margin-bottom:6px'+(mine?';text-align:right':'');
  const meta=document.createElement('div');
  meta.style.cssText='font-size:.48rem;color:var(--dim);margin-bottom:1px'+(mine?';text-align:right':'');
  meta.innerHTML='<span style="color:var(--mint)">'+xss(nm)+'</span><span style="color:var(--dim);margin-left:5px">'+ts+'</span>';
  const bub=document.createElement('div');
  bub.style.cssText='display:inline-block;max-width:75%;padding:5px 8px;font-size:.6rem;color:var(--tx);border-radius:'+(mine?'7px 0 7px 7px':'0 7px 7px 7px')+';border:1px solid;background:'+(mine?'rgba(21,245,186,.04)':'rgba(131,111,255,.04)')+';border-color:'+(mine?'rgba(21,245,186,.15)':'rgba(131,111,255,.15)');
  bub.textContent=tx;d.appendChild(meta);d.appendChild(bub);b.appendChild(d);b.scrollTop=b.scrollHeight;}
function addSys(t){const b=$('cMsgs'),d=document.createElement('div');
  d.style.cssText='text-align:center;font-size:.48rem;color:var(--dim);letter-spacing:2px;margin:4px 0';
  d.textContent='-- '+t+' --';b.appendChild(d);b.scrollTop=b.scrollHeight;}

// ── Data Panel ──
let dpAutoRef=true,dpTimer=null,currentEndpoint='/data';
function fetchApiData(ep){
  currentEndpoint=ep||currentEndpoint;
  set('apiEndpointTitle',currentEndpoint);
  fetch(currentEndpoint).then(r=>{
    $('apiStatusBadge').textContent=r.status;
    $('apiStatusBadge').className=r.ok?'badge bm2':'badge br2';
    return r.json();}).then(d=>{
    $('jsonViewer').textContent=JSON.stringify(d,null,2);
    if(currentEndpoint==='/data')updateDataPanelCards(d);
  }).catch(e=>{
    $('apiStatusBadge').textContent='ERR';
    $('apiStatusBadge').className='badge br2';
    $('jsonViewer').textContent='Fetch error: '+e;});}
function updateDataPanelCards(d){
  if(d.system){const s=Math.floor(d.system.uptime/1000);
    set('dpUpt',Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m '+(s%60)+'s');
    set('dpHeap',(d.system.heapFree/1024).toFixed(1)+' KB');
    set('dpCpu',d.system.cpuFreqMHz+' MHz');set('dpChip',d.system.chipId);}
  if(d.wifi){set('dpApSsid',d.wifi.apSSID);set('dpApClients',d.wifi.apClientsCount);
    set('dpStaSt',d.wifi.staStatus);set('dpStaIp',d.wifi.staIP||'--');}
  if(d.bluetooth){set('dpBleSt',d.bluetooth.scanning?'SCANNING':'IDLE');
    set('dpBleDevs',d.bluetooth.deviceList?d.bluetooth.deviceList.length:0);}}
function autoRefreshToggle(){
  dpAutoRef=!dpAutoRef;
  $('autoRefBtn').textContent='AUTO: '+(dpAutoRef?'ON':'OFF');
  $('autoRefBtn').className=dpAutoRef?'pill p-v':'pill p-off';
  if(dpAutoRef){fetchApiData();if(!dpTimer)dpTimer=setInterval(()=>{if(dpAutoRef)fetchApiData();},3000);}
  else{if(dpTimer){clearInterval(dpTimer);dpTimer=null;}}}
// Initial data panel load (deferred to avoid conflict with poll)
setTimeout(()=>{fetchApiData('/data');dpTimer=setInterval(()=>{if(dpAutoRef)fetchApiData('/data');},3000);},2000);
</script>
</body>
</html>
)RAWHTML";

// ══════════════════════════════════════════════════════════════════════════════
//  ROUTE HANDLERS
// ══════════════════════════════════════════════════════════════════════════════
void handleRoot() { http.send_P(200, "text/html", HTML); }

// ── STATUS — lightweight (default) + full (every 5 polls) ────────────────────
void handleStatus() {
  bool full = http.hasArg("full") && http.arg("full") == "1";
  String j = "{";
  j += "\"uptime\":" + String(millis()) + ",";
  j += "\"heap\":" + String(ESP.getFreeHeap()) + ",";
  j += "\"temp\":" + String(temperatureRead(), 2) + ",";
  j += "\"cpu\":" + String(getCpuFrequencyMhz()) + ",";
  j += "\"clients\":" + String(WiFi.softAPgetStationNum()) + ",";
  j += "\"deauth\":" + String(deauthCnt) + ",";
  j += "\"deauthMac\":\"" + deauthLast + "\",";
  j += "\"deauthChan\":\"" + String(deauthChan) + "\",";
  j += "\"beaconCnt\":" + String(beaconCnt) + ",";
  j += "\"beaconSSID\":\"" + String(beaconSSID) + "\",";
  j += "\"snifferOn\":" + jb(snifferActive) + ",";
  j += "\"kismetOn\":" + jb(kismetMode) + ",";
  j += "\"pmkidOn\":" + jb(pmkidMode) + ",";
  j += "\"deauthOn\":" + jb(deauthMode) + ",";
  if (WiFi.status() == WL_CONNECTED) {
    j += "\"sta\":\"connected\",\"staSSID\":\"" + esc(WiFi.SSID()) + "\",";
    j += "\"staIp\":\"" + WiFi.localIP().toString() + "\",";
    j += "\"staRSSI\":" + String(WiFi.RSSI());
  } else {
    j += "\"sta\":\"" + staConnStatus + "\"";
  }
  if (full) {
    j += ",\"flash\":" + String(ESP.getFlashChipSize());
    j += ",\"psram\":" + String(ESP.getPsramSize());
    j += ",\"chipId\":\"" + String((uint32_t)(ESP.getEfuseMac() >> 32), HEX) +
         "\"";
    j += ",\"inputs\":[" + jb(digitalRead(7)) + "," + jb(digitalRead(8)) + "]";
    j += ",\"pwm\":[" + String(pwmDuty[0]) + "," + String(pwmDuty[1]) + "," +
         String(pwmDuty[2]) + "]";
    j += ",\"touch\":[" + String(touchVal[0]) + "," + String(touchVal[1]) + "]";
    j += ",\"touchActive\":[" + jb(touchActive[0]) + "," + jb(touchActive[1]) +
         "]";
  }
  j += "}";
  http.send(200, "application/json", j);
}

// ── GPIO — all pins
void handleGPIOPin() {
  if (!http.hasArg("pin") || !http.hasArg("state")) {
    http.send(400, "application/json", "{\"e\":\"missing\"}");
    return;
  }
  int pin = http.arg("pin").toInt();
  int state = http.arg("state").toInt();
  if (pin == 0 || pin == 26 || pin == 27 || pin == 32 || pin == 33 ||
      pin == 34 || pin == 35 || pin == 36 || pin == 37) {
    http.send(400, "application/json", "{\"e\":\"reserved pin\"}");
    return;
  }
  int idx = pinIndex(pin);
  if (idx < 0) {
    http.send(404, "application/json", "{\"e\":\"pin not in list\"}");
    return;
  }

  int ch = -1;
  if (pin == GPIO_OUT_1) ch = 0;
  else if (pin == GPIO_OUT_2) ch = 1;
  else if (pin == GPIO_OUT_3) ch = 2;
  if (ch >= 0 && pwmMode[ch]) {
    http.send(409, "application/json", "{\"e\":\"pin in PWM mode\"}");
    return;
  }
  pinMode(pin, OUTPUT);
  gpioStates[idx] = (state == 1);
  digitalWrite(pin, state ? HIGH : LOW);
  http.send(200, "application/json",
            "{\"pin\":" + String(pin) + ",\"state\":" + jb(gpioStates[idx]) +
                "}");
}

void handlePWMSet() {
  int ch = http.arg("ch").toInt();
  int duty = constrain(http.arg("duty").toInt(), 0, 255);
  if (ch < 0 || ch > 2) {
    http.send(400, "application/json", "{\"e\":\"invalid\"}");
    return;
  }
  int g[3] = {GPIO_OUT_1, GPIO_OUT_2, GPIO_OUT_3};
  pwmDuty[ch] = duty;
  if (pwmMode[ch]) ledcWrite(g[ch], duty);
  http.send(200, "application/json",
            "{\"ch\":" + String(ch) + ",\"duty\":" + String(duty) + "}");
}
void handlePWMMode() {
  int ch = http.arg("ch").toInt();
  if (ch < 0 || ch > 2) {
    http.send(400, "application/json", "{\"e\":\"invalid\"}");
    return;
  }
  int g[3] = {GPIO_OUT_1, GPIO_OUT_2, GPIO_OUT_3};
  pwmMode[ch] = !pwmMode[ch];
  if (pwmMode[ch]) {
    ledcAttach(g[ch], PWM_FREQ, PWM_RES);
    ledcWrite(g[ch], pwmDuty[ch]);
  } else {
    ledcDetach(g[ch]);
    pinMode(g[ch], OUTPUT);
    digitalWrite(g[ch], LOW);
  }
  http.send(200, "application/json",
            "{\"ch\":" + String(ch) + ",\"pwm\":" + jb(pwmMode[ch]) + "}");
}

// ── LED
void handleLED() {
  uint8_t r = http.hasArg("r") ? constrain(http.arg("r").toInt(), 0, 255) : 0;
  uint8_t g = http.hasArg("g") ? constrain(http.arg("g").toInt(), 0, 255) : 0;
  uint8_t b = http.hasArg("b") ? constrain(http.arg("b").toInt(), 0, 255) : 0;
  setNeo(r, g, b);
  http.send(200, "application/json",
            "{\"r\":" + String(r) + ",\"g\":" + String(g) +
                ",\"b\":" + String(b) + "}");
}

// ── WIFI
void handleWifiScan() {
  WiFi.scanNetworks(true);
  http.send(200, "application/json", "{\"status\":\"scanning\"}");
}
void handleWifiResults() {
  int n = WiFi.scanComplete();
  if (n == WIFI_SCAN_RUNNING) {
    http.send(200, "application/json",
              "{\"status\":\"scanning\",\"networks\":[]}");
    return;
  }
  String j = "{\"status\":\"done\",\"networks\":[";
  for (int i = 0; i < n; i++) {
    if (i > 0) j += ",";
    j += "{\"ssid\":\"" + esc(WiFi.SSID(i)) +
         "\",\"rssi\":" + String(WiFi.RSSI(i)) +
         ",\"channel\":" + String(WiFi.channel(i)) +
         ",\"enc\":" + jb(WiFi.encryptionType(i) != WIFI_AUTH_OPEN) + "}";
  }
  j += "]}";
  WiFi.scanDelete();
  http.send(200, "application/json", j);
}
void handleWifiConnect() {
  if (!http.hasArg("ssid")) {
    http.send(400, "application/json",
              "{\"status\":\"error\",\"msg\":\"missing ssid\"}");
    return;
  }
  String ss = http.arg("ssid"),
         pw = http.hasArg("pass") ? http.arg("pass") : "";
  http.send(200, "application/json", "{\"status\":\"connecting\"}");
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAPConfig(AP_IP, AP_GW, AP_SN);
  WiFi.softAP(apSSID.c_str(), apPass.c_str());
  WiFi.disconnect(false);
  if (pw.length() > 0 && pw != "(open)")
    WiFi.begin(ss.c_str(), pw.c_str());
  else
    WiFi.begin(ss.c_str());
  staConnStatus = "connecting";
  staSSID = ss;
  staTimeout = millis() + 18000;
}
void handleWifiDisconnect() {
  http.send(200, "application/json", "{\"status\":\"disconnected\"}");
  WiFi.disconnect(false);
  staConnStatus = "disconnected";
  staSSID = "";
  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(AP_IP, AP_GW, AP_SN);
  WiFi.softAP(apSSID.c_str(), apPass.c_str());
}

// ── BLE
void handleBleScan() {
  if (bleScanning) {
    http.send(200, "application/json", "{\"status\":\"scanning\"}");
    return;
  }
  if (chanHopping && (snifferActive || kismetMode || deauthMode || pmkidMode)) {
    http.send(409, "application/json",
              "{\"status\":\"error\",\"msg\":\"disable cyber mode first\"}");
    return;
  }
  bleScanning = true;
  if (bleCb) delete bleCb;
  bleCb = new AxiomBLECb();
  pBLEScan->setAdvertisedDeviceCallbacks(bleCb);
  pBLEScan->setActiveScan(true);
  pBLEScan->start(
      6,
      [](BLEScanResults r) {
        bleCb->json += "]";
        bleResults = bleCb->json;
        bleScanning = false;
      },
      false);
  http.send(200, "application/json", "{\"status\":\"scanning\"}");
}
void handleBleResults() {
  if (bleScanning) {
    http.send(200, "application/json",
              "{\"status\":\"scanning\",\"devices\":[]}");
    return;
  }
  http.send(200, "application/json",
            "{\"status\":\"done\",\"devices\":" + bleResults + "}");
}

// ── SNIFFER
void handleSniffer() {
  bool active = http.hasArg("active") && http.arg("active") == "true";
  int ch = http.hasArg("ch") ? http.arg("ch").toInt() : 0;
  snifferActive = active;
  if (active) {
    if (ch > 0 && ch <= 13) {
      esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
      chanHopping = false;
    } else
      chanHopping = true;
    startPromiscuous();
  } else
    stopPromiscuous();
  http.send(200, "application/json", "{\"active\":" + jb(snifferActive) + "}");
}
void handleSnifferLog() {
  String j = "{\"pkts\":[";
  int start = max(0, pktHead - 20);
  bool first = true;
  for (int i = start; i < pktHead && i < start + 20; i++) {
    int idx = i % MAX_PKT_LOG;
    if (!first) j += ",";
    first = false;
    j += "{\"src\":\"" + String(pktLog[idx].srcMAC) + "\",\"dst\":\"" +
         String(pktLog[idx].dstMAC) + "\"";
    j += ",\"t\":" + String(pktLog[idx].type) +
         ",\"st\":" + String(pktLog[idx].subtype);
    j += ",\"info\":\"" + String(pktLog[idx].info) +
         "\",\"rssi\":" + String(pktLog[idx].rssi);
    j += ",\"ch\":" + String(pktLog[idx].channel) +
         ",\"ts\":" + String(pktLog[idx].ts) + "}";
  }
  j += "],\"total\":" + String(pktTotal) + "}";
  http.send(200, "application/json", j);
}
void handleSnifferClear() {
  pktHead = 0;
  pktTotal = 0;
  http.send(200, "application/json", "{\"ok\":true}");
}
void handleSnifferHop() {
  bool v = http.hasArg("v") && http.arg("v") == "true";
  chanHopping = v;
  http.send(200, "application/json", "{\"ok\":true}");
}

// ── KISMET
void handleKismet() {
  bool active = http.hasArg("active") && http.arg("active") == "true";
  kismetMode = active;
  probeCount = 0;
  if (active) {
    chanHopping = true;
    startPromiscuous();
  } else
    stopPromiscuous();
  http.send(200, "application/json", "{\"active\":" + jb(kismetMode) + "}");
}
void handleKismetData() {
  String j = "{\"aps\":[";
  bool first = true;
  for (int i = 0; i < MAX_AP; i++) {
    if (!kisAPs[i].valid) continue;
    if (!first) j += ",";
    first = false;
    j += "{\"b\":\"" + String(kisAPs[i].bssid) + "\",\"s\":\"" +
         esc(String(kisAPs[i].ssid)) + "\"";
    j += ",\"c\":" + String(kisAPs[i].ch) + ",\"r\":" + String(kisAPs[i].rssi);
    j += ",\"t\":" + String(millis() - kisAPs[i].ts) + "}";
  }
  j += "],\"probes\":[";
  first = true;
  for (int i = 0; i < probeCount; i++) {
    if (!first) j += ",";
    first = false;
    j += "{\"m\":\"" + String(probeLog[i].mac) + "\",\"s\":\"" +
         esc(String(probeLog[i].ssid)) + "\"";
    j += ",\"t\":" + String(millis() - probeLog[i].ts) + "}";
  }
  j += "]}";
  http.send(200, "application/json", j);
}
void handleKismetClear() {
  for (int i = 0; i < MAX_AP; i++) kisAPs[i].valid = false;
  probeCount = 0;
  http.send(200, "application/json", "{\"ok\":true}");
}

// ── PMKID
void handlePMKID() {
  bool active = http.hasArg("active") && http.arg("active") == "true";
  pmkidMode = active;
  if (active) startPromiscuous();
  else stopPromiscuous();
  http.send(200, "application/json", "{\"active\":" + jb(pmkidMode) + "}");
}
void handlePMKIDData() {
  String j = "{\"entries\":[";
  for (int i = 0; i < pmkidCount; i++) {
    if (i > 0) j += ",";
    j += "{\"b\":\"" + String(pmkidLog[i].bssid) + "\",\"c\":\"" +
         String(pmkidLog[i].client) + "\"";
    j += ",\"p\":\"" + String(pmkidLog[i].pmkid) +
         "\",\"t\":" + String(pmkidLog[i].ts) + "}";
  }
  j += "]}";
  http.send(200, "application/json", j);
}

// ── DEAUTH DETECTOR
void handleDeauth() {
  bool active = http.hasArg("active") && http.arg("active") == "true";
  deauthMode = active;
  if (active) {
    chanHopping = true;
    startPromiscuous();
  } else
    stopPromiscuous();
  http.send(200, "application/json", "{\"active\":" + jb(deauthMode) + "}");
}

// ── RECON
void handleRecon() {
  wifi_sta_list_t sl;
  esp_wifi_ap_get_sta_list(&sl);
  esp_netif_t *apif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
  String j = "{\"clients\":[";
  for (int i = 0; i < sl.num; i++) {
    if (i > 0) j += ",";
    const uint8_t *m = sl.sta[i].mac;
    char mac[18];
    snprintf(mac, 18, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3],
             m[4], m[5]);
    logClient(m);
    char ip[16] = "N/A";
    if (apif) {
      esp_netif_pair_mac_ip_t ci;
      memcpy(ci.mac, m, 6);
      if (esp_netif_dhcps_get_clients_by_mac(apif, 1, &ci) == ESP_OK)
        snprintf(ip, 16, IPSTR, IP2STR(&ci.ip));
    }
    uint32_t age = clientAge(m);
    char agB[12];
    snprintf(agB, 12, "%02lu:%02lu:%02lu", age / 3600, (age / 60) % 60,
             age % 60);
    String ports = (String(ip) != "N/A") ? scanPorts(String(ip)) : "[]";
    j += "{\"ip\":\"" + String(ip) + "\",\"mac\":\"" + String(mac) + "\"";
    j += ",\"vendor\":\"" + String(lookupOUI(m)) + "\"";
    j += ",\"rssi\":" + String(sl.sta[i].rssi) + ",\"age\":\"" + String(agB) +
         "\",\"ports\":" + ports + "}";
  }
  j += "]}";
  http.send(200, "application/json", j);
}

// ── TOUCH
void handleTouchActions() {
  if (http.hasArg("t1")) touchAction[0] = http.arg("t1");
  if (http.hasArg("t2")) touchAction[1] = http.arg("t2");
  http.send(200, "application/json", "{\"ok\":true}");
}
void fireTouchAction(int idx) {
  String &a = touchAction[idx];
  if (a == "gpio0") {
    int i = pinIndex(GPIO_OUT_1);
    gpioStates[i] = !gpioStates[i];
    digitalWrite(GPIO_OUT_1, gpioStates[i] ? HIGH : LOW);
  } else if (a == "gpio1") {
    int i = pinIndex(GPIO_OUT_2);
    gpioStates[i] = !gpioStates[i];
    digitalWrite(GPIO_OUT_2, gpioStates[i] ? HIGH : LOW);
  } else if (a == "gpio2") {
    int i = pinIndex(GPIO_OUT_3);
    gpioStates[i] = !gpioStates[i];
    digitalWrite(GPIO_OUT_3, gpioStates[i] ? HIGH : LOW);
  } else if (a == "sleep") {
    esp_sleep_enable_timer_wakeup(30ULL * 1000000ULL);
    esp_sleep_enable_touchpad_wakeup();
    esp_deep_sleep_start();
  }
}

// ── AP CONFIG
void handleAPConfig() {
  if (!http.hasArg("ssid") || !http.hasArg("pass")) {
    http.send(400, "application/json",
              "{\"status\":\"error\",\"msg\":\"missing\"}");
    return;
  }
  String ns = http.arg("ssid"), np = http.arg("pass");
  if (ns.length() == 0 || np.length() < 8) {
    http.send(400, "application/json",
              "{\"status\":\"error\",\"msg\":\"invalid\"}");
    return;
  }
  prefs.begin("axiom", false);
  prefs.putString("apSSID", ns);
  prefs.putString("apPass", np);
  prefs.end();
  http.send(200, "application/json", "{\"status\":\"saved\"}");
  delay(3000);
  ESP.restart();
}
void handleCPU() {
  int f = http.arg("freq").toInt();
  if (f != 240 && f != 160 && f != 80 && f != 40) {
    http.send(400, "application/json", "{\"e\":\"invalid\"}");
    return;
  }
  setCpuFrequencyMhz(f);
  http.send(200, "application/json",
            "{\"freq\":" + String(getCpuFrequencyMhz()) + "}");
}
void handleSleep() {
  int s = http.hasArg("sec") ? constrain(http.arg("sec").toInt(), 5, 3600) : 30;
  http.send(200, "application/json", "{\"sleep\":" + String(s) + "}");
  delay(200);
  esp_sleep_enable_timer_wakeup((uint64_t)s * 1000000ULL);
  esp_sleep_enable_touchpad_wakeup();
  esp_deep_sleep_start();
}
void handleReboot() {
  http.send(200, "application/json", "{\"status\":\"rebooting\"}");
  delay(500);
  ESP.restart();
}

// ── DEDICATED REST DATA ENDPOINTS ──────────────────────────────────────────
void handleDataEndpoint() {
  String j = "{";
  j += "\"system\":{";
  j += "\"uptime\":" + String(millis()) + ",";
  j += "\"heapFree\":" + String(ESP.getFreeHeap()) + ",";
  j += "\"flashSize\":" + String(ESP.getFlashChipSize()) + ",";
  j += "\"psramSize\":" + String(ESP.getPsramSize()) + ",";
  j += "\"cpuFreqMHz\":" + String(getCpuFrequencyMhz()) + ",";
  j += "\"tempC\":" + String(temperatureRead(), 2) + ",";
  j += "\"chipId\":\"" + String((uint32_t)(ESP.getEfuseMac() >> 32), HEX) +
       "\",";
  j += "\"apIP\":\"" + WiFi.softAPIP().toString() + "\",";
  j += "\"macAP\":\"" + WiFi.softAPmacAddress() + "\"";
  j += "},";
  j += "\"wifi\":{";
  j += "\"apSSID\":\"" + esc(apSSID) + "\",";
  j += "\"apClientsCount\":" + String(WiFi.softAPgetStationNum()) + ",";
  j += "\"staStatus\":\"" + staConnStatus + "\",";
  if (WiFi.status() == WL_CONNECTED) {
    j += "\"staSSID\":\"" + esc(WiFi.SSID()) + "\",";
    j += "\"staIP\":\"" + WiFi.localIP().toString() + "\",";
    j += "\"staRSSI\":" + String(WiFi.RSSI()) + ",";
  } else {
    j += "\"staSSID\":\"\",";
    j += "\"staIP\":\"\",";
    j += "\"staRSSI\":0,";
  }
  int scanN = WiFi.scanComplete();
  j += "\"scanStatus\":\"" +
       String(scanN >= 0 ? "done"
                         : (scanN == WIFI_SCAN_RUNNING ? "scanning" : "idle")) +
       "\",";
  j += "\"scanCount\":" + String(scanN > 0 ? scanN : 0);
  j += "},";
  j += "\"bluetooth\":{";
  j += "\"scanning\":" + jb(bleScanning) + ",";
  j += "\"deviceList\":" + (bleResults.length() > 0 ? bleResults : "[]");
  j += "},";
  j += "\"gpio\":{";
  j += "\"outputs\":[";
  for (int i = 0; i < OUT_COUNT; i++) {
    if (i > 0) j += ",";
    j += "{\"pin\":" + String(OUT_PINS[i]) + ",\"state\":" + jb(gpioStates[i]) +
         "}";
  }
  j += "],";
  j += "\"inputs\":[";
  for (int i = 0; i < IN_COUNT; i++) {
    if (i > 0) j += ",";
    j += "{\"pin\":" + String(IN_PINS[i]) +
         ",\"val\":" + String(digitalRead(IN_PINS[i])) + "}";
  }
  j += "],";
  j += "\"adc\":[";
  for (int i = 0; i < ADC_COUNT; i++) {
    if (i > 0) j += ",";
    j += "{\"pin\":" + String(ADC_PINS[i]) +
         ",\"raw\":" + String(analogRead(ADC_PINS[i])) + "}";
  }
  j += "],";
  j += "\"pwm\":[";
  for (int i = 0; i < 3; i++) {
    if (i > 0) j += ",";
    int g[3] = {GPIO_OUT_1, GPIO_OUT_2, GPIO_OUT_3};
    j += "{\"pin\":" + String(g[i]) + ",\"duty\":" + String(pwmDuty[i]) +
         ",\"enabled\":" + jb(pwmMode[i]) + "}";
  }
  j += "],";
  j += "\"touch\":[";
  for (int i = 0; i < 2; i++) {
    if (i > 0) j += ",";
    j += "{\"ch\":" + String(i + 1) + ",\"raw\":" + String(touchVal[i]) +
         ",\"active\":" + jb(touchActive[i]) + ",\"action\":\"" +
         touchAction[i] + "\"}";
  }
  j += "]},";
  j += "\"rfIntel\":{";
  j += "\"snifferActive\":" + jb(snifferActive) + ",";
  j += "\"kismetActive\":" + jb(kismetMode) + ",";
  j += "\"pmkidActive\":" + jb(pmkidMode) + ",";
  j += "\"deauthActive\":" + jb(deauthMode) + ",";
  j += "\"channel\":" + String(deauthChan) + ",";
  j += "\"deauthCount\":" + String(deauthCnt) + ",";
  j += "\"deauthLastMAC\":\"" + String((char *)_deauthMAC) + "\",";
  j += "\"beaconBurst\":" + String(beaconCnt) + ",";
  j += "\"beaconSSID\":\"" + esc(String(beaconSSID)) + "\",";
  j += "\"pmkidCount\":" + String(pmkidCount);
  j += "}";
  j += "}";
  http.send(200, "application/json", j);
}

void handleGPIOEndpoint() {
  String j = "{";
  j += "\"status\":\"ok\",";
  j += "\"outPins\":[";
  for (int i = 0; i < OUT_COUNT; i++) {
    if (i > 0) j += ",";
    j += "{\"pin\":" + String(OUT_PINS[i]) + ",\"state\":" + jb(gpioStates[i]) +
         "}";
  }
  j += "],\"inPins\":[";
  for (int i = 0; i < IN_COUNT; i++) {
    if (i > 0) j += ",";
    j += "{\"pin\":" + String(IN_PINS[i]) +
         ",\"val\":" + String(digitalRead(IN_PINS[i])) + "}";
  }
  j += "],\"adcPins\":[";
  for (int i = 0; i < ADC_COUNT; i++) {
    if (i > 0) j += ",";
    j += "{\"pin\":" + String(ADC_PINS[i]) +
         ",\"raw\":" + String(analogRead(ADC_PINS[i])) + "}";
  }
  j += "],\"pwm\":[";
  int g[3] = {GPIO_OUT_1, GPIO_OUT_2, GPIO_OUT_3};
  for (int i = 0; i < 3; i++) {
    if (i > 0) j += ",";
    j += "{\"ch\":" + String(i) + ",\"pin\":" + String(g[i]) +
         ",\"duty\":" + String(pwmDuty[i]) + ",\"mode\":" + jb(pwmMode[i]) +
         "}";
  }
  j += "],\"touch\":[";
  for (int i = 0; i < 2; i++) {
    if (i > 0) j += ",";
    j += "{\"pad\":" + String(i + 1) + ",\"gpio\":" + String(i + 1) +
         ",\"val\":" + String(touchVal[i]) +
         ",\"active\":" + jb(touchActive[i]) + ",\"action\":\"" +
         touchAction[i] + "\"}";
  }
  j += "]}";
  http.send(200, "application/json", j);
}

void handleWifiEndpoint() {
  wifi_sta_list_t sl;
  esp_wifi_ap_get_sta_list(&sl);
  esp_netif_t *apif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");

  String j = "{";
  j += "\"mode\":\"AP_STA\",";
  j += "\"ap\":{";
  j += "\"ssid\":\"" + esc(apSSID) + "\",";
  j += "\"ip\":\"" + WiFi.softAPIP().toString() + "\",";
  j += "\"mac\":\"" + WiFi.softAPmacAddress() + "\",";
  j += "\"stationsCount\":" + String(sl.num);
  j += "},";

  j += "\"sta\":{";
  j += "\"status\":\"" + staConnStatus + "\",";
  if (WiFi.status() == WL_CONNECTED) {
    j += "\"ssid\":\"" + esc(WiFi.SSID()) + "\",";
    j += "\"ip\":\"" + WiFi.localIP().toString() + "\",";
    j += "\"rssi\":" + String(WiFi.RSSI()) + ",";
    j += "\"mac\":\"" + WiFi.macAddress() + "\"";
  } else {
    j += "\"ssid\":\"\",";
    j += "\"ip\":\"\",";
    j += "\"rssi\":0,";
    j += "\"mac\":\"" + WiFi.macAddress() + "\"";
  }
  j += "},";

  j += "\"clients\":[";
  for (int i = 0; i < sl.num; i++) {
    if (i > 0) j += ",";
    const uint8_t *m = sl.sta[i].mac;
    char mac[18];
    snprintf(mac, 18, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3],
             m[4], m[5]);
    char ip[16] = "N/A";
    if (apif) {
      esp_netif_pair_mac_ip_t ci;
      memcpy(ci.mac, m, 6);
      if (esp_netif_dhcps_get_clients_by_mac(apif, 1, &ci) == ESP_OK)
        snprintf(ip, 16, IPSTR, IP2STR(&ci.ip));
    }
    j += "{\"mac\":\"" + String(mac) + "\",\"ip\":\"" + String(ip) +
         "\",\"rssi\":" + String(sl.sta[i].rssi) + ",\"vendor\":\"" +
         String(lookupOUI(m)) + "\"}";
  }
  j += "],";

  int n = WiFi.scanComplete();
  j += "\"scan\":{";
  j +=
      "\"status\":\"" +
      String(n >= 0 ? "done" : (n == WIFI_SCAN_RUNNING ? "scanning" : "idle")) +
      "\",";
  j += "\"networksFound\":" + String(n > 0 ? n : 0);
  j += "}";

  j += "}";
  http.send(200, "application/json", j);
}

void handleBluetoothEndpoint() {
  String j = "{";
  j += "\"status\":\"" + String(bleScanning ? "scanning" : "ready") + "\",";
  j += "\"scanning\":" + jb(bleScanning) + ",";
  j += "\"devices\":" + (bleResults.length() > 0 ? bleResults : "[]");
  j += "}";
  http.send(200, "application/json", j);
}

void handleNotFound() { http.send(404, "text/plain", "AXIOM 404"); }

// ══════════════════════════════════════════════════════════════════════════════
//  OLED DISPLAY — REDESIGNED GLITCH-FREE UI
// ══════════════════════════════════════════════════════════════════════════════

// Trims long strings to fit the 128px width safely
String truncateStr(String str, int maxLen) {
  if (str.length() > maxLen) {
    return str.substring(0, maxLen - 1) + ".";
  }
  return str;
}

// Formats milliseconds into a compact HH:MM:SS or MM:SS string
String formatTime(unsigned long ms) {
  unsigned long s = ms / 1000;
  unsigned long h = s / 3600;
  unsigned long m = (s % 3600) / 60;
  s = s % 60;
  char buf[12];
  if (h > 0) snprintf(buf, sizeof(buf), "%luh %lum", h, m);
  else snprintf(buf, sizeof(buf), "%lum %lus", m, s);
  return String(buf);
}

void oledHeader(const char *title) {
  oled.setFont(u8g2_font_6x10_tf);
  oled.setCursor(0, 9);
  oled.print("AXIOM");
  
  // Right-align the title safely
  int titleWidth = strlen(title) * 6; // 6px per character
  oled.setCursor(128 - titleWidth, 9);
  oled.print(title);
  
  oled.drawHLine(0, 11, 128);
}

// Renders a label on the left, and right-aligns the value to prevent overflow
void oledKV(int y, const char *label, String value) {
  oled.setCursor(0, y);
  oled.print(label);
  
  // Right align value (max 12 chars to fit safely on the right side)
  String valStr = truncateStr(value, 13);
  int valWidth = valStr.length() * 6;
  int xPos = 128 - valWidth;
  
  // Prevent label and value from colliding
  if (xPos < 60) xPos = 60; 
  
  oled.setCursor(xPos, y);
  oled.print(valStr);
}

void oledFooter(const char *left, const char *right) {
  oled.drawHLine(0, 52, 128);
  oled.setCursor(0, 62);
  oled.print(left);
  
  // Right align footer status
  int rWidth = strlen(right) * 6;
  oled.setCursor(128 - rWidth, 62);
  oled.print(right);
}

void drawOled() {
  if (!oledReady) return;
  if (oledDrawing) return;  // prevent re-entrant SPI collision
  oledDrawing = true;

  // Stabilize SH1106 charge pump before every draw
  oled.setContrast(OLED_CONTRAST);

  oled.clearBuffer();
  oled.setFont(u8g2_font_6x10_tf);
  
  switch (oledPage) {
    case PG_HOME: {
      oledHeader("HOME");
      oledKV(23, "Uptime:", formatTime(millis()));
      oledKV(35, "Heap:", String(ESP.getFreeHeap() / 1024) + " KB");
      oledKV(47, "CPU/Temp:", String(getCpuFrequencyMhz()) + "M / " + String((int)temperatureRead()) + "C");
      oledFooter(String("1/" + String(PG_COUNT)).c_str(), WiFi.softAPIP().toString().c_str());
      break;
    }
    case PG_WIFI: {
      oledHeader("WIFI");
      oledKV(23, "AP:", truncateStr(apSSID, 13));
      oledKV(35, "STA:", (WiFi.status() == WL_CONNECTED) ? truncateStr(WiFi.SSID(), 13) : "Disconnected");
      oledKV(47, "Clients:", String(WiFi.softAPgetStationNum()));
      String rssi = (WiFi.status() == WL_CONNECTED) ? (String(WiFi.RSSI()) + " dBm") : "--";
      oledFooter(String("2/" + String(PG_COUNT)).c_str(), rssi.c_str());
      break;
    }
    case PG_SNIFFER: {
      oledHeader("SNIFFER");
      oledKV(23, "Status:", snifferActive ? "ACTIVE" : "IDLE");
      oledKV(35, "Channel:", chanHopping ? "HOPPING" : String(snifferChan));
      oledKV(47, "Packets:", String(pktTotal));
      String dInfo = "Deauth: " + String(deauthCnt);
      oledFooter(String("3/" + String(PG_COUNT)).c_str(), dInfo.c_str());
      break;
    }
    case PG_KISMET: {
      oledHeader("KISMET");
      int apCount = 0;
      for (int i = 0; i < MAX_AP; i++) if (kisAPs[i].valid) apCount++;
      
      oledKV(23, "Status:", kismetMode ? "MAPPING" : "IDLE");
      oledKV(35, "APs:", String(apCount));
      oledKV(47, "Probes:", String(probeCount));
      oledFooter(String("4/" + String(PG_COUNT)).c_str(), "CH: HOP");
      break;
    }
    case PG_PMKID: {
      oledHeader("PMKID");
      oledKV(23, "Status:", pmkidMode ? "LISTENING" : "IDLE");
      oledKV(35, "Captured:", String(pmkidCount));
      oledKV(47, "Protocol:", "WPA2");
      oledFooter(String("5/" + String(PG_COUNT)).c_str(), "LAB ONLY");
      break;
    }
    case PG_GPIO: {
      oledHeader("GPIO");
      int highCount = 0;
      for (int i = 0; i < OUT_COUNT; i++) if (gpioStates[i]) highCount++;
      
      oledKV(23, "Outputs:", String(highCount) + "/" + String(OUT_COUNT) + " HIGH");
      oledKV(35, "Touch 1:", touchActive[0] ? "ACTIVE" : "idle");
      oledKV(47, "Touch 2:", touchActive[1] ? "ACTIVE" : "idle");
      oledFooter(String("6/" + String(PG_COUNT)).c_str(), "ESP32-S3");
      break;
    }
  }
  oled.sendBuffer();
  oledDrawing = false;
  oledDirty = false;  // mark clean after successful draw
}

void sendOledPageJSON() {
  String j = "{\"page\":" + String(oledPage) + ",\"name\":\"" +
             String(oledPageNames[oledPage]) +
             "\",\"count\":" + String(PG_COUNT) + "}";
  http.send(200, "application/json", j);
}
void handleDisplayNext() {
  oledPage = (oledPage + 1) % PG_COUNT;
  oledDirty = true;  // let loop() handle the draw safely
  sendOledPageJSON();
}
void handleDisplayPrev() {
  oledPage = (oledPage - 1 + PG_COUNT) % PG_COUNT;
  oledDirty = true;
  sendOledPageJSON();
}
void handleDisplayPage() {
  if (http.hasArg("id")) {
    int id = http.arg("id").toInt();
    if (id >= 0 && id < PG_COUNT)
      oledPage = id;
  }
  oledDirty = true;
  sendOledPageJSON();
}
void handleDisplayStatus() { sendOledPageJSON(); }

// ══════════════════════════════════════════════════════════════════════════════
//  SETUP
// ══════════════════════════════════════════════════════════════════════════════
void setNeo(uint8_t r, uint8_t g, uint8_t b);

void setup() {
  Serial.begin(115200);
  delay(400);
  Serial.println("\n+-------------------------------+");
  Serial.println("| AXIOM v12.0 GLITCH-FREE EDTN |");
  Serial.println("+-------------------------------+");

  // NeoPixel — boot violet immediately
  neo.begin();
  neo.setBrightness(60);
  setNeo(131, 111, 255);
  Serial.println("[LED] NeoPixel GPIO 48 ready");

  // OLED (SH1106 1.3" SPI) — U8g2 HW SPI mode handles bus init internally
  oledReady = oled.begin();
  if (oledReady) {
    oled.setContrast(OLED_CONTRAST);  // lock contrast at init
    lastContrastReset = millis();
    oledDirty = true;
    drawOled();
    Serial.println("[OLED] SH1106 ready (HW SPI, contrast locked)");
  } else {
    Serial.println("[OLED] init failed — check wiring/pins");
  }

  // GPIO
  for (int p : {GPIO_OUT_1, GPIO_OUT_2, GPIO_OUT_3}) {
    pinMode(p, OUTPUT);
    digitalWrite(p, LOW);
  }
  pinMode(7, INPUT_PULLDOWN);
  pinMode(8, INPUT_PULLDOWN);
  Serial.println("[GPIO] Ready");

  // Touch
  touch_pad_init();
  touch_pad_set_voltage(TOUCH_HVOLT_2V7, TOUCH_LVOLT_0V5, TOUCH_HVOLT_ATTEN_1V);
  touch_pad_config(TOUCH_PAD_NUM1);
  touch_pad_config(TOUCH_PAD_NUM2);
  touch_pad_fsm_start();
  Serial.println("[TOUCH] Ready GPIO 1,2");

  // NVS
  prefs.begin("axiom", true);
  apSSID = prefs.getString("apSSID", DEFAULT_AP_SSID);
  apPass = prefs.getString("apPass", DEFAULT_AP_PASS);
  prefs.end();
  Serial.println("[NVS] Config loaded.");

  // WiFi AP
  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(AP_IP, AP_GW, AP_SN);
  WiFi.softAP(apSSID.c_str(), apPass.c_str());
  Serial.println("[WIFI] AP -> http://192.168.4.1");

  // mDNS
  if (MDNS.begin(MDNS_HOST)) {
    MDNS.addService("http", "tcp", 80);
    MDNS.addService("ws", "tcp", 81);
    Serial.println("[mDNS] http://axiom.local");
  }

  // BLE scanner
  BLEDevice::init("AXIOM");
  pBLEScan = BLEDevice::getScan();
  pBLEScan->setInterval(100);
  pBLEScan->setWindow(99);
  Serial.println("[BLE] Scanner ready");

  // ── ROUTES ──
  http.on("/", HTTP_GET, handleRoot);
  http.on("/status", HTTP_GET, handleStatus);

  http.on("/gpio/pin", HTTP_GET, handleGPIOPin);
  http.on("/gpio/pwm", HTTP_GET, handlePWMSet);
  http.on("/gpio/pwmmode", HTTP_GET, handlePWMMode);
  http.on("/led", HTTP_GET, handleLED);
  http.on("/wifi/scan", HTTP_GET, handleWifiScan);
  http.on("/wifi/results", HTTP_GET, handleWifiResults);
  http.on("/wifi/connect", HTTP_POST, handleWifiConnect);
  http.on("/wifi/disconnect", HTTP_GET, handleWifiDisconnect);
  http.on("/ble/scan", HTTP_GET, handleBleScan);
  http.on("/ble/results", HTTP_GET, handleBleResults);

  http.on("/sniffer", HTTP_GET, handleSniffer);
  http.on("/sniffer/log", HTTP_GET, handleSnifferLog);
  http.on("/sniffer/clear", HTTP_GET, handleSnifferClear);
  http.on("/sniffer/hop", HTTP_GET, handleSnifferHop);
  http.on("/kismet", HTTP_GET, handleKismet);
  http.on("/kismet/data", HTTP_GET, handleKismetData);
  http.on("/kismet/clear", HTTP_GET, handleKismetClear);
  http.on("/pmkid", HTTP_GET, handlePMKID);
  http.on("/pmkid/data", HTTP_GET, handlePMKIDData);
  http.on("/rf/deauth", HTTP_GET, handleDeauth);
  http.on("/recon", HTTP_GET, handleRecon);
  http.on("/touch/actions", HTTP_GET, handleTouchActions);
  http.on("/ap/config", HTTP_POST, handleAPConfig);
  http.on("/system/cpu", HTTP_GET, handleCPU);
  http.on("/system/sleep", HTTP_GET, handleSleep);
  http.on("/system/reboot", HTTP_GET, handleReboot);

  http.on("/display/next", HTTP_GET, handleDisplayNext);
  http.on("/display/prev", HTTP_GET, handleDisplayPrev);
  http.on("/display/page", HTTP_GET, handleDisplayPage);
  http.on("/display/status", HTTP_GET, handleDisplayStatus);

  // Dedicated REST data endpoints
  http.on("/data", HTTP_GET, handleDataEndpoint);
  http.on("/gpio", HTTP_GET, handleGPIOEndpoint);
  http.on("/wifi", HTTP_GET, handleWifiEndpoint);
  http.on("/bluetooth", HTTP_GET, handleBluetoothEndpoint);
  http.on("/bt", HTTP_GET, handleBluetoothEndpoint);

  http.onNotFound(handleNotFound);

  http.begin();
  Serial.println("[HTTP] :80 ready");

  wsChat.begin();
  wsChat.onEvent(wsEvent);
  Serial.println("[WS] Chat :81 ready");

  // Boot blink: violet → mint → violet (confirms LED working)
  setNeo(21, 245, 186);
  delay(200);
  setNeo(131, 111, 255);
  delay(200);
  setNeo(21, 245, 186);

  Serial.printf("[AXIOM] Ready! Heap:%u CPU:%dMHz Temp:%.1fC\n",
                ESP.getFreeHeap(), getCpuFrequencyMhz(), temperatureRead());
}

// ══════════════════════════════════════════════════════════════════════════════
//  LOOP
// ══════════════════════════════════════════════════════════════════════════════
void loop() {
  http.handleClient();
  wsChat.loop();

  // STA watchdog (non-blocking)
  if (staConnStatus == "connecting") {
    if (WiFi.status() == WL_CONNECTED) {
      staConnStatus = "connected";
      Serial.println("[WIFI] Connected -> " + WiFi.localIP().toString());
      setNeo(21, 245, 186); // mint = connected
    } else if (millis() > staTimeout) {
      staConnStatus = "failed";
      Serial.println("[WIFI] Connection failed");
      setNeo(255, 30, 0);
      static unsigned long failLEDTime = 0;
      if (failLEDTime == 0) failLEDTime = millis() + 2000;
      if (millis() > failLEDTime) {
        setNeo(131, 111, 255);
        failLEDTime = 0;
      }
    }
  }

  // Channel hopping — only when not BLE scanning
  if (chanHopping && !bleScanning &&
      (snifferActive || kismetMode || deauthMode || pmkidMode) &&
      millis() - lastChanHop > 350) {
    deauthChan = (deauthChan % 13) + 1;
    esp_wifi_set_channel(deauthChan, WIFI_SECOND_CHAN_NONE);
    lastChanHop = millis();
    deauthCnt = _deauthCnt;
    deauthLast = String((char *)_deauthMAC);
  }

  // Touch polling
  if (millis() - lastTouchPoll > 150) {
    lastTouchPoll = millis();
    uint32_t v0 = 0, v1 = 0;
    touch_pad_read_raw_data(TOUCH_PAD_NUM1, &v0);
    touch_pad_read_raw_data(TOUCH_PAD_NUM2, &v1);
    touchVal[0] = v0;
    touchVal[1] = v1;
    touchActive[0] = (v0 < TOUCH_THRESHOLD);
    touchActive[1] = (v1 < TOUCH_THRESHOLD);
    for (int i = 0; i < 2; i++) {
      if (touchActive[i] && !prevTouch[i]) fireTouchAction(i);
      prevTouch[i] = touchActive[i];
    }
  }

  // OLED refresh — dirty-flag driven + periodic live update (3s)
  // Never call drawOled() from HTTP handlers; only here in loop()
  static unsigned long lastOledRefresh = 0;
  if (oledReady && !oledDrawing) {
    bool needsDraw = oledDirty;

    // Periodic contrast reset — prevents SH1106 charge pump inversion
    if (millis() - lastContrastReset > CONTRAST_RESET_INTERVAL) {
      lastContrastReset = millis();
      oled.setContrast(OLED_CONTRAST);
    }

    // Live data refresh every 3s (was 1s — reduces flicker by 66%)
    if (millis() - lastOledRefresh > OLED_LIVE_INTERVAL) {
      lastOledRefresh = millis();
      needsDraw = true;
    }

    if (needsDraw) {
      drawOled();
    }
  }

  // Heartbeat
  if (millis() - lastHeartbeat > 10000) {
    lastHeartbeat = millis();
    Serial.printf("[AXIOM] Up:%lus Heap:%u STA:%s Sniffer:%s Kismet:%s "
                  "PMKID:%d Deauth:%d\n",
                  millis() / 1000, ESP.getFreeHeap(),
                  WiFi.status() == WL_CONNECTED ? "UP" : "DOWN",
                  snifferActive ? "ON" : "OFF", kismetMode ? "ON" : "OFF",
                  pmkidCount, deauthCnt);
  }
}