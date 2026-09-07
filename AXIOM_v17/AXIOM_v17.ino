/*
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║                                AXIOM  v17                                ║
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
 *  CHANGES in v17:
 *    - ADDED:   /wifi/nat endpoint (handleNatBridge) with enable/disableBridgeNAPT.
 *    - REVERTED: v16 hardening pass (AXIOM_VERSION define, auth token, ArduinoJson
 *               refactor) back to the classic string handlers.
 *    - CHANGED: TOUCH_THRESHOLD back to 40000.
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

// ─── LIBRARIES ───────────────────────────────────────────────────────────────
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
#include <time.h>

// Forward declarations
bool isPinInUse(int pin);

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
  PG_RFINTEL,
  PG_RECON,
  PG_SYSTEM,
  PG_CHAT,
  PG_COUNT
};
const char *oledPageNames[PG_COUNT] = {"HOME",   "WIFI",  "SNIFFER",
                                       "KISMET", "PMKID", "GPIO",
                                       "RFINTEL", "RECON", "SYSTEM", "CHAT"};
int oledPage = PG_HOME;  // default to HOME panel (PG_HOME) as per request
bool oledReady = false;
volatile bool oledDirty = true;      // force first draw
volatile bool oledDrawing = false;   // re-entrancy guard
int oledScrollOffset = 0;            // in-panel scroll position (WIFI/GPIO lists)
volatile unsigned long lastHttpActivityAt = 0;  // last time a request was sent/handled
const unsigned long OLED_QUIET_WINDOW = 150;    // don't SPI-write within this many ms of WiFi TX
const uint8_t OLED_CONTRAST = 0xCF; // stable contrast for SH1106
unsigned long lastContrastReset = 0;
// Auto modes (server-side state exposed to the dashboard)
bool oledAutoCycle = false;    // server-side auto-cycle flag
bool oledAutoRefresh = false;   // server-side auto-refresh flag (default OFF to avoid blinking)

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
const int CHAT_HISTORY_COUNT = 5;
String chatHistory[CHAT_HISTORY_COUNT] = {"No messages yet", "", "", "", ""};
int chatHistoryIndex = 0;
String staConnStatus = "disconnected";
String staSSID = "";
unsigned long staTimeout = 0;
bool bridgeNaptEnabled = false;
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
// Reduced timeout from 120ms → 80ms, port list trimmed to most useful
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
    if (c.connect(ip.c_str(), PORTS[i].port, 80)) { // 80ms timeout
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
// Forward declaration for async BLE scan starter used by handlers
void startBleScanAsync();

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
      
      String formattedMsg = nm + ": " + tx;
      chatHistory[chatHistoryIndex] = formattedMsg;
      chatHistoryIndex = (chatHistoryIndex + 1) % CHAT_HISTORY_COUNT;
      
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
//  HTML — AXIOM v17 DASHBOARD
// ══════════════════════════════════════════════════════════════════════════════
const char HTML[] PROGMEM = R"RAWHTML(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1"/>
<title>AXIOM v8</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap" rel="stylesheet"/>
<style>
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}
:root{
  --bg:#0a0614;--bg1:#110d1f;--bg2:#17122b;
  --bd:rgba(131,111,255,0.15);--bd2:rgba(131,111,255,0.28);
  --v1:#F0F3FF;--v2:#15F5BA;--v3:#836FFF;--v4:#211951;
  --v3a:rgba(131,111,255,0.12);--v2a:rgba(21,245,186,0.12);
  --tx:#F0F3FF;--dm:#6b7280;--dk:#1e1b34;--rd:#ff6b6b;--or:#fbbf24;
}
body{background:var(--bg);color:var(--tx);font-family:'Space Mono',monospace;min-height:100vh;overflow-x:hidden}
#bg{position:fixed;inset:0;z-index:0;pointer-events:none}
.shell{position:relative;z-index:1;max-width:860px;margin:0 auto;padding:10px 12px 20px}

/* HDR */
.hdr{display:flex;align-items:center;justify-content:space-between;padding:12px 18px;margin-bottom:12px;
  background:rgba(33,25,81,0.6);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);
  border:1px solid var(--bd2);border-radius:14px;
  box-shadow:0 0 30px rgba(131,111,255,0.08),inset 0 1px 0 rgba(240,243,255,0.05)}
.logo{font-family:'Syne',sans-serif;font-weight:800;font-size:1.35rem;letter-spacing:6px;
  background:linear-gradient(135deg,var(--v2),var(--v3));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent}
.hdr-r{display:flex;align-items:center;gap:8px;font-size:.58rem;color:var(--dm)}
.hdr-ip{color:var(--v2);letter-spacing:1px;font-size:.6rem}
.pill{padding:3px 9px;border-radius:20px;font-size:.52rem;letter-spacing:2px;font-weight:700;white-space:nowrap}
.p-on{background:rgba(21,245,186,.12);color:var(--v2);border:1px solid rgba(21,245,186,.28)}
.p-off{background:rgba(107,114,128,.1);color:var(--dm);border:1px solid rgba(107,114,128,.2)}
.p-v{background:rgba(131,111,255,.12);color:var(--v3);border:1px solid rgba(131,111,255,.28)}
.p-rd{background:rgba(255,107,107,.1);color:var(--rd);border:1px solid rgba(255,107,107,.25)}
.p-or{background:rgba(251,191,36,.1);color:var(--or);border:1px solid rgba(251,191,36,.25)}

/* TABS */
.tabs{display:flex;gap:4px;margin-bottom:12px;flex-wrap:wrap;overflow-x:auto;
  scrollbar-width:none;padding-bottom:2px}
.tabs::-webkit-scrollbar{display:none}
.tab{flex-shrink:0;padding:7px 11px;border-radius:9px;border:1px solid var(--bd);
  background:rgba(33,25,81,0.3);color:var(--dm);font-family:'Space Mono',monospace;
  font-size:.55rem;letter-spacing:1px;cursor:pointer;transition:all .2s;white-space:nowrap}
.tab.active{border-color:var(--bd2);color:var(--v3);background:var(--v3a);
  box-shadow:0 0 12px rgba(131,111,255,.12)}
.tab:hover:not(.active){color:#a5b4fc;border-color:rgba(131,111,255,.2)}
.tab.t-cyber{border-color:rgba(21,245,186,.15);color:#6ee7b7}
.tab.t-cyber.active{border-color:rgba(21,245,186,.35);color:var(--v2);background:var(--v2a);
  box-shadow:0 0 12px rgba(21,245,186,.12)}
.page{display:none}.page.active{display:block}

/* GLASS */
.g{background:rgba(33,25,81,0.35);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  border:1px solid var(--bd);border-radius:13px;padding:15px;
  box-shadow:0 4px 24px rgba(0,0,0,.35),inset 0 1px 0 rgba(240,243,255,.04)}
.g2{background:rgba(33,25,81,0.55);backdrop-filter:blur(20px);border:1px solid var(--bd2);
  border-radius:13px;padding:15px;box-shadow:0 4px 24px rgba(0,0,0,.4)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(248px,1fr));gap:10px}
.sp{grid-column:1/-1}.mb{margin-bottom:10px}

.ct{font-size:.52rem;letter-spacing:4px;color:var(--dm);text-transform:uppercase;margin-bottom:11px;
  display:flex;align-items:center;gap:8px}
.ct::after{content:'';flex:1;height:1px;background:linear-gradient(90deg,var(--bd),transparent)}

.row{display:flex;align-items:center;justify-content:space-between;margin-bottom:7px;
  padding:7px 10px;border-radius:8px;border:1px solid rgba(131,111,255,.08);
  background:rgba(0,0,0,.25);transition:border-color .2s}
.row:hover{border-color:rgba(131,111,255,.2)}
.lbl{font-size:.7rem;color:#a5b4fc}
.tog{width:42px;height:21px;border-radius:11px;border:none;cursor:pointer;position:relative;
  transition:background .3s;background:rgba(131,111,255,.15);flex-shrink:0}
.tog.on{background:linear-gradient(135deg,var(--v2),#0abf93)}
.tog::after{content:'';position:absolute;width:15px;height:15px;border-radius:50%;
  background:#fff;top:3px;left:3px;transition:transform .3s;box-shadow:0 1px 4px rgba(0,0,0,.5)}
.tog.on::after{transform:translateX(21px)}

.ir{display:flex;justify-content:space-between;font-size:.66rem;color:var(--dm);
  margin-bottom:4px;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.025)}
.ir span:last-child{color:#c7d2fe;text-align:right;max-width:55%}
.ir.nb{border-bottom:none}

.btn{width:100%;padding:9px;border-radius:9px;font-family:'Space Mono',monospace;
  font-size:.58rem;letter-spacing:2px;cursor:pointer;transition:all .22s;margin-top:7px;
  position:relative;overflow:hidden}
.btn::after{content:'';position:absolute;inset:0;opacity:0;background:rgba(255,255,255,.06);transition:opacity .2s}
.btn:hover::after{opacity:1}
.bv{background:linear-gradient(135deg,rgba(131,111,255,.15),rgba(131,111,255,.06));
  border:1px solid rgba(131,111,255,.3);color:var(--v3)}
.bm{background:linear-gradient(135deg,rgba(21,245,186,.15),rgba(21,245,186,.06));
  border:1px solid rgba(21,245,186,.3);color:var(--v2)}
.bo{background:linear-gradient(135deg,rgba(251,191,36,.12),rgba(251,191,36,.04));
  border:1px solid rgba(251,191,36,.28);color:var(--or)}
.br{background:linear-gradient(135deg,rgba(255,107,107,.1),rgba(255,107,107,.04));
  border:1px solid rgba(255,107,107,.28);color:var(--rd)}
.btn:disabled{opacity:.28;cursor:not-allowed}

.slk{padding:8px 10px;background:rgba(0,0,0,.25);border-radius:8px;border:1px solid rgba(131,111,255,.08);margin-bottom:8px}
.slbl{font-size:.5rem;color:var(--dm);letter-spacing:2px;margin-bottom:3px}
.slider{width:100%;-webkit-appearance:none;height:3px;border-radius:2px;background:rgba(255,255,255,.08);outline:none}
.slider::-webkit-slider-thumb{-webkit-appearance:none;width:13px;height:13px;border-radius:50%;
  background:linear-gradient(135deg,var(--v3),var(--v2));cursor:pointer;box-shadow:0 0 8px rgba(131,111,255,.5)}

.badge{padding:2px 7px;border-radius:20px;font-size:.52rem;letter-spacing:2px;display:inline-block}
.bv2{background:rgba(131,111,255,.1);color:var(--v3);border:1px solid rgba(131,111,255,.25)}
.bm2{background:rgba(21,245,186,.1);color:var(--v2);border:1px solid rgba(21,245,186,.25)}
.br2{background:rgba(255,107,107,.1);color:var(--rd);border:1px solid rgba(255,107,107,.25)}
.bo2{background:rgba(251,191,36,.1);color:var(--or);border:1px solid rgba(251,191,36,.25)}
.bx2{background:rgba(107,114,128,.08);color:var(--dm);border:1px solid rgba(107,114,128,.15)}

.tbl{width:100%;border-collapse:collapse;font-size:.62rem;margin-top:6px}
.tbl th{color:rgba(131,111,255,.6);letter-spacing:2px;padding:5px 6px;
  border-bottom:1px solid var(--bd);text-align:left;font-weight:400}
.tbl td{color:#64748b;padding:5px 6px;border-bottom:1px solid rgba(255,255,255,.02);vertical-align:top}
.tbl tr:hover td{color:#a5b4fc;background:rgba(131,111,255,.03)}
.sig{height:4px;border-radius:2px;display:inline-block;min-width:3px;vertical-align:middle}
.sv{background:linear-gradient(90deg,var(--v3),#5a4bd1)}
.sm{background:linear-gradient(90deg,var(--v2),#0abf93)}
.sr{background:linear-gradient(90deg,var(--rd),#e53935)}

.fld{margin-bottom:9px}
.fld label{display:block;font-size:.5rem;color:var(--dm);letter-spacing:2px;margin-bottom:3px}
.fld input,.fld select,.fld textarea{width:100%;background:rgba(0,0,0,.35);border:1px solid var(--bd);
  border-radius:8px;padding:8px 11px;color:var(--tx);font-family:'Space Mono',monospace;
  font-size:.68rem;outline:none;transition:border-color .2s}
.fld textarea{min-height:92px;resize:vertical;line-height:1.45}
.fld input:focus,.fld select:focus,.fld textarea:focus{border-color:rgba(131,111,255,.4)}
.fld select option{background:#110d1f}

#evtLog,#pktLog{background:rgba(0,0,0,.45);border:1px solid var(--bd);border-radius:8px;
  padding:8px;overflow-y:auto;font-size:.58rem;line-height:1.9;
  scrollbar-width:thin;scrollbar-color:var(--bd) transparent}
#evtLog{height:100px}
#pktLog{height:220px;font-size:.55rem}
.le{color:rgba(131,111,255,.45)}.le.w{color:rgba(251,191,36,.45)}.le.g{color:rgba(21,245,186,.45)}.le.r{color:rgba(255,107,107,.45)}
.pk-m{color:rgba(131,111,255,.7)}.pk-d{color:rgba(21,245,186,.6)}.pk-c{color:rgba(251,191,36,.6)}.pk-x{color:rgba(255,107,107,.5)}

.gpio-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(72px,1fr));gap:6px;margin-top:8px}
.gpio-btn{padding:7px 4px;border-radius:8px;border:1px solid var(--bd);background:rgba(0,0,0,.25);
  cursor:pointer;text-align:center;transition:all .2s;font-family:'Space Mono',monospace}
.gpio-btn .gn{font-size:.55rem;color:var(--dm);letter-spacing:1px;display:block;margin-bottom:2px}
.gpio-btn .gs{font-size:.6rem;font-weight:700}
.gpio-btn.off .gs{color:#334155}
.gpio-btn.on{border-color:rgba(21,245,186,.35);background:rgba(21,245,186,.06)}
.gpio-btn.on .gs{color:var(--v2)}
.gpio-btn.adc{border-color:rgba(131,111,255,.15)}
.gpio-btn.adc .gn::after{content:' ADC';color:rgba(131,111,255,.4);font-size:.45rem}
.gpio-btn:hover{border-color:rgba(131,111,255,.3);background:rgba(131,111,255,.06)}
/* In-use pins (reserved by hardware like OLED) */
.gpio-btn.inuse{opacity:.6;border-color:rgba(255,99,71,.25);background:rgba(255,99,71,.03);cursor:not-allowed}
.gpio-btn.inuse .gn::after{content:' HW';color:rgba(255,99,71,.45);font-size:.45rem}

.net-item{display:flex;align-items:center;justify-content:space-between;padding:8px 10px;
  border-radius:8px;border:1px solid var(--bd);background:rgba(0,0,0,.2);margin-bottom:5px;
  cursor:pointer;transition:all .2s}
.net-item:hover{border-color:rgba(21,245,186,.28);background:rgba(21,245,186,.04)}
.net-item.sel{border-color:rgba(21,245,186,.45);background:rgba(21,245,186,.07)}
.net-n{font-size:.7rem;color:#e2e8f0}
.net-m{display:flex;align-items:center;gap:8px}
.sigs{display:flex;align-items:flex-end;gap:2px;height:13px}
.sb{width:3px;border-radius:1px;background:rgba(255,255,255,.12)}
.sb.on{background:var(--v2)}

.mbg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:300;
  align-items:center;justify-content:center;backdrop-filter:blur(6px)}
.mbg.show{display:flex}
.modal{background:#110d1f;border:1px solid var(--bd2);border-radius:14px;padding:20px;
  width:min(330px,92vw);box-shadow:0 20px 60px rgba(0,0,0,.7),0 0 40px rgba(131,111,255,.06)}
.modal h3{font-family:'Syne',sans-serif;font-size:.7rem;letter-spacing:3px;color:var(--v2);margin-bottom:12px}
.mbns{display:flex;gap:6px;margin-top:3px}.mbns .btn{margin-top:0;flex:1}
#mSt{font-size:.56rem;letter-spacing:1px;display:block;margin-bottom:7px;min-height:12px}

@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}

.stabox{background:rgba(0,0,0,.3);border:1px solid var(--bd);border-radius:9px;padding:10px 13px;margin-top:9px}
.sts{display:flex;justify-content:space-between;padding:3px 0;font-size:.62rem}
.stk{color:var(--dm)}.stv{color:#c7d2fe}
.stv.g{color:var(--v2);animation:glow 2s infinite}
.stv.o{color:var(--or);animation:blink .8s infinite}
.stv.r{color:var(--rd)}
@keyframes glow{0%,100%{opacity:1;text-shadow:0 0 6px var(--v2)}50%{opacity:.7;text-shadow:none}}

.rgbrow{display:flex;gap:8px;flex-wrap:wrap;padding:8px 0}
.dot{width:36px;height:36px;border-radius:50%;cursor:pointer;border:2px solid transparent;
  transition:all .25s;display:flex;align-items:center;justify-content:center;
  font-size:.5rem;font-weight:700;letter-spacing:1px}
.dot:hover{transform:scale(1.12)}.dot.a{border-color:white}

#chCv{width:100%;height:85px;display:block;margin-top:6px}

.dan{font-family:'Syne',sans-serif;font-size:3rem;font-weight:800;line-height:1;text-align:center;letter-spacing:4px;
  background:linear-gradient(135deg,var(--v3),var(--v2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.dal{font-size:.52rem;color:var(--dm);letter-spacing:3px;text-align:center;margin-top:3px}
.daa{font-size:.62rem;color:var(--rd);letter-spacing:2px;text-align:center;margin-top:6px;display:none;animation:blink 1s infinite}

.torb{width:64px;height:64px;border-radius:50%;border:2px solid var(--bd);
  display:flex;align-items:center;justify-content:center;font-size:.6rem;color:var(--dm);
  transition:all .4s;letter-spacing:1px;position:relative}
.torb.on{border-color:rgba(131,111,255,.5);background:rgba(131,111,255,.08);color:var(--v3);box-shadow:0 0 18px rgba(131,111,255,.2)}

.gr{display:flex;align-items:center;gap:9px;margin-bottom:6px}
.gb{flex:1;height:3px;background:rgba(255,255,255,.05);border-radius:2px;overflow:hidden}
.gf{height:100%;border-radius:2px;transition:width .6s}

.warn-box{background:rgba(255,107,107,.06);border:1px solid rgba(255,107,107,.2);
  border-radius:9px;padding:10px 13px;margin-bottom:10px;font-size:.6rem;color:rgba(255,107,107,.8);line-height:1.7}


.kap{display:flex;align-items:center;justify-content:space-between;padding:6px 10px;
  border-bottom:1px solid rgba(255,255,255,.03)}
.kap-s{font-size:.68rem;color:#e2e8f0}.kap-m{font-size:.55rem;color:#334155}

footer{text-align:center;margin-top:18px;font-size:.48rem;color:rgba(255,255,255,.08);letter-spacing:3px;padding-bottom:8px}
</style>
</head>
<body>
<canvas id="bg"></canvas>
<div class="shell">

<!-- HDR -->
<div class="hdr">
  <div class="logo">AXIOM</div>
  <div class="hdr-r">
    <span class="hdr-ip" id="hIP">192.168.4.1</span>
    <span class="pill p-on">AP</span>
    <span class="pill p-off" id="staPill" style="display:none">STA</span>
    <span class="pill p-rd" id="cyberPill" style="display:none">⚡ CYBER</span>
  </div>
</div>

<!-- TABS -->
<div class="tabs">
  <button class="tab active"          onclick="P('wifi',this)">📡 WIFI</button>
  <button class="tab"                 onclick="P('gpio',this)">⚡ GPIO</button>
  <button class="tab"                 onclick="P('ble',this)">🔵 BLE</button>
  <button class="tab t-cyber"         onclick="P('datapanel',this)">📊 DATA PANEL</button>
  <button class="tab t-cyber"         onclick="P('sniffer',this)">🦈 SNIFFER</button>
  <button class="tab t-cyber"         onclick="P('kismet',this)">🗺️ KISMET</button>
  <button class="tab t-cyber"         onclick="P('pmkid',this)">🔑 PMKID</button>
  <button class="tab t-cyber"         onclick="P('deauth',this)">🛡️ RF INTEL</button>
  <button class="tab"                 onclick="P('recon',this)">🕵️ RECON</button>
  <button class="tab"                 onclick="P('chat',this)">💬 CHAT</button>
  <button class="tab"                 onclick="P('system',this)">🔧 SYSTEM</button>
  <button class="tab"                 onclick="P('display',this)">🖥️ DISPLAY</button>
</div>

<!-- ══ WIFI ══ -->
<div class="page active" id="wifiPage">
  <div class="grid">
    <div class="g sp">
      <div class="ct">WIFI SCANNER
        <span id="wBridge" class="pill p-off" style="margin-left:auto">STA OFF</span>
      </div>
      <div style="display:flex;gap:7px;align-items:center;flex-wrap:wrap;margin-bottom:10px">
        <button class="btn bm" id="wSB" onclick="wScan()" style="width:auto;margin:0;padding:7px 16px">▶ SCAN NETWORKS</button>
        <span id="wSS" style="font-size:.58rem;color:var(--dm);letter-spacing:2px"></span>
      </div>
      <div id="netList"><div style="color:var(--dm);font-size:.62rem;text-align:center;padding:14px">Scan to see networks</div></div>
    </div>
    <div class="g">
      <div class="ct">UPLINK (STA MODE)</div>
      <div class="ir"><span>STATUS</span><span id="staSt">—</span></div>
      <div class="ir"><span>NETWORK</span><span id="staS">—</span></div>
      <div class="ir"><span>ESP IP</span><span id="staI">—</span></div>
      <div class="ir nb"><span>RSSI</span><span id="staR">—</span></div>
      <div class="row"><span class="lbl">NAT BRIDGE</span><button class="tog" id="natToggle" onclick="toggleNatBridge()" aria-label="Toggle NAT bridge"></button></div>
      <span id="natSt" style="font-size:.52rem;color:var(--dm);display:block;text-align:right">UPSTREAM REQUIRED</span>
      <button class="btn br" id="discBtn" onclick="wDisc()" style="display:none">✕ DISCONNECT</button>
    </div>
    <div class="g">
      <div class="ct">RGB LED (GPIO 48)</div>
      <div class="rgbrow">
        <div class="dot" style="background:#ef4444;color:#fff;box-shadow:0 0 10px #ef444455" onclick="setLED(255,0,0)">R</div>
        <div class="dot" style="background:#22c55e;color:#fff;box-shadow:0 0 10px #22c55e55" onclick="setLED(0,255,0)">G</div>
        <div class="dot" style="background:#3b82f6;color:#fff;box-shadow:0 0 10px #3b82f655" onclick="setLED(0,0,255)">B</div>
        <div class="dot" style="background:#15F5BA;color:#000;box-shadow:0 0 10px #15F5BA55" onclick="setLED(21,245,186)">M</div>
        <div class="dot" style="background:#836FFF;color:#fff;box-shadow:0 0 10px #836FFF55" onclick="setLED(131,111,255)">V</div>
        <div class="dot" style="background:#f97316;color:#fff;box-shadow:0 0 10px #f9731655" onclick="setLED(255,120,0)">O</div>
        <div class="dot" style="background:#1e1b34;color:#555;border:1px solid #334155" onclick="setLED(0,0,0)">OFF</div>
      </div>
      <div class="stabox">
        <div class="sts"><span class="stk">SELECTED NET</span><span class="stv" id="sbNet">—</span></div>
        <div class="sts"><span class="stk">SIGNAL</span><span class="stv" id="sbSig">—</span></div>
        <div class="sts"><span class="stk">STATUS</span><span class="stv" id="sbSt">IDLE</span></div>
        <div class="sts"><span class="stk">IP ASSIGNED</span><span class="stv" id="sbIP">—</span></div>
      </div>
    </div>
    <div class="g sp">
      <div class="ct">AP SETTINGS (SAVED TO FLASH)</div>
      <div class="grid" style="grid-template-columns:1fr 1fr;gap:10px">
        <div><div class="fld"><label>NEW SSID</label><input type="text" id="nSsid" maxlength="32"/></div></div>
        <div><div class="fld"><label>NEW PASSWORD (≥8)</label><input type="password" id="nPass" maxlength="64"/></div></div>
      </div>
      <div class="fld"><label>CONFIRM PASSWORD</label><input type="password" id="nPassC" maxlength="64"/></div>
      <span id="apSt" style="font-size:.56rem;color:var(--dm);letter-spacing:1px;display:block;margin-top:4px"></span>
      <button class="btn bm" onclick="saveAP()">💾 SAVE & REBOOT</button>
    </div>
  </div>
</div>

<!-- ══ GPIO ══ -->
<div class="page" id="gpioPage">
  <div class="grid">
    <div class="g sp">
      <div class="ct">ALL OUTPUT PINS — CLICK TO TOGGLE</div>
      <div class="gpio-grid" id="gpioGrid"></div>
    </div>
    <div class="g">
      <div class="ct">PWM CONTROL</div>
      <div class="slk"><div class="slbl">GPIO 4 · CH0 · <span id="d0">0</span>/255</div>
        <input type="range" class="slider" min="0" max="255" value="0" oninput="setPWM(0,this.value)"/>
        <button class="btn bv" style="margin-top:4px;padding:4px;font-size:.5rem" onclick="togPWM(0)" id="pm0">ENABLE PWM</button></div>
      <div class="slk"><div class="slbl">GPIO 5 · CH1 · <span id="d1">0</span>/255</div>
        <input type="range" class="slider" min="0" max="255" value="0" oninput="setPWM(1,this.value)"/>
        <button class="btn bv" style="margin-top:4px;padding:4px;font-size:.5rem" onclick="togPWM(1)" id="pm1">ENABLE PWM</button></div>
      <div class="slk"><div class="slbl">GPIO 6 · CH2 · <span id="d2">0</span>/255</div>
        <input type="range" class="slider" min="0" max="255" value="0" oninput="setPWM(2,this.value)"/>
        <button class="btn bv" style="margin-top:4px;padding:4px;font-size:.5rem" onclick="togPWM(2)" id="pm2">ENABLE PWM</button></div>
    </div>
    <div class="g">
      <div class="ct">INPUT MONITOR</div>
      <div class="row"><span class="lbl">GPIO 7 — IN 1</span><span class="badge bx2" id="in0">—</span></div>
      <div class="row"><span class="lbl">GPIO 8 — IN 2</span><span class="badge bx2" id="in1">—</span></div>
      <div class="ct" style="margin-top:12px">CAPACITIVE TOUCH</div>
      <div style="display:flex;gap:16px;justify-content:center;padding:10px 0">
        <div style="text-align:center"><div class="torb" id="tc0">T1</div>
          <div style="font-size:.5rem;color:var(--dm);margin-top:4px">GPIO 1</div>
          <div style="font-size:.55rem;color:#2d3748;margin-top:2px" id="tv0">—</div></div>
        <div style="text-align:center"><div class="torb" id="tc1">T2</div>
          <div style="font-size:.5rem;color:var(--dm);margin-top:4px">GPIO 2</div>
          <div style="font-size:.55rem;color:#2d3748;margin-top:2px" id="tv1">—</div></div>
      </div>
      <div class="fld"><label>T1 ACTION</label>
        <select id="ta0"><option value="none">None</option><option value="gpio0">Toggle GPIO 4</option>
          <option value="gpio1">Toggle GPIO 5</option><option value="gpio2">Toggle GPIO 6</option>
          <option value="sleep">Deep Sleep</option></select></div>
      <div class="fld"><label>T2 ACTION</label>
        <select id="ta1"><option value="none">None</option><option value="gpio0">Toggle GPIO 4</option>
          <option value="gpio1">Toggle GPIO 5</option><option value="gpio2">Toggle GPIO 6</option>
          <option value="sleep">Deep Sleep</option></select></div>
      <button class="btn bm" onclick="saveTouchAct()">💾 SAVE TOUCH ACTIONS</button>
    </div>
    <div class="g sp"><div class="ct">EVENT LOG</div>
      <div id="evtLog"><span style="color:#1e293b">Waiting...</span></div></div>
  </div>
</div>

<!-- ══ BLE ══ -->
<div class="page" id="blePage">
  <div class="g">
    <div class="ct">BLUETOOTH LE SCANNER</div>
    <div style="display:flex;gap:7px;align-items:center;margin-bottom:10px">
      <button class="btn bv" id="bSB" onclick="bScan()" style="width:auto;margin:0;padding:7px 16px">▶ SCAN BLE</button>
      <span id="bSS" style="font-size:.58rem;color:var(--dm);letter-spacing:2px"></span>
    </div>
    <table class="tbl">
      <thead><tr><th>NAME</th><th>MAC ADDRESS</th><th>MANUFACTURER</th><th>RSSI</th><th>SIG</th></tr></thead>
      <tbody id="bT"><tr><td colspan="5" style="color:#1e293b;text-align:center;padding:14px">Scan to find BLE devices</td></tr></tbody>
    </table>
  </div>
</div>

<!-- ══ SNIFFER ══ -->
<div class="page" id="snifferPage">
  <div class="warn-box">⚠ FOR AUTHORIZED LAB USE ONLY. Capturing 802.11 frames on networks you do not own or have explicit written permission to test is illegal in most jurisdictions.</div>
  <div class="grid">
    <div class="g sp">
      <div class="ct">🦈 PACKET SNIFFER — 802.11 LIVE CAPTURE</div>
      <div style="display:flex;gap:7px;align-items:center;flex-wrap:wrap;margin-bottom:10px">
        <button class="btn bm" id="snifBtn" onclick="togSniffer()" style="width:auto;margin:0;padding:7px 16px">▶ START CAPTURE</button>
        <button class="btn bv" onclick="clearPkts()" style="width:auto;margin:0;padding:7px 12px">CLEAR</button>
        <span id="snifSt" style="font-size:.58rem;color:var(--dm);letter-spacing:2px"></span>
        <label style="font-size:.55rem;color:var(--dm);letter-spacing:2px;margin-left:auto">
          <input type="checkbox" id="hopCb" onchange="setHop(this.checked)" style="margin-right:4px"/>CHANNEL HOP
        </label>
        <select id="chanSel" style="background:rgba(0,0,0,.3);border:1px solid var(--bd);border-radius:7px;
          padding:4px 8px;color:var(--tx);font-family:'Space Mono',monospace;font-size:.58rem">
          <option value="0">ALL CH (hop)</option>
          <option value="1">CH 1</option><option value="6">CH 6</option><option value="11">CH 11</option>
          <option value="2">CH 2</option><option value="3">CH 3</option><option value="4">CH 4</option>
          <option value="5">CH 5</option><option value="7">CH 7</option><option value="8">CH 8</option>
          <option value="9">CH 9</option><option value="10">CH 10</option><option value="13">CH 13</option>
        </select>
      </div>
      <div id="pktLog"><span style="color:#1e293b">Start capture to see packets...</span></div>
      <div style="display:flex;justify-content:space-between;margin-top:6px;font-size:.55rem;color:var(--dm)">
        <span>TOTAL: <span id="pktTotal" style="color:var(--v3)">0</span></span>
        <span>MGMT: <span id="pktMgmt" style="color:var(--v3)">0</span></span>
        <span>DATA: <span id="pktData" style="color:var(--v2)">0</span></span>
        <span>CTRL: <span id="pktCtrl" style="color:var(--or)">0</span></span>
      </div>
    </div>
  </div>
</div>

<!-- ══ KISMET ══ -->
<div class="page" id="kismetPage">
  <div class="warn-box">⚠ AUTHORIZED LAB USE ONLY. This passively maps all visible APs, clients, and probe requests.</div>
  <div class="grid">
    <div class="g sp">
      <div class="ct">🗺️ KISMET — AP + CLIENT MAPPER</div>
      <div style="display:flex;gap:7px;align-items:center;margin-bottom:10px;flex-wrap:wrap">
        <button class="btn bm" id="kisBtn" onclick="togKismet()" style="width:auto;margin:0;padding:7px 16px">▶ START KISMET</button>
        <button class="btn bv" onclick="clearKismet()" style="width:auto;margin:0;padding:7px 12px">CLEAR</button>
        <span id="kisSt" style="font-size:.58rem;color:var(--dm);letter-spacing:2px"></span>
      </div>
      <div class="ct">ACCESS POINTS DETECTED</div>
      <table class="tbl">
        <thead><tr><th>BSSID</th><th>SSID</th><th>CH</th><th>RSSI</th><th>SIG</th><th>LAST SEEN</th></tr></thead>
        <tbody id="kApT"><tr><td colspan="6" style="color:#1e293b;text-align:center;padding:12px">Start Kismet to discover APs</td></tr></tbody>
      </table>
    </div>
    <div class="g sp">
      <div class="ct">PROBE REQUESTS (HIDDEN SSID DISCOVERY)</div>
      <table class="tbl">
        <thead><tr><th>CLIENT MAC</th><th>PROBED SSID</th><th>LAST SEEN</th></tr></thead>
        <tbody id="kProbeT"><tr><td colspan="3" style="color:#1e293b;text-align:center;padding:12px">No probes captured yet</td></tr></tbody>
      </table>
    </div>
  </div>
</div>

<!-- ══ PMKID ══ -->
<div class="page" id="pmkidPage">
  <div class="warn-box">⚠ AUTHORIZED LAB USE ONLY. PMKID capture for WPA2 offline analysis. Only use on your own network or with explicit written authorization.</div>
  <div class="g sp mb">
    <div class="ct">🔑 PMKID CAPTURE — WPA2 4-WAY HANDSHAKE SNIFFER</div>
    <div style="display:flex;gap:7px;align-items:center;margin-bottom:10px;flex-wrap:wrap">
      <button class="btn bm" id="pmkBtn" onclick="togPMKID()" style="width:auto;margin:0;padding:7px 16px">▶ START CAPTURE</button>
      <span id="pmkSt" style="font-size:.58rem;color:var(--dm);letter-spacing:2px"></span>
    </div>
    <table class="tbl">
      <thead><tr><th>AP BSSID</th><th>CLIENT MAC</th><th>PMKID HASH</th><th>CAPTURED AT</th></tr></thead>
      <tbody id="pmkT"><tr><td colspan="4" style="color:#1e293b;text-align:center;padding:14px">No PMKID captured yet</td></tr></tbody>
    </table>
  </div>
</div>

<!-- ══ RF INTEL ══ -->
<div class="page" id="deauthPage">
  <div class="grid">
    <div class="g">
      <div class="ct">🛡️ DEAUTH DETECTOR</div>
      <div style="padding:12px 0 8px">
        <div class="dan" id="dCnt">0</div>
        <div class="dal">DEAUTH / DISASSOC FRAMES</div>
        <div class="daa" id="dAlert">⚠ ATTACK DETECTED</div>
      </div>
      <div class="ir"><span>LAST SOURCE MAC</span><span id="dMac" style="color:rgba(255,107,107,.6);font-size:.58rem">—</span></div>
      <div class="ir nb"><span>SCANNING CH</span><span id="dChan">—</span></div>
      <button class="btn bo" id="dBtn" onclick="togDeauth()">▶ START MONITORING</button>
    </div>
    <div class="g">
      <div class="ct">📊 CHANNEL CONGESTION MAP</div>
      <div style="display:flex;gap:7px;margin-bottom:6px">
        <button class="btn bm" onclick="scanCh()" style="width:auto;margin:0;padding:6px 14px">▶ SCAN</button>
        <span id="chSt" style="font-size:.58rem;color:var(--dm);letter-spacing:2px;align-self:center"></span>
      </div>
      <canvas id="chCv"></canvas>
      <div class="ir" style="margin-top:5px"><span>BEST CHANNEL</span><span id="bestCh" class="badge bm2">—</span></div>
    </div>
    <div class="g">
      <div class="ct">🌊 BEACON FLOOD MONITOR</div>
      <div style="text-align:center;padding:10px 0">
        <div style="font-family:'Syne',sans-serif;font-size:2.5rem;font-weight:800;color:var(--or)" id="bfCnt">0</div>
        <div style="font-size:.52rem;color:var(--dm);letter-spacing:3px;margin-top:2px">BEACONS / 2s WINDOW</div>
        <div id="bfAlert" style="font-size:.6rem;color:var(--rd);letter-spacing:2px;margin-top:6px;display:none;animation:blink 1s infinite">⚠ BEACON FLOOD DETECTED</div>
      </div>
      <div class="ir nb"><span>FLOOD SSID</span><span id="bfSSID" style="color:rgba(251,191,36,.7);font-size:.58rem">—</span></div>
    </div>
    <div class="g">
      <div class="ct">👁️ EVIL TWIN DETECTOR</div>
      <p style="font-size:.6rem;color:var(--dm);line-height:1.8;margin-bottom:8px">Detects duplicate SSIDs with different BSSIDs — classic evil twin attack signature.</p>
      <button class="btn bm" onclick="detectEvilTwin()" style="width:auto;margin:0;padding:6px 14px">▶ DETECT</button>
      <div id="etResults" style="font-size:.6rem;color:var(--dm);margin-top:8px">Run a WiFi scan first, then detect.</div>
    </div>
  </div>
</div>

<!-- ══ RECON ══ -->
<div class="page" id="reconPage">
  <div class="g sp mb">
    <div class="ct">🕵️ CLIENT RECON — IP · MAC · VENDOR · PORTS · AGE</div>
    <div style="display:flex;gap:7px;align-items:center;margin-bottom:10px;flex-wrap:wrap">
      <button class="btn bo" id="rBtn" onclick="doRecon()">▶ SCAN CLIENTS</button>
      <span id="rSt" style="font-size:.58rem;color:var(--dm);letter-spacing:2px"></span>
    </div>
    <table class="tbl">
      <thead><tr><th>VENDOR</th><th>IP</th><th>MAC</th><th>OPEN PORTS</th><th>CONN AGE</th></tr></thead>
      <tbody id="rT"><tr><td colspan="5" style="color:#1e293b;text-align:center;padding:14px">No scan yet</td></tr></tbody>
    </table>
  </div>
</div>

<!-- ══ CHAT ══ -->
<div class="page" id="chatPage">
  <div style="display:flex;flex-direction:column;height:calc(100vh - 215px);min-height:360px" id="chatInner">
    <div style="background:rgba(33,25,81,.5);backdrop-filter:blur(20px);border:1px solid var(--bd2);
      border-radius:13px 13px 0 0;padding:10px 14px;display:flex;align-items:center;justify-content:space-between">
      <span style="font-family:'Syne',sans-serif;font-size:.6rem;letter-spacing:4px;color:var(--dm)">AXIOM LAN CHAT</span>
      <div style="display:flex;gap:8px">
        <span id="onl" style="font-size:.52rem;color:rgba(21,245,186,.3);letter-spacing:2px">0 ONLINE</span>
        <span class="pill p-off" id="wsp">OFFLINE</span>
      </div>
    </div>
    <div id="cMsgs" style="flex:1;background:rgba(0,0,0,.3);border-left:1px solid var(--bd);
      border-right:1px solid var(--bd);padding:11px;overflow-y:auto;min-height:180px;
      scrollbar-width:thin;scrollbar-color:var(--bd) transparent">
      <div style="text-align:center;font-size:.52rem;color:rgba(255,255,255,.12);letter-spacing:2px;margin:6px 0">— AXIOM LOCAL NETWORK —</div>
    </div>
    <div style="display:flex;gap:5px;background:rgba(33,25,81,.5);backdrop-filter:blur(20px);
      border:1px solid var(--bd2);border-radius:0 0 13px 13px;padding:8px">
      <input id="nIn" type="text" placeholder="NAME" maxlength="16" style="width:85px;background:rgba(0,0,0,.3);
        border:1px solid var(--bd);border-radius:7px;padding:6px 9px;color:var(--tx);
        font-family:'Space Mono',monospace;font-size:.68rem;outline:none;color:#64748b"/>
      <input id="mIn" type="text" placeholder="Message..." maxlength="200" style="flex:1;background:rgba(0,0,0,.3);
        border:1px solid var(--bd);border-radius:7px;padding:6px 9px;color:var(--tx);
        font-family:'Space Mono',monospace;font-size:.68rem;outline:none"
        onkeydown="if(event.key==='Enter')sChat()"/>
      <button onclick="sChat()" style="background:rgba(21,245,186,.12);border:1px solid rgba(21,245,186,.28);
        color:var(--v2);border-radius:7px;padding:6px 13px;font-family:'Space Mono',monospace;
        font-size:.58rem;cursor:pointer;letter-spacing:2px">SEND ↵</button>
    </div>
  </div>
</div>

<!-- ══ SYSTEM ══ -->
<div class="page" id="systemPage">
  <div class="grid">
    <div class="g">
      <div class="ct">ESP32-S3 INFO</div>
      <div class="ir"><span>UPTIME</span><span id="upt">—</span></div>
      <div class="ir"><span>FREE HEAP</span><span id="hp">—</span></div>
      <div class="ir"><span>CHIP TEMP</span><span id="tmp">—</span></div>
      <div class="ir"><span>CPU FREQ</span><span id="cpu">—</span></div>
      <div class="ir"><span>FLASH</span><span id="fl">—</span></div>
      <div class="ir"><span>PSRAM</span><span id="ps">—</span></div>
      <div class="ir"><span>CHIP ID</span><span id="cid">—</span></div>
      <div class="ir nb"><span>AP CLIENTS</span><span id="sCl">—</span></div>
    </div>
    <div class="g">
      <div class="ct">RESOURCE GAUGES</div>
      <div class="gr"><span style="font-size:.55rem;color:var(--dm);width:50px">HEAP</span>
        <div class="gb"><div class="gf" id="hBar" style="width:0%;background:linear-gradient(90deg,var(--v3),var(--v2))"></div></div>
        <span id="hPct" style="font-size:.52rem;color:var(--dm);width:30px;text-align:right">0%</span></div>
      <div class="gr"><span style="font-size:.55rem;color:var(--dm);width:50px">TEMP</span>
        <div class="gb"><div class="gf" id="tBar" style="width:0%;background:linear-gradient(90deg,var(--or),var(--rd))"></div></div>
        <span id="tPct" style="font-size:.52rem;color:var(--dm);width:30px;text-align:right">—</span></div>
    </div>
    <div class="g">
      <div class="ct">CPU SCALING</div>
      <div class="fld"><label>FREQUENCY</label>
        <select id="cpuF">
          <option value="240">240 MHz — Max Performance</option>
          <option value="160">160 MHz — Balanced</option>
          <option value="80">80 MHz — Low Power</option>
          <option value="40">40 MHz — Minimal</option>
        </select></div>
      <button class="btn bm" onclick="setCPU()">⚡ APPLY</button>
    </div>
    <div class="g">
      <div class="ct">SLEEP + REBOOT</div>
      <div class="fld"><label>DEEP SLEEP WAKE AFTER (s)</label>
        <input type="number" id="slpS" value="30" min="5" max="3600"/></div>
      <div id="slpCd" style="font-family:'Syne',sans-serif;font-size:2.2rem;font-weight:800;color:var(--or);text-align:center;display:none;padding:8px 0"></div>
      <button class="btn bo" onclick="doSleep()">😴 DEEP SLEEP</button>
      <button class="btn br" style="margin-top:5px" onclick="doReboot()">⟳ REBOOT</button>
    </div>
  </div>
</div>

<!-- ══ DATA PANEL ══ -->
<div class="page" id="datapanelPage">
  <div class="grid">
    <div class="g sp">
      <div class="ct">REST DATA ENDPOINTS (192.168.4.1)
        <span id="dpStatus" class="pill p-on" style="margin-left:auto">LIVE TELEMETRY</span>
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px">
        <button class="btn bm" onclick="fetchApiData('/data')" style="width:auto;margin:0;padding:6px 14px">⚡ GET /data</button>
        <button class="btn bv" onclick="fetchApiData('/gpio')" style="width:auto;margin:0;padding:6px 14px">🔌 GET /gpio</button>
        <button class="btn bv" onclick="fetchApiData('/wifi')" style="width:auto;margin:0;padding:6px 14px">📡 GET /wifi</button>
        <button class="btn bv" onclick="fetchApiData('/bluetooth')" style="width:auto;margin:0;padding:6px 14px">🔵 GET /bluetooth</button>
        <button class="btn bo" onclick="fetchApiData('/status?full=1')" style="width:auto;margin:0;padding:6px 14px">🔧 GET /status</button>
        <button class="btn bo" onclick="fetchApiData('/recon')" style="width:auto;margin:0;padding:6px 14px">🕵️ GET /recon</button>
        <a href="/data" target="_blank" class="btn br" style="width:auto;margin:0;padding:6px 14px;text-decoration:none;display:inline-block">↗ OPEN /data IN TAB</a>
      </div>

      <!-- Live JSON Inspector Box -->
      <div style="background:rgba(0,0,0,0.6);border:1px solid var(--bd2);border-radius:10px;padding:12px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
          <span style="font-size:.6rem;color:var(--v2);letter-spacing:2px" id="apiEndpointTitle">ENDPOINT: /data</span>
          <div style="display:flex;gap:6px">
            <button onclick="autoRefreshToggle()" id="autoRefBtn" class="pill p-v" style="cursor:pointer">AUTO REFRESH: ON</button>
            <span id="apiStatusBadge" class="badge bm2">200 OK</span>
          </div>
        </div>
        <pre id="jsonViewer" style="background:#090611;color:#15F5BA;padding:12px;border-radius:8px;font-size:.6rem;line-height:1.45;max-height:340px;overflow:auto;white-space:pre-wrap;word-break:break-all;border:1px solid rgba(21,245,186,0.15)">Loading telemetry...</pre>
      </div>
    </div>

    <!-- Telemetry Cards -->
    <div class="g">
      <div class="ct">SYSTEM & MEMORY</div>
      <div class="ir"><span>UPTIME</span><span id="dpUpt">—</span></div>
      <div class="ir"><span>FREE HEAP</span><span id="dpHeap">—</span></div>
      <div class="ir"><span>CPU FREQ</span><span id="dpCpu">—</span></div>
      <div class="ir"><span>TEMPERATURE</span><span id="dpTemp">—</span></div>
      <div class="ir nb"><span>CHIP ID</span><span id="dpChip">—</span></div>
    </div>

    <div class="g">
      <div class="ct">WIFI REST TELEMETRY</div>
      <div class="ir"><span>AP SSID</span><span id="dpApSsid">—</span></div>
      <div class="ir"><span>AP CLIENTS</span><span id="dpApClients">—</span></div>
      <div class="ir"><span>STA MODE</span><span id="dpStaSt">—</span></div>
      <div class="ir"><span>STA IP</span><span id="dpStaIp">—</span></div>
      <div class="ir nb"><span>STA RSSI</span><span id="dpStaRssi">—</span></div>
    </div>

    <div class="g">
      <div class="ct">BLUETOOTH TELEMETRY</div>
      <div class="ir"><span>BLE SCANNER</span><span id="dpBleSt">—</span></div>
      <div class="ir"><span>DEVICES FOUND</span><span id="dpBleDevs">—</span></div>
      <div class="ir nb"><span>LAST SCANNER TS</span><span id="dpBleTs">—</span></div>
    </div>

    <div class="g sp">
      <div class="ct">GPIO LIVE TELEMETRY MATRIX</div>
      <div id="dpGpioMatrix" class="gpio-grid"></div>
    </div>
  </div>
</div>

<!-- ══ DISPLAY ══ -->
<div class="page" id="displayPage">
  <div class="grid">
    <div class="g sp">
      <div class="ct">OLED — SH1106 1.3" (SPI)</div>
      <div class="ir"><span>CURRENT PAGE</span><span id="oledPg">—</span></div>
      <div class="ct" style="margin-top:12px">JUMP TO PAGE</div>
      <div class="gpio-grid" id="oledPages"></div>
      <div class="row" style="margin-top:12px">
        <span>AUTO REFRESH</span>
        <button class="btn" style="width:auto;margin:0;padding:4px 12px" id="refreshBtn" onclick="toggleOledRefresh()">…</button>
      </div>
      <div class="row">
        <span>AUTO CYCLE</span>
        <button class="btn" style="width:auto;margin:0;padding:4px 12px" id="cycleBtn" onclick="toggleOledCycle()">…</button>
      </div>
      <div class="row" style="margin-top:12px;">
        <span>NAV</span>
        <div style="display:grid;grid-template-columns:48px 48px 48px;gap:6px;justify-content:center;margin-top:8px">
          <div></div>
          <button class="btn nav-btn" onclick="oledUp()">▲</button>
          <div></div>

          <button class="btn nav-btn" onclick="oledPrev()">◀</button>
          <button class="btn nav-btn" onclick="oledGoto(0)" id="oledHome">OK</button>
          <button class="btn nav-btn" onclick="oledNext()">▶</button>

          <div></div>
          <button class="btn nav-btn" onclick="oledDown()">▼</button>
          <div></div>
        </div>
      </div>
    </div>
  </div>
</div>

</div><!-- /shell -->
<footer>AXIOM · CYBER INTELLIGENCE CONTROLLER · v8.0 · ESP32-S3</footer>

<!-- CONNECT MODAL -->
<div class="mbg" id="cModal">
  <div class="modal">
    <h3>🔗 CONNECT TO NETWORK</h3>
    <div class="fld"><label>SSID</label><input type="text" id="mSSID" readonly style="color:rgba(21,245,186,.6)"/></div>
    <div class="fld"><label>PASSWORD</label><input type="password" id="mPw" placeholder="Enter password..."/></div>
    <span id="mSt"></span>
    <div class="mbns">
      <button class="btn bm" onclick="doConn()">CONNECT</button>
      <button class="btn br" onclick="closeM()">CANCEL</button>
    </div>
  </div>
</div>

<script>
// ── ANIMATED BG ───────────────────────────────────────────────────────────────
(()=>{
  const cv=document.getElementById('bg'),ctx=cv.getContext('2d');
  let W,H,pts=[];const N=55;
  function resize(){W=cv.width=innerWidth;H=cv.height=innerHeight;
    pts=Array.from({length:N},()=>({x:Math.random()*W,y:Math.random()*H,vx:(Math.random()-.5)*.25,vy:(Math.random()-.5)*.25}));}
  addEventListener('resize',resize);resize();
  function draw(){
    ctx.clearRect(0,0,W,H);
    ctx.strokeStyle='rgba(131,111,255,0.025)';ctx.lineWidth=1;
    for(let x=0;x<W;x+=65){ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,H);ctx.stroke();}
    for(let y=0;y<H;y+=65){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(W,y);ctx.stroke();}
    pts.forEach(p=>{p.x+=p.vx;p.y+=p.vy;if(p.x<0||p.x>W)p.vx*=-1;if(p.y<0||p.y>H)p.vy*=-1;
      ctx.beginPath();ctx.arc(p.x,p.y,1.1,0,Math.PI*2);
      ctx.fillStyle='rgba(131,111,255,0.3)';ctx.fill();});
    for(let i=0;i<N;i++)for(let j=i+1;j<N;j++){
      const d=Math.hypot(pts[i].x-pts[j].x,pts[i].y-pts[j].y);
      if(d<95){ctx.beginPath();ctx.moveTo(pts[i].x,pts[i].y);ctx.lineTo(pts[j].x,pts[j].y);
        ctx.strokeStyle=`rgba(131,111,255,${.06*(1-d/95)})`;ctx.lineWidth=.5;ctx.stroke();}}
    requestAnimationFrame(draw);}
  draw();
})();

let selNet='',selEnc=false;

// ── GPIO GRID ─────────────────────────────────────────────────────────────────
const OUT_PINS=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,17,18,21,38,39,40,41,42,45,46];
const ADC_PINS=[1,2,3,4,5,6,7,8,9,10];
const gpioState={};
function buildGPIOGrid(){
  const g=document.getElementById('gpioGrid');g.innerHTML='';
  OUT_PINS.forEach(p=>{
    gpioState[p]=false;
    const isADC=ADC_PINS.includes(p);
    const d=document.createElement('div');
    d.className='gpio-btn off'+(isADC?' adc':'');
    d.id='gp'+p;
    d.innerHTML=`<span class="gn">GPIO ${p}</span><span class="gs">LOW</span>`;
    d.onclick=()=>toggleGPIO(p);
    g.appendChild(d);
  });}
// Populate current states and mark pins that are reserved/active by peripherals
function refreshGPIOGrid(){
  fetch('/gpio').then(r=>r.json()).then(d=>{
    if(!d.outPins) return;
    d.outPins.forEach(o=>{
      const el=document.getElementById('gp'+o.pin);
      if(!el) return;
      // state
      el.className='gpio-btn '+(o.state?'on':'off')+(ADC_PINS.includes(o.pin)?' adc':'');
      el.querySelector('.gs').textContent=o.state?'HIGH':'LOW';
      gpioState[o.pin]=o.state;
      // reserved/in-use
      if(o.inUse){
        el.classList.add('inuse');
        el.title='Reserved (hardware in use)';
        // disable clicks to prevent accidental writes
        el.onclick=null;
      }
    });
  }).catch(()=>{});
}
buildGPIOGrid();
refreshGPIOGrid();
function toggleGPIO(pin){
  fetch('/gpio/pin?pin='+pin+'&state='+(gpioState[pin]?0:1))
    .then(r=>r.json()).then(d=>{
      gpioState[pin]=d.state;
      const el=document.getElementById('gp'+pin);
      el.className='gpio-btn '+(d.state?'on':'off')+(ADC_PINS.includes(pin)?' adc':'');
      el.querySelector('.gs').textContent=d.state?'HIGH':'LOW';
      addLog('GPIO '+pin+' → '+(d.state?'HIGH':'LOW'));
    });}
buildGPIOGrid();

// ── UTILS ─────────────────────────────────────────────────────────────────────
const $=id=>document.getElementById(id);
function set(id,v){const e=$(id);if(e)e.textContent=v;}
function xss(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function escJ(s){return String(s).replace(/\\/g,'\\\\').replace(/'/g,"\\'")}
function sig(r,c='sv'){const p=Math.min(100,Math.max(0,(r+100)*2));
  return`<span class="sig ${c}" style="width:${Math.max(3,Math.round(p*.42))}px;opacity:${.3+p/140}"></span>`;}
function sigBars(rssi){const p=Math.min(100,Math.max(0,(rssi+100)*2));const b=Math.round(p/25);
  return`<div class="sigs">${[1,2,3,4].map(i=>`<div class="sb ${i<=b?'on':''}" style="height:${i*3+2}px"></div>`).join('')}</div>`;}
function addLog(msg,cls=''){const l=$('evtLog');const ph=l.querySelector('span');if(ph)ph.remove();
  const t=new Date().toTimeString().slice(0,8);const e=document.createElement('div');
  e.className='le '+cls;e.textContent='['+t+'] '+msg;l.appendChild(e);l.scrollTop=l.scrollHeight;}

// ── PAGE SWITCH ───────────────────────────────────────────────────────────────
function P(n,el){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  $(n+'Page').classList.add('active');
  if(el)el.classList.add('active');
  // Chat WS on demand
  if(n==='chat' && !ws) initWS();
  if(n==='datapanel') fetchApiData('/data');
}

// ── FAST POLL (1s) — lightweight status ──────────────────────────────────────
// Only fetches what changes frequently: heap, temp, uptime, sta, cyber counters
// Full poll every 5s fetches GPIO, touch, etc.
let pollCycle=0;
const OLED_PAGES=['HOME','WIFI','SNIFFER','KISMET','PMKID','GPIO','RFINTEL','RECON','SYSTEM','CHAT'];
function poll(){
  pollCycle++;
  const url = (pollCycle%5===0) ? '/status?full=1' : '/status';
  fetch(url).then(r=>r.json()).then(d=>{
    // Always update
    const s=Math.floor(d.uptime/1000),m=Math.floor(s/60),h=Math.floor(m/60);
    set('upt',h+'h '+(m%60)+'m '+(s%60)+'s');
    set('hp',(d.heap/1024).toFixed(1)+' KB');
    set('tmp',d.temp.toFixed(1)+' °C');
    set('cpu',d.cpu+' MHz');
    set('sCl',d.clients);
    // Piggyback OLED page sync on the existing 1s poll instead of a
    // dedicated interval — avoids adding synchronized extra WiFi traffic.
    if(d.oledPage!==undefined){
      set('oledPg',OLED_PAGES[d.oledPage]);
      highlightOledPage(d.oledPage);
      if(oledCycleOn!==d.oledCycle) setCycleBtn(d.oledCycle);
    }
    const hp=Math.round((1-d.heap/(320*1024))*100);
    $('hBar').style.width=hp+'%';set('hPct',hp+'%');
    const tp=Math.min(100,Math.round((d.temp-20)/70*100));
    $('tBar').style.width=tp+'%';set('tPct',d.temp.toFixed(0)+'°C');

    // STA
    const connected=d.sta==='connected';
    const natToggle=$('natToggle');
    if(d.napt!==undefined){
      natToggle.classList.toggle('on',!!d.napt);
      set('natSt',d.napt?'ENABLED':'DISABLED');
      $('natSt').style.color=d.napt?'var(--v2)':'var(--dm)';
    }
    const stP=$('staPill');
    if(connected){
      stP.style.display='block';stP.className='pill p-on';stP.textContent='STA: '+(d.staSSID||'');
      $('staSt').innerHTML='<span class="badge bm2">CONNECTED</span>';
      set('staS',d.staSSID||'—');set('staI',d.staIp||'—');set('staR',d.staRSSI+' dBm');
      $('wBridge').className='pill p-on';$('wBridge').textContent='STA ON';
      $('discBtn').style.display='block';
      $('sbSt').className='stv g';$('sbSt').textContent='CONNECTED';
      set('sbIP',d.staIp||'—');set('sbNet',d.staSSID||'—');
    } else {
      stP.style.display='none';
      $('staSt').innerHTML='<span class="badge bx2">'+(d.sta||'—').toUpperCase()+'</span>';
      set('staS','—');set('staI','—');set('staR','—');
      $('wBridge').className='pill p-off';$('wBridge').textContent='STA OFF';
      $('discBtn').style.display='none';
      if(d.sta==='connecting'){$('sbSt').className='stv o';$('sbSt').textContent='CONNECTING...';}
      else if(d.sta==='failed'){$('sbSt').className='stv r';$('sbSt').textContent='FAILED';}
      else{$('sbSt').className='stv';$('sbSt').textContent='IDLE';}
      set('sbIP','—');
    }

    // Cyber counters
    set('dCnt',d.deauth||0);set('dMac',d.deauthMac||'—');set('dChan','CH '+(d.deauthChan||1));
    if($('dAlert'))$('dAlert').style.display=(d.deauth>0)?'block':'none';
    set('bfCnt',d.beaconCnt||0);set('bfSSID',d.beaconSSID||'—');
    if($('bfAlert'))$('bfAlert').style.display=(d.beaconCnt>50)?'block':'none';
    const cyberOn=d.snifferOn||d.kismetOn||d.pmkidOn||d.deauthOn;
    $('cyberPill').style.display=cyberOn?'block':'none';

    // Full poll extras (every 5s)
    if(d.flash!==undefined){
      set('fl',(d.flash/1024/1024).toFixed(0)+' MB');
      set('ps',d.psram?(d.psram/1024/1024).toFixed(0)+' MB':'N/A');
      set('cid',d.chipId);
    }
    if(d.inputs){['in0','in1'].forEach((id,i)=>{const e=$(id);if(!e)return;e.textContent=d.inputs[i]?'HIGH':'LOW';e.className='badge '+(d.inputs[i]?'bm2':'bx2');});}
    if(d.pwm){for(let i=0;i<3;i++) set('d'+i,d.pwm[i]);}
    if(d.touch){for(let i=0;i<2;i++){set('tv'+i,d.touch[i]);$('tc'+i).className='torb'+(d.touchActive[i]?' on':'');}}
  }).catch(()=>{});}
poll();setInterval(poll,1000);  // 1s poll — much snappier

// ── WIFI ──────────────────────────────────────────────────────────────────────
let lastNets=[];
function wScan(){
  $('wSB').disabled=true;set('wSS','SCANNING...');
  fetch('/wifi/scan')
    .then(()=>setTimeout(wRes,5500))
    .catch(()=>{ $('wSB').disabled=false; set('wSS','Scan failed'); });
}
function wRes(){fetch('/wifi/results').then(r=>r.json()).then(d=>{
  if(d.status==='scanning'){setTimeout(wRes,1500);return;}
  $('wSB').disabled=false;set('wSS',d.networks.length+' FOUND');lastNets=d.networks;
  const nl=$('netList');
  if(!d.networks.length){nl.innerHTML='<div style="color:var(--dm);font-size:.62rem;text-align:center;padding:14px">No networks found</div>';return;}
  nl.innerHTML=d.networks.map(n=>`
    <div class="net-item" onclick="selNetwork(this,'${escJ(n.ssid)}',${n.enc},${n.rssi})">
      <div><div class="net-n">${xss(n.ssid)||'<em style="color:var(--dm)">Hidden</em>'}</div>
        <div style="font-size:.52rem;color:var(--dm);margin-top:2px">CH ${n.channel} · ${n.rssi} dBm · ${n.enc?'🔒 WPA':'🔓 OPEN'}</div></div>
      <div class="net-m">${sigBars(n.rssi)}<span style="font-size:.52rem;color:var(--dm)">${n.rssi} dBm</span></div>
    </div>`).join('');})}

function selNetwork(el, ssid, enc, rssi){
  selNet=ssid;selEnc=enc;
  document.querySelectorAll('.net-item').forEach(e=>e.classList.remove('sel'));
  if(el && el.classList) el.classList.add('sel');
  set('sbNet',ssid);set('sbSig',rssi+' dBm');
  openM(ssid);$('mPw').value='';
}
function openM(s){$('mSSID').value=s;$('mPw').value='';$('mSt').textContent='';$('cModal').classList.add('show');setTimeout(()=>$('mPw').focus(),100);}
function closeM(){$('cModal').classList.remove('show');}
function doConn(){
  const st=$('mSt');st.textContent='Connecting...';st.style.color='var(--or)';
  fetch('/wifi/connect',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'ssid='+encodeURIComponent($('mSSID').value)+'&pass='+encodeURIComponent($('mPw').value)})
  .then(r=>r.json()).then(d=>{
    if(d.status==='connecting'){st.textContent='Sent!';st.style.color='rgba(21,245,186,.5)';
      set('sbNet',$('mSSID').value);$('sbSt').className='stv o';$('sbSt').textContent='CONNECTING...';
      setTimeout(closeM,6000);}
    else{st.textContent='Error: '+d.msg;st.style.color='var(--rd)';}});}
function wDisc(){if(!confirm('Disconnect?'))return;fetch('/wifi/disconnect').then(()=>{addLog('Disconnected','w');set('sbSt','IDLE');set('sbIP','—');});}
function toggleNatBridge(){
  const enabled=$('natToggle').classList.contains('on');
  fetch('/wifi/nat?on='+(enabled?0:1)).then(r=>r.json().then(d=>({ok:r.ok,data:d}))).then(v=>{
    if(!v.ok){set('natSt',v.data.msg||'NAT TOGGLE FAILED');$('natSt').style.color='var(--rd)';return;}
    $('natToggle').classList.toggle('on',!!v.data.enabled);
    set('natSt',v.data.enabled?'ENABLED':'DISABLED');
    $('natSt').style.color=v.data.enabled?'var(--v2)':'var(--dm)';
  }).catch(()=>{set('natSt','NAT TOGGLE FAILED');$('natSt').style.color='var(--rd)';});
}

// ── OLED DISPLAY ──────────────────────────────────────────────────────────────
function buildOledPages(){
  $('oledPages').innerHTML=OLED_PAGES.map((n,i)=>
    `<button class="gpio-btn oled-pg-btn" data-pg="${i}" onclick="oledGoto(${i})"><span class="gn">${n}</span></button>`).join('');
}
function highlightOledPage(id){
  document.querySelectorAll('.oled-pg-btn').forEach(b=>b.classList.toggle('on',+b.dataset.pg===id));
}
let oledRefreshOn=false;
function setRefreshBtn(on){
  oledRefreshOn=on;
  const b=$('refreshBtn');
  b.textContent=on?'ON':'OFF';
  b.style.color=on?'var(--v2)':'var(--dm)';
  b.style.borderColor=on?'var(--v2)':'';
}
function toggleOledRefresh(){
  fetch('/display/refresh?on='+(oledRefreshOn?0:1)).then(r=>r.json()).then(d=>setRefreshBtn(d.refresh));
}
let oledCycleOn=false;
function setCycleBtn(on){
  oledCycleOn=on;
  const b=$('cycleBtn');
  b.textContent=on?'ON':'OFF';
  b.style.color=on?'var(--v2)':'var(--dm)';
  b.style.borderColor=on?'var(--v2)':'';
  // No dedicated poll while cycling — /status already runs every 1s and
  // now carries oledPage/oledCycle, so we piggyback there (see poll())
  // instead of adding a second synchronized request every 3s, which was
  // what caused the OLED SPI draw and a WiFi TX to collide on schedule.
}
function toggleOledCycle(){
  fetch('/display/cycle?on='+(oledCycleOn?0:1)).then(r=>r.json()).then(d=>setCycleBtn(d.cycle));
}
function oledGoto(id){
  fetch('/display/page?id='+id).then(r=>r.json()).then(d=>{set('oledPg',d.name);highlightOledPage(d.page);setCycleBtn(d.cycle);})
    .catch(()=>{setTimeout(()=>oledGoto(id),800);});  // WiFi hiccup during radio burst — retry once
}
function oledPrev(){fetch('/status').then(r=>r.json()).then(d=>oledGoto((d.oledPage-1+OLED_PAGES.length)%OLED_PAGES.length));}
function oledNext(){fetch('/status').then(r=>r.json()).then(d=>oledGoto((d.oledPage+1)%OLED_PAGES.length));}
function oledUp(){fetch('/display/scroll?dir=up').then(r=>r.json()).then(d=>{set('oledPg',d.name);highlightOledPage(d.page);});}
function oledDown(){fetch('/display/scroll?dir=down').then(r=>r.json()).then(d=>{set('oledPg',d.name);highlightOledPage(d.page);});}
buildOledPages();
// Init display navigation (keyboard arrows + long-press repeat)
function initDisplayNav(){
  const btns = document.querySelectorAll('.nav-btn');
  btns.forEach(b=>{
    let holdTimer=0, repeatId=0;
    const act = ()=>{ try{ b.onclick && b.onclick(); }catch(e){} };
    b.addEventListener('mousedown', e=>{ holdTimer = setTimeout(()=>{ act(); repeatId = setInterval(act,200); },400); });
    b.addEventListener('touchstart', e=>{ e.preventDefault(); holdTimer = setTimeout(()=>{ act(); repeatId = setInterval(act,200); },400); },{passive:false});
    const clear = ()=>{ if(holdTimer){clearTimeout(holdTimer); holdTimer=0;} if(repeatId){clearInterval(repeatId); repeatId=0;} };
    b.addEventListener('mouseup', clear); b.addEventListener('mouseleave', clear); b.addEventListener('touchend', clear); b.addEventListener('touchcancel', clear);
  });
  // keyboard arrows
  const keys = {};
  window.addEventListener('keydown', e=>{
    if(e.repeat) return; // ignore held auto-repeat — we handle long-press manually
    if(e.key==='ArrowLeft') { oledPrev(); keys['ArrowLeft']=true; }
    else if(e.key==='ArrowRight') { oledNext(); keys['ArrowRight']=true; }
    else if(e.key==='ArrowUp') { oledUp(); keys['ArrowUp']=true; }
    else if(e.key==='ArrowDown') { oledDown(); keys['ArrowDown']=true; }
    else if(e.key==='Enter') { oledGoto(0); }
  });
}
initDisplayNav();
fetch('/display/status').then(r=>r.json()).then(d=>{set('oledPg',d.name);highlightOledPage(d.page);setRefreshBtn(d.refresh);setCycleBtn(d.cycle);}).catch(()=>{});

// ── LED ───────────────────────────────────────────────────────────────────────
function setLED(r,g,b){fetch('/led?r='+r+'&g='+g+'&b='+b).then(()=>addLog('LED → rgb('+r+','+g+','+b+')','g'));}

// ── GPIO ──────────────────────────────────────────────────────────────────────
// Debounced PWM setter to avoid flooding server and OLED redraws while sliding
const _pwmTimers = {};
function setPWM(ch,v){
  set('d'+ch,v); // update UI immediately
  // clear existing timer for this channel
  if(_pwmTimers[ch]) clearTimeout(_pwmTimers[ch]);
  // schedule send after user stops moving the slider for 250ms
  _pwmTimers[ch] = setTimeout(()=>{
    fetch('/gpio/pwm?ch='+ch+'&duty='+v).then(()=>{ delete _pwmTimers[ch]; }).catch(()=>{ delete _pwmTimers[ch]; });
  },250);
}
function togPWM(ch){fetch('/gpio/pwmmode?ch='+ch).then(r=>r.json()).then(d=>{
  const b=$('pm'+ch);b.textContent=d.pwm?'DISABLE PWM':'ENABLE PWM';
  b.className=d.pwm?'btn bm':'btn bv';addLog('GPIO '+(ch+4)+' → '+(d.pwm?'PWM':'DIGITAL'));});}

// ── BLE ───────────────────────────────────────────────────────────────────────
function bScan(){$('bSB').disabled=true;set('bSS','SCANNING 6s...');fetch('/ble/scan').then(()=>setTimeout(bRes,7000));}
function bRes(){fetch('/ble/results').then(r=>r.json()).then(d=>{
  if(d.status==='scanning'){setTimeout(bRes,1000);return;}
  $('bSB').disabled=false;set('bSS',d.devices.length+' FOUND');
  const tb=$('bT');
  if(!d.devices.length){tb.innerHTML='<tr><td colspan="5" style="color:#1e293b;text-align:center;padding:14px">No BLE devices</td></tr>';return;}
  tb.innerHTML=d.devices.map(v=>`<tr><td>${xss(v.n)}</td><td style="font-size:.56rem;color:#334155">${v.a}</td>
    <td>${v.m?'<span class="badge bv2">'+xss(v.m)+'</span>':'<span style="color:#334155">—</span>'}</td>
    <td>${v.r} dBm</td><td>${sig(v.r,'sv')}</td></tr>`).join('');})}

// ── SNIFFER ───────────────────────────────────────────────────────────────────
let snifOn=false,pktMgmt=0,pktData=0,pktCtrl=0,snifPoll=null;
function togSniffer(){
  snifOn=!snifOn;
  const ch=parseInt($('chanSel').value)||0;
  fetch('/sniffer?active='+snifOn+'&ch='+ch).then(r=>r.json()).then(d=>{
    $('snifBtn').textContent=snifOn?'■ STOP CAPTURE':'▶ START CAPTURE';
    $('snifBtn').className=snifOn?'btn br':'btn bm';
    set('snifSt',snifOn?'CAPTURING...':'STOPPED');
    if(snifOn){snifPoll=setInterval(fetchPkts,800);}
    else{clearInterval(snifPoll);}});}
function clearPkts(){pktMgmt=0;pktData=0;pktCtrl=0;set('pktTotal',0);set('pktMgmt',0);set('pktData',0);set('pktCtrl',0);
  $('pktLog').innerHTML='<span style="color:#1e293b">Cleared.</span>';
  fetch('/sniffer/clear');}
function setHop(v){fetch('/sniffer/hop?v='+v);}
function fetchPkts(){
  fetch('/sniffer/log').then(r=>r.json()).then(d=>{
    if(!d.pkts||!d.pkts.length)return;
    const log=$('pktLog');const ph=log.querySelector('span');if(ph)ph.remove();
    d.pkts.forEach(p=>{
      const e=document.createElement('div');
      let cls='pk-m';
      if(p.t===2)cls='pk-d';else if(p.t===1)cls='pk-c';else if(p.t===3)cls='pk-x';
      if(p.t===0)pktMgmt++;else if(p.t===2)pktData++;else if(p.t===1)pktCtrl++;
      e.className=cls;
      e.textContent=`[${String(p.ts).padStart(8)}ms] ${p.info.padEnd(22)} ${p.src} → ${p.dst}  CH${p.ch}  ${p.rssi}dBm`;
      log.appendChild(e);
    });
    log.scrollTop=log.scrollHeight;
    set('pktTotal',d.total);set('pktMgmt',pktMgmt);set('pktData',pktData);set('pktCtrl',pktCtrl);});}

// ── KISMET ────────────────────────────────────────────────────────────────────
let kisOn=false,kisPoll=null;
function togKismet(){
  kisOn=!kisOn;
  fetch('/kismet?active='+kisOn).then(r=>r.json()).then(d=>{
    $('kisBtn').textContent=kisOn?'■ STOP KISMET':'▶ START KISMET';
    $('kisBtn').className=kisOn?'btn br':'btn bm';
    set('kisSt',kisOn?'MAPPING NETWORK...':'STOPPED');
    if(kisOn){kisPoll=setInterval(fetchKismet,2000);}else{clearInterval(kisPoll);}});}
function clearKismet(){fetch('/kismet/clear');$('kApT').innerHTML='<tr><td colspan="6" style="color:#1e293b;text-align:center;padding:12px">Cleared</td></tr>';$('kProbeT').innerHTML='<tr><td colspan="3" style="color:#1e293b;text-align:center;padding:12px">Cleared</td></tr>';}
function fetchKismet(){
  fetch('/kismet/data').then(r=>r.json()).then(d=>{
    const tb=$('kApT');
    if(!d.aps||!d.aps.length){tb.innerHTML='<tr><td colspan="6" style="color:#1e293b;text-align:center;padding:12px">No APs yet</td></tr>';return;}
    tb.innerHTML=d.aps.map(a=>`<tr><td style="font-size:.56rem;color:#836FFF">${a.b}</td>
      <td style="color:#e2e8f0">${a.s||'<em style="color:#334155">hidden</em>'}</td>
      <td>${a.c}</td><td>${a.r} dBm</td><td>${sig(a.r,'sv')}</td>
      <td style="font-size:.54rem;color:#334155">${a.t}ms ago</td></tr>`).join('');
    const pt=$('kProbeT');
    if(!d.probes||!d.probes.length){pt.innerHTML='<tr><td colspan="3" style="color:#1e293b;text-align:center;padding:12px">No probes yet</td></tr>';return;}
    pt.innerHTML=d.probes.map(p=>`<tr><td style="font-size:.56rem;color:#836FFF">${p.m}</td>
      <td style="color:var(--v2)">${xss(p.s)}</td>
      <td style="font-size:.54rem;color:#334155">${p.t}ms ago</td></tr>`).join('');})}

// ── PMKID ─────────────────────────────────────────────────────────────────────
let pmkOn=false,pmkPoll=null;
function togPMKID(){
  pmkOn=!pmkOn;
  fetch('/pmkid?active='+pmkOn).then(r=>r.json()).then(d=>{
    $('pmkBtn').textContent=pmkOn?'■ STOP CAPTURE':'▶ START CAPTURE';
    $('pmkBtn').className=pmkOn?'btn br':'btn bm';
    set('pmkSt',pmkOn?'LISTENING FOR EAPOL...':'STOPPED');
    if(pmkOn){pmkPoll=setInterval(fetchPMKID,3000);}else{clearInterval(pmkPoll);}});}
function fetchPMKID(){
  fetch('/pmkid/data').then(r=>r.json()).then(d=>{
    const tb=$('pmkT');
    if(!d.entries||!d.entries.length){tb.innerHTML='<tr><td colspan="4" style="color:#1e293b;text-align:center;padding:14px">No PMKID captured yet</td></tr>';return;}
    tb.innerHTML=d.entries.map(e=>`<tr>
      <td style="font-size:.56rem;color:#836FFF">${e.b}</td>
      <td style="font-size:.56rem;color:#334155">${e.c}</td>
      <td style="font-size:.5rem;color:var(--v2);word-break:break-all">${e.p}</td>
      <td style="font-size:.52rem;color:#334155">${e.t}ms</td></tr>`).join('');})}

// ── DEAUTH ────────────────────────────────────────────────────────────────────
let dRun=false;
function togDeauth(){dRun=!dRun;fetch('/rf/deauth?active='+dRun);
  $('dBtn').textContent=dRun?'■ STOP MONITORING':'▶ START MONITORING';
  $('dBtn').className=dRun?'btn br':'btn bo';}

// ── CHANNEL MAP ───────────────────────────────────────────────────────────────
function scanCh(){set('chSt','SCANNING...');fetch('/wifi/scan').then(()=>setTimeout(drawCh,5500));}
function drawCh(){fetch('/wifi/results').then(r=>r.json()).then(d=>{
  if(d.status==='scanning'){setTimeout(drawCh,1500);return;}
  set('chSt',d.networks.length+' NETS');
  const cnt=new Array(14).fill(0);
  d.networks.forEach(n=>{if(n.channel>=1&&n.channel<=13)cnt[n.channel]++;});
  const mx=Math.max(1,...cnt.slice(1));let best=1;
  for(let i=2;i<=13;i++)if(cnt[i]<cnt[best])best=i;
  set('bestCh','CH '+best);$('bestCh').className='badge bm2';
  const cv=$('chCv'),ctx=cv.getContext('2d');cv.width=cv.offsetWidth||380;cv.height=85;
  ctx.clearRect(0,0,cv.width,cv.height);
  const bw=Math.floor((cv.width-14)/13);
  for(let c=1;c<=13;c++){const x=7+(c-1)*bw,h2=cnt[c]?Math.max(4,Math.round(cnt[c]/mx*55)):2,y=cv.height-h2-13;
    const gd=ctx.createLinearGradient(x,y,x,cv.height-13);
    if(c===best){gd.addColorStop(0,'rgba(21,245,186,.75)');gd.addColorStop(1,'rgba(21,245,186,.15)');}
    else{gd.addColorStop(0,'rgba(131,111,255,.6)');gd.addColorStop(1,'rgba(131,111,255,.1)');}
    ctx.fillStyle=gd;ctx.fillRect(x,y,bw-2,h2);
    ctx.fillStyle='rgba(255,255,255,.12)';ctx.font='7px monospace';ctx.textAlign='center';
    ctx.fillText(c,x+bw/2-1,cv.height-2);
    if(cnt[c]){ctx.fillStyle='rgba(131,111,255,.8)';ctx.fillText(cnt[c],x+bw/2-1,y-2);}}})}

// ── EVIL TWIN ─────────────────────────────────────────────────────────────────
function detectEvilTwin(){
  if(!lastNets.length){$('etResults').textContent='Run a WiFi scan first.';return;}
  const ssidMap={};lastNets.forEach(n=>{if(!ssidMap[n.ssid])ssidMap[n.ssid]=[];ssidMap[n.ssid].push(n);});
  const twins=Object.entries(ssidMap).filter(([s,ns])=>ns.length>1&&s);
  if(!twins.length){$('etResults').innerHTML='<span style="color:var(--v2)">✓ No evil twin candidates detected</span>';return;}
  $('etResults').innerHTML=twins.map(([s,ns])=>`
    <div style="margin-bottom:8px;padding:8px;background:rgba(255,107,107,.06);border:1px solid rgba(255,107,107,.2);border-radius:7px">
      <div style="color:var(--rd);font-size:.65rem;margin-bottom:4px">⚠ DUPLICATE SSID: "${xss(s)}"</div>
      ${ns.map(n=>`<div style="font-size:.58rem;color:#94a3b8;padding:2px 0">CH${n.channel} · ${n.rssi}dBm</div>`).join('')}
    </div>`).join('');}

// ── RECON ─────────────────────────────────────────────────────────────────────
function doRecon(){$('rBtn').disabled=true;set('rSt','SCANNING + PORT PROBE...');
  fetch('/recon').then(r=>r.json()).then(d=>{
    $('rBtn').disabled=false;set('rSt',d.clients.length+' CLIENT(S)');
    const tb=$('rT');
    if(!d.clients.length){tb.innerHTML='<tr><td colspan="5" style="color:#1e293b;text-align:center;padding:14px">No clients</td></tr>';return;}
    tb.innerHTML=d.clients.map(c=>{
      const pts=c.ports.length?c.ports.map(p=>`<span class="badge bv2" style="margin:1px 2px 1px 0;font-size:.48rem">${p.p}:${p.s}</span>`).join(''):'<span style="color:#334155;font-size:.52rem">none</span>';
      return`<tr><td style="color:#e2e8f0;font-size:.62rem">${c.vendor}</td>
        <td style="color:rgba(21,245,186,.7)">${c.ip}</td>
        <td style="font-size:.52rem;color:#334155">${c.mac}</td>
        <td>${pts}</td><td style="font-size:.55rem;color:var(--dm)">${c.age}</td></tr>`;
    }).join('');}).catch(()=>{$('rBtn').disabled=false;set('rSt','Error');});}

// ── TOUCH ─────────────────────────────────────────────────────────────────────
function saveTouchAct(){fetch('/touch/actions?t1='+$('ta0').value+'&t2='+$('ta1').value).then(()=>addLog('Touch actions saved','g'));}

// ── SYSTEM ────────────────────────────────────────────────────────────────────
function setCPU(){fetch('/system/cpu?freq='+$('cpuF').value).then(r=>r.json()).then(d=>addLog('CPU → '+d.freq+' MHz','g'));}
function saveAP(){
  const ss=$('nSsid').value.trim(),pw=$('nPass').value,pc=$('nPassC').value,st=$('apSt');
  if(!ss){st.textContent='SSID cannot be empty';st.style.color='var(--rd)';return;}
  if(pw.length<8){st.textContent='Password ≥8 chars';st.style.color='var(--rd)';return;}
  if(pw!==pc){st.textContent='Passwords do not match';st.style.color='var(--rd)';return;}
  st.textContent='Saving...';st.style.color='var(--or)';
  fetch('/ap/config',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'ssid='+encodeURIComponent(ss)+'&pass='+encodeURIComponent(pw)})
  .then(r=>r.json()).then(d=>{
    if(d.status==='saved'){st.textContent='Saved! Rebooting...';st.style.color='var(--v2)';}
    else{st.textContent='Error: '+(d.msg||'?');st.style.color='var(--rd)';}});}
function doSleep(){const s=parseInt($('slpS').value)||30;if(!confirm('Deep sleep '+s+'s?'))return;
  $('slpCd').style.display='block';let c=3;
  const iv=setInterval(()=>{$('slpCd').textContent=c--;if(c<0){clearInterval(iv);fetch('/system/sleep?sec='+s);}},1000);}
function doReboot(){if(confirm('Reboot AXIOM?'))fetch('/system/reboot').then(()=>addLog('Rebooting...','w'));}

// ── CHAT (WS) ─────────────────────────────────────────────────────────────────
let ws=null,myN='';
function initWS(){
  ws=new WebSocket('ws://'+location.hostname+':81');
  ws.onopen=()=>{set('wsp','ONLINE');$('wsp').className='pill p-on';addSys('Connected');};
  ws.onclose=()=>{set('wsp','OFFLINE');$('wsp').className='pill p-off';ws=null;setTimeout(initWS,3000);};
  ws.onmessage=e=>{try{const d=JSON.parse(e.data);
    if(d.t==='chat')apMsg(d.n,d.m,d.ts,d.n===myN);
    else if(d.t==='sys'){addSys(d.msg);set('onl',d.n+' ONLINE');}}catch(e){}};
}
function sChat(){const n=$('nIn').value.trim()||'ANON',t=$('mIn').value.trim();myN=n;
  if(!t||!ws||ws.readyState!==1)return;ws.send(JSON.stringify({t:'chat',n,m:t}));$('mIn').value='';}
function apMsg(nm,tx,ts,mine=false){const b=$('cMsgs');const d=document.createElement('div');
  d.style.cssText='margin-bottom:8px'+(mine?';text-align:right':'');
  const meta=document.createElement('div');meta.style.cssText='font-size:.52rem;color:rgba(131,111,255,.4);margin-bottom:2px'+(mine?';text-align:right':'');
  meta.innerHTML=`<span style="color:rgba(21,245,186,.5)">${xss(nm)}</span><span style="color:rgba(255,255,255,.1);margin-left:7px">${ts}</span>`;
  const bub=document.createElement('div');
  bub.style.cssText=`display:inline-block;max-width:78%;padding:6px 10px;font-size:.7rem;color:#c7d2fe;border-radius:${mine?'9px 0 9px 9px':'0 9px 9px 9px'};border:1px solid;background:${mine?'rgba(21,245,186,.06)':'rgba(131,111,255,.06)'};border-color:${mine?'rgba(21,245,186,.18)':'rgba(131,111,255,.18)'}`;
  bub.textContent=tx;d.appendChild(meta);d.appendChild(bub);b.appendChild(d);b.scrollTop=b.scrollHeight;}
function addSys(t){const b=$('cMsgs');const d=document.createElement('div');
  d.style.cssText='text-align:center;font-size:.5rem;color:rgba(255,255,255,.12);letter-spacing:2px;margin:6px 0';
  d.textContent='— '+t+' —';b.appendChild(d);b.scrollTop=b.scrollHeight;}

// ── REST DATA PANEL HELPERS ───────────────────────────────────────────────────
let dpAutoRef=true,dpTimer=null,currentEndpoint='/data';
function fetchApiData(ep){
  currentEndpoint=ep||currentEndpoint;
  set('apiEndpointTitle','ENDPOINT: '+currentEndpoint);
  fetch(currentEndpoint).then(r=>{
    $('apiStatusBadge').textContent=r.status+' '+r.statusText;
    $('apiStatusBadge').className=r.ok?'badge bm2':'badge br2';
    return r.json();
  }).then(d=>{
    $('jsonViewer').textContent=JSON.stringify(d,null,2);
    if(currentEndpoint==='/data')updateDataPanelCards(d);
  }).catch(e=>{
    $('apiStatusBadge').textContent='ERR';
    $('apiStatusBadge').className='badge br2';
    $('jsonViewer').textContent='Error fetching endpoint: '+e;
  });
}
function updateDataPanelCards(d){
  if(d.system){
    const s=Math.floor(d.system.uptime/1000);
    set('dpUpt',Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m '+(s%60)+'s');
    set('dpHeap',(d.system.heapFree/1024).toFixed(1)+' KB');
    set('dpCpu',d.system.cpuFreqMHz+' MHz');
    set('dpTemp',d.system.tempC+' °C');
    set('dpChip',d.system.chipId);
  }
  if(d.wifi){
    set('dpApSsid',d.wifi.apSSID);
    set('dpApClients',d.wifi.apClientsCount);
    set('dpStaSt',d.wifi.staStatus);
    set('dpStaIp',d.wifi.staIP||'—');
    set('dpStaRssi',d.wifi.staRSSI?d.wifi.staRSSI+' dBm':'—');
  }
  if(d.bluetooth){
    set('dpBleSt',d.bluetooth.scanning?'SCANNING...':'IDLE');
    set('dpBleDevs',d.bluetooth.deviceList?d.bluetooth.deviceList.length:0);
    set('dpBleTs',new Date().toLocaleTimeString());
  }
  if(d.gpio&&d.gpio.outputs){
    const mx=$('dpGpioMatrix');
    if(mx){
      mx.innerHTML=d.gpio.outputs.map(p=>`
        <div class="gpio-btn ${p.state?'on':'off'}">
          <span class="gn">GPIO ${p.pin}</span>
          <span class="gs">${p.state?'HIGH':'LOW'}</span>
        </div>`).join('');
    }
  }
}
function autoRefreshToggle(){
  dpAutoRef=!dpAutoRef;
  $('autoRefBtn').textContent='AUTO REFRESH: '+(dpAutoRef?'ON':'OFF');
  $('autoRefBtn').className=dpAutoRef?'pill p-v':'pill p-off';
  if(dpAutoRef){fetchApiData();if(!dpTimer)dpTimer=setInterval(()=>{if(dpAutoRef)fetchApiData();},2000);}
  else{if(dpTimer){clearInterval(dpTimer);dpTimer=null;}}
}
setTimeout(()=>{fetchApiData('/data');dpTimer=setInterval(()=>{if(dpAutoRef)fetchApiData('/data');},3000);},1000);
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
  j += "\"napt\":" + jb(bridgeNaptEnabled) + ",";
  if (WiFi.status() == WL_CONNECTED) {
    j += "\"sta\":\"connected\",\"staSSID\":\"" + esc(WiFi.SSID()) + "\",";
    j += "\"staIp\":\"" + WiFi.localIP().toString() + "\",";
    j += "\"staRSSI\":" + String(WiFi.RSSI());
  } else {
    j += "\"sta\":\"" + staConnStatus + "\"";
  }
  // Full extras
  if (full) {
    j += ",\"flash\":" + String(ESP.getFlashChipSize());
    j += ",\"psram\":" + String(ESP.getPsramSize());
    j += ",\"chipId\":\"" + String((uint32_t)(ESP.getEfuseMac() >> 32), HEX) +
         "\"";
    // GPIO input states
    j += ",\"inputs\":[" + jb(digitalRead(7)) + "," + jb(digitalRead(8)) + "]";
    // PWM duties
    j += ",\"pwm\":[" + String(pwmDuty[0]) + "," + String(pwmDuty[1]) + "," +
         String(pwmDuty[2]) + "]";
    // Touch
    j += ",\"touch\":[" + String(touchVal[0]) + "," + String(touchVal[1]) + "]";
    j += ",\"touchActive\":[" + jb(touchActive[0]) + "," + jb(touchActive[1]) +
         "]";
  }
  j += ",\"oledPage\":" + String(oledPage) + ",\"oledCycle\":" + jb(oledAutoCycle) + ",\"oledRefresh\":" + jb(oledAutoRefresh);
  j += "}";
  lastHttpActivityAt = millis();
  http.send(200, "application/json", j);
}

// ── GPIO — all pins
// ───────────────────────────────────────────────────────────
void handleGPIOPin() {
  if (!http.hasArg("pin") || !http.hasArg("state")) {
    http.send(400, "application/json", "{\"e\":\"missing\"}");
    return;
  }
  int pin = http.arg("pin").toInt();
  int state = http.arg("state").toInt();
  // Block strapping/reserved pins
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

  // Don't digital-write PWM pins while PWM active
  int ch = -1;
  if (pin == GPIO_OUT_1)
    ch = 0;
  else if (pin == GPIO_OUT_2)
    ch = 1;
  else if (pin == GPIO_OUT_3)
    ch = 2;
  if (ch >= 0 && pwmMode[ch]) {
    http.send(409, "application/json", "{\"e\":\"pin in PWM mode\"}");
    return;
  }
  // Prevent writing to pins reserved/used by onboard peripherals (OLED, SPI, etc.)
  if (isPinInUse(pin)) {
    http.send(409, "application/json", "{\"e\":\"pin in use\"}");
    return;
  }
  pinMode(pin, OUTPUT);
  gpioStates[idx] = (state == 1);
  digitalWrite(pin, state ? HIGH : LOW);
  oledDirty = true;
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
  if (pwmMode[ch])
    ledcWrite(g[ch], duty);
  oledDirty = true;
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
  oledDirty = true;
  http.send(200, "application/json",
            "{\"ch\":" + String(ch) + ",\"pwm\":" + jb(pwmMode[ch]) + "}");
}

// ── LED
// ───────────────────────────────────────────────────────────────────────
void handleLED() {
  uint8_t r = http.hasArg("r") ? constrain(http.arg("r").toInt(), 0, 255) : 0;
  uint8_t g = http.hasArg("g") ? constrain(http.arg("g").toInt(), 0, 255) : 0;
  uint8_t b = http.hasArg("b") ? constrain(http.arg("b").toInt(), 0, 255) : 0;
  setNeo(r, g, b);
  oledDirty = true;
  http.send(200, "application/json",
            "{\"r\":" + String(r) + ",\"g\":" + String(g) +
                ",\"b\":" + String(b) + "}");
}

// ── WIFI
// ──────────────────────────────────────────────────────────────────────
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
    if (i > 0)
      j += ",";
    j += "{\"ssid\":\"" + esc(WiFi.SSID(i)) +
         "\",\"rssi\":" + String(WiFi.RSSI(i)) +
         ",\"channel\":" + String(WiFi.channel(i)) +
         ",\"enc\":" + jb(WiFi.encryptionType(i) != WIFI_AUTH_OPEN) + "}";
  }
  j += "]}";
  WiFi.scanDelete();
  http.send(200, "application/json", j);
}

static void enableBridgeNAPT() {
  esp_netif_t *apNetif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
  if (!apNetif) {
    Serial.println("[BRIDGE] AP netif unavailable; NAPT not enabled");
    return;
  }

  esp_netif_dns_info_t dnsInfo = {};
  dnsInfo.ip.type = ESP_IPADDR_TYPE_V4;
  IPAddress upstreamDns = WiFi.dnsIP();
  if (upstreamDns == IPAddress(0, 0, 0, 0))
    upstreamDns = IPAddress(8, 8, 8, 8);
  dnsInfo.ip.u_addr.ip4.addr = (uint32_t)upstreamDns;

  esp_netif_dhcps_stop(apNetif);
  uint8_t offerDns = 1;
  esp_netif_dhcps_option(apNetif, ESP_NETIF_OP_SET,
                         ESP_NETIF_DOMAIN_NAME_SERVER, &offerDns,
                         sizeof(offerDns));
  esp_netif_set_dns_info(apNetif, ESP_NETIF_DNS_MAIN, &dnsInfo);
  esp_netif_dhcps_start(apNetif);

  esp_err_t result = esp_netif_napt_enable(apNetif);
  bridgeNaptEnabled = result == ESP_OK;
  Serial.printf("[BRIDGE] NAPT %s (DNS %s)\n",
                bridgeNaptEnabled ? "enabled" : "enable failed",
                upstreamDns.toString().c_str());
}

static void disableBridgeNAPT() {
  esp_netif_t *apNetif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
  if (apNetif)
    esp_netif_napt_disable(apNetif);
  bridgeNaptEnabled = false;
  Serial.println("[BRIDGE] NAPT disabled");
}

void handleNatBridge() {
  bool enabled = http.hasArg("on") && http.arg("on") == "1";
  if (enabled && WiFi.status() != WL_CONNECTED) {
    http.send(409, "application/json",
              "{\"status\":\"error\",\"msg\":\"connect upstream first\"}");
    return;
  }

  if (enabled)
    enableBridgeNAPT();
  else
    disableBridgeNAPT();

  http.send(bridgeNaptEnabled ? 200 : (enabled ? 500 : 200),
            "application/json",
            "{\"status\":\"ok\",\"enabled\":" +
                jb(bridgeNaptEnabled) + "}");
}

void handleWifiConnect() {
  if (!http.hasArg("ssid")) {
    http.send(400, "application/json",
              "{\"status\":\"error\",\"msg\":\"missing ssid\"}");
    return;
  }
  String ss = http.arg("ssid"),
         pw = http.hasArg("pass") ? http.arg("pass") : "";
  // Respond FIRST, then start connection (no blocking delay in handler)
  http.send(200, "application/json", "{\"status\":\"connecting\"}");
  // Only (re)build the AP if it isn't already up — recreating it while
  // clients (like whoever is viewing this dashboard) are associated kicks
  // them off and breaks the web dashboard mid-request.
  if (WiFi.getMode() != WIFI_AP_STA) {
    WiFi.mode(WIFI_AP_STA);
    WiFi.softAPConfig(AP_IP, AP_GW, AP_SN);
    WiFi.softAP(apSSID.c_str(), apPass.c_str());
  }
  disableBridgeNAPT();
  WiFi.disconnect(false);
  if (pw.length() > 0 && pw != "(open)")
    WiFi.begin(ss.c_str(), pw.c_str());
  else
    WiFi.begin(ss.c_str());
  staConnStatus = "connecting";
  staSSID = ss;
  staTimeout = millis() + 18000;
  oledDirty = true;
}
void handleWifiDisconnect() {
  // Respond first, disconnect after
  http.send(200, "application/json", "{\"status\":\"disconnected\"}");
  disableBridgeNAPT();
  WiFi.disconnect(false);
  staConnStatus = "disconnected";
  staSSID = "";
  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(AP_IP, AP_GW, AP_SN);
  WiFi.softAP(apSSID.c_str(), apPass.c_str());
  oledDirty = true;
}

// ── BLE
// ───────────────────────────────────────────────────────────────────────
void handleBleScan() {
  // Use shared async starter so other endpoints can trigger scans too
  startBleScanAsync();
  http.send(200, "application/json", "{\"status\":" + String(bleScanning?"\"scanning\"":"\"started\"") + "}");
}

// Helper: start BLE scan asynchronously without sending HTTP response
void startBleScanAsync() {
  if (bleScanning) return;
  // Don't start BLE scan if channel hopping is active — causes crashes
  if (chanHopping && (snifferActive || kismetMode || deauthMode || pmkidMode)) return;
  bleScanning = true;
  if (bleCb) delete bleCb;
  bleCb = new AxiomBLECb();
  pBLEScan->setAdvertisedDeviceCallbacks(bleCb);
  pBLEScan->setActiveScan(true);
  pBLEScan->start(6,
                  [](BLEScanResults r) {
                    bleCb->json += "]";
                    bleResults = bleCb->json;
                    bleScanning = false;
                    oledDirty = true;
                  },
                  false);
  oledDirty = true;
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
// ───────────────────────────────────────────────────────────────────
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
  oledDirty = true;
  http.send(200, "application/json", "{\"active\":" + jb(snifferActive) + "}");
}
void handleSnifferLog() {
  String j = "{\"pkts\":[";
  int start = max(0, pktHead - 20);
  bool first = true;
  for (int i = start; i < pktHead && i < start + 20; i++) {
    int idx = i % MAX_PKT_LOG;
    if (!first)
      j += ",";
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
  oledDirty = true;
  http.send(200, "application/json", "{\"ok\":true}");
}
void handleSnifferHop() {
  bool v = http.hasArg("v") && http.arg("v") == "true";
  chanHopping = v;
  oledDirty = true;
  http.send(200, "application/json", "{\"ok\":true}");
}

// ── KISMET
// ────────────────────────────────────────────────────────────────────
void handleKismet() {
  bool active = http.hasArg("active") && http.arg("active") == "true";
  kismetMode = active;
  probeCount = 0;
  if (active) {
    chanHopping = true;
    startPromiscuous();
  } else
    stopPromiscuous();
  oledDirty = true;
  http.send(200, "application/json", "{\"active\":" + jb(kismetMode) + "}");
}
void handleKismetData() {
  String j = "{\"aps\":[";
  bool first = true;
  for (int i = 0; i < MAX_AP; i++) {
    if (!kisAPs[i].valid)
      continue;
    if (!first)
      j += ",";
    first = false;
    j += "{\"b\":\"" + String(kisAPs[i].bssid) + "\",\"s\":\"" +
         esc(String(kisAPs[i].ssid)) + "\"";
    j += ",\"c\":" + String(kisAPs[i].ch) + ",\"r\":" + String(kisAPs[i].rssi);
    j += ",\"t\":" + String(millis() - kisAPs[i].ts) + "}";
  }
  j += "],\"probes\":[";
  first = true;
  for (int i = 0; i < probeCount; i++) {
    if (!first)
      j += ",";
    first = false;
    j += "{\"m\":\"" + String(probeLog[i].mac) + "\",\"s\":\"" +
         esc(String(probeLog[i].ssid)) + "\"";
    j += ",\"t\":" + String(millis() - probeLog[i].ts) + "}";
  }
  j += "]}";
  http.send(200, "application/json", j);
}
void handleKismetClear() {
  for (int i = 0; i < MAX_AP; i++)
    kisAPs[i].valid = false;
  probeCount = 0;
  oledDirty = true;
  http.send(200, "application/json", "{\"ok\":true}");
}

// ── PMKID
// ─────────────────────────────────────────────────────────────────────
void handlePMKID() {
  bool active = http.hasArg("active") && http.arg("active") == "true";
  pmkidMode = active;
  if (active)
    startPromiscuous();
  else
    stopPromiscuous();
  oledDirty = true;
  http.send(200, "application/json", "{\"active\":" + jb(pmkidMode) + "}");
}
void handlePMKIDData() {
  String j = "{\"entries\":[";
  for (int i = 0; i < pmkidCount; i++) {
    if (i > 0)
      j += ",";
    j += "{\"b\":\"" + String(pmkidLog[i].bssid) + "\",\"c\":\"" +
         String(pmkidLog[i].client) + "\"";
    j += ",\"p\":\"" + String(pmkidLog[i].pmkid) +
         "\",\"t\":" + String(pmkidLog[i].ts) + "}";
  }
  j += "]}";
  http.send(200, "application/json", j);
}

// ── DEAUTH DETECTOR
// ───────────────────────────────────────────────────────────
void handleDeauth() {
  bool active = http.hasArg("active") && http.arg("active") == "true";
  deauthMode = active;
  if (active) {
    chanHopping = true;
    startPromiscuous();
  } else
    stopPromiscuous();
  oledDirty = true;
  http.send(200, "application/json", "{\"active\":" + jb(deauthMode) + "}");
}

// ── RECON
// ─────────────────────────────────────────────────────────────────────
void handleRecon() {
  wifi_sta_list_t sl;
  esp_wifi_ap_get_sta_list(&sl);
  esp_netif_t *apif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
  String j = "{\"clients\":[";
  for (int i = 0; i < sl.num; i++) {
    if (i > 0)
      j += ",";
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
// ─────────────────────────────────────────────────────────────────────
void handleTouchActions() {
  if (http.hasArg("t1"))
    touchAction[0] = http.arg("t1");
  if (http.hasArg("t2"))
    touchAction[1] = http.arg("t2");
  http.send(200, "application/json", "{\"ok\":true}");
}
void fireTouchAction(int idx) {
  String &a = touchAction[idx];
  if (a == "gpio0") {
    int i = pinIndex(GPIO_OUT_1);
    gpioStates[i] = !gpioStates[i];
    digitalWrite(GPIO_OUT_1, gpioStates[i] ? HIGH : LOW);
    oledDirty = true;
  } else if (a == "gpio1") {
    int i = pinIndex(GPIO_OUT_2);
    gpioStates[i] = !gpioStates[i];
    digitalWrite(GPIO_OUT_2, gpioStates[i] ? HIGH : LOW);
    oledDirty = true;
  } else if (a == "gpio2") {
    int i = pinIndex(GPIO_OUT_3);
    gpioStates[i] = !gpioStates[i];
    digitalWrite(GPIO_OUT_3, gpioStates[i] ? HIGH : LOW);
    oledDirty = true;
  } else if (a == "sleep") {
    esp_sleep_enable_timer_wakeup(30ULL * 1000000ULL);
    esp_sleep_enable_touchpad_wakeup();
    esp_deep_sleep_start();
  }
}

// ── AP CONFIG
// ─────────────────────────────────────────────────────────────────
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
  // System metrics
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

  // WiFi telemetry
  j += "\"wifi\":{";
  j += "\"apSSID\":\"" + esc(apSSID) + "\",";
  j += "\"apClientsCount\":" + String(WiFi.softAPgetStationNum()) + ",";
  j += "\"staStatus\":\"" + staConnStatus + "\",";
  j += "\"napt\":" + jb(bridgeNaptEnabled) + ",";
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

  // Bluetooth telemetry
  j += "\"bluetooth\":{";
  j += "\"scanning\":" + jb(bleScanning) + ",";
  j += "\"deviceList\":" + (bleResults.length() > 0 ? bleResults : "[]");
  j += "},";

  // GPIO telemetry
  j += "\"gpio\":{";
  j += "\"outputs\":[";
  for (int i = 0; i < OUT_COUNT; i++) {
    if (i > 0)
      j += ",";
    j += "{\"pin\":" + String(OUT_PINS[i]) + ",\"state\":" + jb(gpioStates[i]) +
         ",\"inUse\":" + jb(isPinInUse(OUT_PINS[i])) + "}";
  }
  j += "],";
  j += "\"inputs\":[";
  for (int i = 0; i < IN_COUNT; i++) {
    if (i > 0)
      j += ",";
    j += "{\"pin\":" + String(IN_PINS[i]) +
         ",\"val\":" + String(digitalRead(IN_PINS[i])) + "}";
  }
  j += "],";
  j += "\"adc\":[";
  for (int i = 0; i < ADC_COUNT; i++) {
    if (i > 0)
      j += ",";
    j += "{\"pin\":" + String(ADC_PINS[i]) +
         ",\"raw\":" + String(analogRead(ADC_PINS[i])) + "}";
  }
  j += "],";
  j += "\"pwm\":[";
  for (int i = 0; i < 3; i++) {
    if (i > 0)
      j += ",";
    int g[3] = {GPIO_OUT_1, GPIO_OUT_2, GPIO_OUT_3};
    j += "{\"pin\":" + String(g[i]) + ",\"duty\":" + String(pwmDuty[i]) +
         ",\"enabled\":" + jb(pwmMode[i]) + "}";
  }
  j += "],";
  j += "\"touch\":[";
  for (int i = 0; i < 2; i++) {
    if (i > 0)
      j += ",";
    j += "{\"ch\":" + String(i + 1) + ",\"raw\":" + String(touchVal[i]) +
         ",\"active\":" + jb(touchActive[i]) + ",\"action\":\"" +
         touchAction[i] + "\"}";
  }
  j += "]},";

  // Sniffer & Cyber intel
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
  lastHttpActivityAt = millis();
  http.send(200, "application/json", j);
}

void handleGPIOEndpoint() {
  String j = "{";
  j += "\"status\":\"ok\",";
  j += "\"outPins\":[";
  for (int i = 0; i < OUT_COUNT; i++) {
    if (i > 0)
      j += ",";
    j += "{\"pin\":" + String(OUT_PINS[i]) + ",\"state\":" + jb(gpioStates[i]) +
         ",\"inUse\":" + jb(isPinInUse(OUT_PINS[i])) + "}";
  }
  j += "],\"inPins\":[";
  for (int i = 0; i < IN_COUNT; i++) {
    if (i > 0)
      j += ",";
    j += "{\"pin\":" + String(IN_PINS[i]) +
         ",\"val\":" + String(digitalRead(IN_PINS[i])) + "}";
  }
  j += "],\"adcPins\":[";
  for (int i = 0; i < ADC_COUNT; i++) {
    if (i > 0)
      j += ",";
    j += "{\"pin\":" + String(ADC_PINS[i]) +
         ",\"raw\":" + String(analogRead(ADC_PINS[i])) + "}";
  }
  j += "],\"pwm\":[";
  int g[3] = {GPIO_OUT_1, GPIO_OUT_2, GPIO_OUT_3};
  for (int i = 0; i < 3; i++) {
    if (i > 0)
      j += ",";
    j += "{\"ch\":" + String(i) + ",\"pin\":" + String(g[i]) +
         ",\"duty\":" + String(pwmDuty[i]) + ",\"mode\":" + jb(pwmMode[i]) +
         "}";
  }
  j += "],\"touch\":[";
  for (int i = 0; i < 2; i++) {
    if (i > 0)
      j += ",";
    j += "{\"pad\":" + String(i + 1) + ",\"gpio\":" + String(i + 1) +
         ",\"val\":" + String(touchVal[i]) +
         ",\"active\":" + jb(touchActive[i]) + ",\"action\":\"" +
         touchAction[i] + "\"}";
  }
  j += "]}";
  http.send(200, "application/json", j);
}

void handleWifiEndpoint() {
  if (WiFi.scanComplete() != WIFI_SCAN_RUNNING) {
    WiFi.scanNetworks(true, true); // async = true, show_hidden = true
  }
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
    if (i > 0)
      j += ",";
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
  oledDirty = true; // fresh read requested — mark display dirty so caller sees updates
  http.send(200, "application/json", j);
}

void handleBluetoothEndpoint() {
  // Trigger an async BLE scan if none in progress so callers get live data
  startBleScanAsync();
  String j = "{";
  j += "\"status\":\"" + String(bleScanning ? "scanning" : "ready") + "\",";
  j += "\"scanning\":" + jb(bleScanning) + ",";
  j += "\"devices\":" + (bleResults.length() > 0 ? bleResults : "[]");
  j += "}";
  http.send(200, "application/json", j);
}

void handleNotFound() { http.send(404, "text/plain", "AXIOM 404"); }

// ══════════════════════════════════════════════════════════════════════════════
//  OLED DISPLAY
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

// GPIO panel table — tags each pin with its actual purpose (touch, PWM,
// digital input, or general output) instead of just showing raw HIGH/LOW,
// so it doubles as an "in use for X" indicator.
bool isPinInUse(int pin) {
  if (pin == 11 || pin == 12 || pin == 9 || pin == 14 || pin == 10) return true; // OLED SPI
  if (pin == 48) return true; // NeoPixel LED
  if (pin == 4 || pin == 5 || pin == 6) return true; // PWM / Output
  if (pin == 7 || pin == 8) return true; // Inputs
  if (pin == 1 || pin == 2) return true; // Touch
  return false;
}

String gpioLabel(int i) {
  int pin = OUT_PINS[i];
  String label = "";
  if (pin == 1) label = "P1 TOUCH1";
  else if (pin == 2) label = "P2 TOUCH2";
  else if (pin == 4) label = "P4 PWM1";
  else if (pin == 5) label = "P5 PWM2";
  else if (pin == 6) label = "P6 PWM3";
  else if (pin == 7) label = "P7 IN0";
  else if (pin == 8) label = "P8 IN1";
  else label = "P" + String(pin) + " OUT";
  
  if (isPinInUse(pin)) {
    label += "*";
  }
  return label;
}
String gpioValue(int i) {
  int pin = OUT_PINS[i];
  String val = "";
  if (pin == 1) val = touchActive[0] ? "ACTIVE" : "idle";
  else if (pin == 2) val = touchActive[1] ? "ACTIVE" : "idle";
  else if (pin == 4) val = String(pwmDuty[0]);
  else if (pin == 5) val = String(pwmDuty[1]);
  else if (pin == 6) val = String(pwmDuty[2]);
  else if (pin == 7) val = digitalRead(7) ? "HIGH" : "LOW";
  else if (pin == 8) val = digitalRead(8) ? "HIGH" : "LOW";
  else val = gpioStates[i] ? "HIGH" : "LOW";
  
  if (isPinInUse(pin)) {
    val += " (U)";
  }
  return val;
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

// Full recovery from a WiFi-brownout glitch. A brownout severe enough to
// flip/mirror the display (segment-remap + COM-scan-direction registers,
// not just the invert flag) usually means the SH1106's whole register set
// got scrambled — a single "normal display" command isn't enough. Re-run
// the controller's full init sequence instead, which resets segment remap,
// COM scan direction, and the invert flag all at once.
void forceOledNormal() {
  if (!oledReady) return;
  oled.begin();                    // full SH1106 re-init: fixes invert AND flip/mirror
  oled.setContrast(OLED_CONTRAST);
  oledDirty = true;
}

// WiFi radio events (AP client join/leave, STA connect/disconnect, and
// DHCP/IP-assignment) are when TX current spikes happen — DHCP/IP handoff
// in particular is when a phone starts actually pulling data (loading the
// dashboard, etc.), which is often a bigger spike than the initial
// association. Re-assert normal display immediately on all of these.
unsigned long pendingOledRecovery = 0;  // 0 = none scheduled

void onAxiomWifiEvent(WiFiEvent_t event) {
  switch (event) {
    case ARDUINO_EVENT_WIFI_AP_STACONNECTED:
    case ARDUINO_EVENT_WIFI_AP_STADISCONNECTED:
    case ARDUINO_EVENT_WIFI_AP_STAIPASSIGNED:
    case ARDUINO_EVENT_WIFI_STA_CONNECTED:
    case ARDUINO_EVENT_WIFI_STA_DISCONNECTED:
    case ARDUINO_EVENT_WIFI_STA_GOT_IP:
      forceOledNormal();
      // The actual current spike from follow-on traffic (DHCP finishing,
      // your first click/page load) can land a moment after this event
      // fires, so schedule a second recovery pass instead of relying on
      // one immediate call.
      pendingOledRecovery = millis() + 1500;
      break;
    default:
      break;
  }
}

void drawOled() {
  if (!oledReady) return;
  if (oledDrawing) return;  // prevent re-entrant SPI collision
  oledDrawing = true;

  // Full re-init before every draw, not just a single command resend.
  // A corrupted SPI transaction can leave the SH1106 mid-command-sequence
  // — desynced, not just showing stale pixels — and a normal draw sent
  // into that state gets misinterpreted too, so the glitch persists
  // through redraws until something forces a real resync (this is why
  // only a WiFi disconnect event, which calls this same reinit via
  // forceOledNormal(), was clearing it — not the KISMET click itself).
  // Making every draw do this closes that gap.
  oled.begin();
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
      int n = WiFi.scanComplete();
      if (n == WIFI_SCAN_RUNNING) {
        oled.setCursor(0, 30);
        oled.print("Scanning networks..");
        oledFooter(String(String(PG_WIFI + 1) + "/" + String(PG_COUNT)).c_str(), "please wait");
      } else if (n <= 0) {
        oledKV(23, "AP:", truncateStr(apSSID, 13));
        oledKV(35, "STA:", (WiFi.status() == WL_CONNECTED) ? truncateStr(WiFi.SSID(), 13) : "Disconnected");
        oled.setCursor(0, 47);
        oled.print("No networks found");
        oledFooter(String(String(PG_WIFI + 1) + "/" + String(PG_COUNT)).c_str(), "");
      } else {
        // Scrollable list of scanned networks: SSID + signal strength
        int maxOff = n - 3;
        if (maxOff < 0) maxOff = 0;
        if (oledScrollOffset > maxOff) oledScrollOffset = maxOff;
        if (oledScrollOffset < 0) oledScrollOffset = 0;
        int ys[3] = {23, 35, 47};
        for (int r = 0; r < 3; r++) {
          int idx = oledScrollOffset + r;
          if (idx >= n) continue;
          String ssid = WiFi.SSID(idx);
          if (ssid.length() == 0) ssid = "(hidden)";
          oledKV(ys[r], truncateStr(ssid, 10).c_str(), String(WiFi.RSSI(idx)) + "dBm");
        }
        String pos = String(oledScrollOffset + 1) + "-" +
                     String(min(oledScrollOffset + 3, n)) + "/" + String(n);
        oledFooter(pos.c_str(), "UP/DN SCRL");
      }
      break;
    }
    case PG_SNIFFER: {
      oledHeader("SNIFFER");
      oledKV(23, "Capture:", snifferActive ? "RUNNING" : "STOPPED");
      oledKV(35, "Channel:", chanHopping ? "HOPPING" : String(snifferChan));
      oledKV(47, "Packets:", String(pktTotal));
      String dInfo = "Deauth: " + String(deauthCnt);
      oledFooter(String(String(PG_SNIFFER + 1) + "/" + String(PG_COUNT)).c_str(), dInfo.c_str());
      break;
    }
    case PG_KISMET: {
      oledHeader("KISMET");
      int apCount = 0;
      for (int i = 0; i < MAX_AP; i++) if (kisAPs[i].valid) apCount++;

      oledKV(23, "Status:", kismetMode ? "MAPPING" : "IDLE");
      oledKV(35, "APs:", String(apCount));
      oledKV(47, "Probes:", String(probeCount));
      oledFooter(String(String(PG_KISMET + 1) + "/" + String(PG_COUNT)).c_str(), "CH: HOP");
      break;
    }
    case PG_PMKID: {
      oledHeader("PMKID");
      oledKV(23, "Status:", pmkidMode ? "LISTENING" : "IDLE");
      oledKV(35, "Captured:", String(pmkidCount));
      oledKV(47, "Protocol:", "WPA2");
      oledFooter(String(String(PG_PMKID + 1) + "/" + String(PG_COUNT)).c_str(), "LAB ONLY");
      break;
    }
    case PG_GPIO: {
      oledHeader("GPIO");
      // Scrollable table of all 24 pins — purpose tag doubles as an
      // "in use for X" indicator, value column shows live state.
      int maxOff = OUT_COUNT - 3;
      if (maxOff < 0) maxOff = 0;
      if (oledScrollOffset > maxOff) oledScrollOffset = maxOff;
      if (oledScrollOffset < 0) oledScrollOffset = 0;
      int ys[3] = {23, 35, 47};
      for (int r = 0; r < 3; r++) {
        int idx = oledScrollOffset + r;
        if (idx >= OUT_COUNT) continue;
        oledKV(ys[r], gpioLabel(idx).c_str(), gpioValue(idx));
      }
      String pos = String(oledScrollOffset + 1) + "-" +
                   String(min(oledScrollOffset + 3, OUT_COUNT)) + "/" + String(OUT_COUNT);
      oledFooter(pos.c_str(), "UP/DN SCRL");
      break;
    }
    case PG_RFINTEL: {
      oledHeader("RF INTEL");
      oledKV(23, "BLE Status:", bleScanning ? "SCANNING" : "READY");
      int bleCount = bleCb ? bleCb->cnt : 0;
      oledKV(35, "BLE Devs:", String(bleCount));
      oledKV(47, "RF Status:", snifferActive ? "PROMISC" : "NORMAL");
      oledFooter(String(String(PG_RFINTEL + 1) + "/" + String(PG_COUNT)).c_str(), "AXIOM CONTROLLER");
      break;
    }
    case PG_RECON: {
      oledHeader("RECON STATUS");
      int apCount = 0;
      for (int i = 0; i < MAX_AP; i++) if (kisAPs[i].valid) apCount++;
      oledKV(23, "Kismet Mode:", kismetMode ? "MAPPING" : "IDLE");
      oledKV(35, "APs Found:", String(apCount));
      oledKV(47, "Probe Req:", String(probeCount));
      oledFooter(String(String(PG_RECON + 1) + "/" + String(PG_COUNT)).c_str(), "RECON MONITOR");
      break;
    }
    case PG_SYSTEM: {
      oledHeader("SYSTEM");
      unsigned int fs = ESP.getFlashChipSize();
      oledKV(23, "Flash:", String(fs / (1024UL * 1024UL)) + " MB");
      uint32_t ps = ESP.getPsramSize();
      oledKV(35, "PSRAM:", ps ? String(ps / (1024UL * 1024UL)) + " MB" : String("N/A"));
      oledKV(47, "ChipID:", String((uint32_t)(ESP.getEfuseMac() >> 32), HEX));
      oledFooter(String(String(PG_SYSTEM + 1) + "/" + String(PG_COUNT)).c_str(), "SYS");
      break;
    }
    case PG_CHAT: {
      oledHeader("CHAT OUTPUT");
      int maxOff = CHAT_HISTORY_COUNT - 3;
      if (maxOff < 0) maxOff = 0;
      if (oledScrollOffset > maxOff) oledScrollOffset = maxOff;
      if (oledScrollOffset < 0) oledScrollOffset = 0;
      
      int ys[3] = {23, 35, 47};
      for (int r = 0; r < 3; r++) {
        int idx = (chatHistoryIndex - 1 - oledScrollOffset - r + CHAT_HISTORY_COUNT) % CHAT_HISTORY_COUNT;
        String msg = chatHistory[idx];
        if (msg.length() == 0) msg = "-";
        oled.setCursor(0, ys[r]);
        oled.print(truncateStr(msg, 21).c_str());
      }
      oledFooter(String(String(PG_CHAT + 1) + "/" + String(PG_COUNT)).c_str(), "UP/DN SCRL");
      break;
    }
  }
  oled.sendBuffer();
  oledDrawing = false;
  oledDirty = false;  // mark clean after successful draw
}

void sendOledPageJSON() {
  String j = "{";
  j += "\"page\":" + String(oledPage) + ",";
  j += "\"name\":\"" + String(oledPageNames[oledPage]) + "\",";
  j += "\"count\":" + String(PG_COUNT) + ",";
  j += "\"refresh\":" + jb(oledAutoRefresh) + ",";
  j += "\"cycle\":" + jb(oledAutoCycle);
  j += "}";
  lastHttpActivityAt = millis();
  http.send(200, "application/json", j);
}
void handleDisplayRefresh() {
  if (http.hasArg("on")) oledAutoRefresh = http.arg("on") == "1";
  oledDirty = true;
  sendOledPageJSON();
}
void handleDisplayCycle() {
  if (http.hasArg("on")) oledAutoCycle = http.arg("on") == "1";
  oledDirty = true;
  sendOledPageJSON();
}
void handleDisplayScroll() {
  if (http.hasArg("dir")) {
    String d = http.arg("dir");
    if (d == "up") oledScrollOffset = max(0, oledScrollOffset - 1);
    else if (d == "down") oledScrollOffset++;  // clamped to content length at draw time
  }
  oledDirty = true;
  sendOledPageJSON();
}
void handleDisplayPage() {
  if (http.hasArg("id")) {
    int id = http.arg("id").toInt();
    if (id >= 0 && id < PG_COUNT) {
      oledPage = id;
      oledScrollOffset = 0;  // reset scroll position on panel switch
      if (id == PG_WIFI) WiFi.scanNetworks(true);  // refresh the network list
    }
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
  Serial.println("|   AXIOM v13.6 SELF-HEALING DRAW EDITION   |");
  Serial.println("+-------------------------------+");

  // NeoPixel — boot violet immediately
  neo.begin();
  neo.setBrightness(60);
  setNeo(131, 111, 255);
  Serial.println("[LED] NeoPixel GPIO 48 ready");

  // OLED (SH1106 1.3" SPI) — U8g2 HW SPI mode handles bus init internally
  // Lower SPI clock = wider signal-integrity margin against WiFi-radio EMI
  // coupling onto the SPI lines (the "glitches/jitter" mechanism from your
  // research) — set once, before begin(), and it persists across the
  // full re-inits forceOledNormal() does later.
  oled.setBusClock(400000);  // 400kHz — plenty fast for a 128x64 mono panel
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
  WiFi.onEvent(onAxiomWifiEvent);
  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(AP_IP, AP_GW, AP_SN);
  WiFi.softAP(apSSID.c_str(), apPass.c_str());
  // Cap TX power to cut the peak current spike during transmit — the
  // actual root cause of the voltage sag that corrupts the OLED. This is
  // a software-side mitigation only; the real fix is still a decoupling
  // cap at the display's VCC/GND. 15dBm is plenty for AP-range use;
  // raise it back toward WIFI_POWER_19_5dBm if you need more range once
  // the hardware fix is in.
  WiFi.setTxPower(WIFI_POWER_15dBm);
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
  http.on("/wifi/nat", HTTP_GET, handleNatBridge);
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

  http.on("/display/page", HTTP_GET, handleDisplayPage);
  http.on("/display/refresh", HTTP_GET, handleDisplayRefresh);
  http.on("/display/cycle", HTTP_GET, handleDisplayCycle);
  http.on("/display/scroll", HTTP_GET, handleDisplayScroll);
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
      enableBridgeNAPT();
      setNeo(21, 245, 186); // mint = connected
    } else if (millis() > staTimeout) {
      staConnStatus = "failed";
      Serial.println("[WIFI] Connection failed");
      setNeo(255, 30, 0);
      // Non-blocking recovery: schedule LED reset via flag
      // (simple: just update next loop without delay)
      static unsigned long failLEDTime = 0;
      if (failLEDTime == 0)
        failLEDTime = millis() + 2000;
      if (millis() > failLEDTime) {
        setNeo(131, 111, 255);
        failLEDTime = 0;
      }
    }
  } else if (staConnStatus == "connected" && WiFi.status() != WL_CONNECTED) {
    disableBridgeNAPT();
    staConnStatus = "connecting";
    staTimeout = millis() + 18000;
    Serial.println("[WIFI] Upstream lost -> reconnecting");
    WiFi.reconnect();
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
      if (touchActive[i] && !prevTouch[i])
        fireTouchAction(i);
      prevTouch[i] = touchActive[i];
    }
  }

  // Deferred OLED recovery — catches corruption from follow-on traffic
  // (DHCP completing, first click/page load) that lands after the WiFi
  // event that scheduled it, not exactly at it.
  if (pendingOledRecovery != 0 && millis() > pendingOledRecovery) {
    pendingOledRecovery = 0;
    forceOledNormal();
  }

  // Auto cycle OLED pages if enabled
  static unsigned long lastAutoCycle = 0;
  if (oledAutoCycle && millis() - lastAutoCycle > 3000) {
    lastAutoCycle = millis();
    oledPage = (oledPage + 1) % PG_COUNT;
    oledScrollOffset = 0;
    oledDirty = true;
  }

  // Auto refresh OLED if enabled
  static unsigned long lastAutoRefresh = 0;
  if (oledAutoRefresh && millis() - lastAutoRefresh > 3000) {
    lastAutoRefresh = millis();
    oledDirty = true;
  }

  // OLED refresh — purely dirty-flag driven now (no periodic timer, no
  // auto-cycle). Draws only happen from an explicit action: a panel jump,
  // a scroll press, or a WiFi-glitch recovery. Never call drawOled() from
  // HTTP handlers directly; only here in loop().
  if (oledReady && !oledDrawing && oledDirty) {
    // Don't SPI-write while WiFi TX is in flight — that's the actual
    // collision causing invert/flip. Wait for a quiet gap; if traffic
    // keeps stealing every gap, force the draw anyway after 2s so the
    // display never fully freezes.
    static unsigned long pendingSince = 0;
    if (pendingSince == 0) pendingSince = millis();
    bool quiet = millis() - lastHttpActivityAt > OLED_QUIET_WINDOW;
    bool starved = millis() - pendingSince > 2000;
    if (quiet || starved) {
      pendingSince = 0;
      drawOled();
    }
    // else: leave oledDirty set, retry next loop iteration
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
