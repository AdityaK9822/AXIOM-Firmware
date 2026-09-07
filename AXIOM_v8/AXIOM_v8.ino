/*
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║                                AXIOM  v8                                 ║
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
 *  CHANGES in v8:
 *    - CHANGED: compact experimental build — trimmed dashboard HTML/footer.
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

// ─── HARDWARE PINS ───────────────────────────────────────────────────────────
#define NEO_PIN 48
#define NEO_COUNT 1
Adafruit_NeoPixel neo(NEO_COUNT, NEO_PIN, NEO_GRB + NEO_KHZ800);

#define OLED_MOSI_PIN 11
#define OLED_SCK_PIN 12
#define OLED_DC_PIN 9
#define OLED_RST_PIN 14
#define OLED_CS_PIN 10
U8G2_SH1106_128X64_NONAME_F_4W_HW_SPI oled(U8G2_R0, OLED_CS_PIN, OLED_DC_PIN, OLED_RST_PIN);

// ─── GLOBAL STATE ────────────────────────────────────────────────────────────
enum OledPage { PG_HOME = 0, PG_WIFI, PG_SNIFFER, PG_KISMET, PG_PMKID, PG_GPIO, PG_COUNT };
const char *oledPageNames[PG_COUNT] = {"HOME", "WIFI", "SNIFFER", "KISMET", "PMKID", "GPIO"};
int oledPage = PG_HOME;
bool oledReady = false;
bool oledDirty = true;

static const int OUT_PINS[] = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 17, 18, 21, 38, 39, 40, 41, 42, 45, 46};
static const int OUT_COUNT = 24;
static const int IN_PINS[] = {1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18};
static const int IN_COUNT = 18;
static const int ADC_PINS[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
static const int ADC_COUNT = 10;
bool gpioStates[24] = {};

#define GPIO_OUT_1 4
#define GPIO_OUT_2 5
#define GPIO_OUT_3 6
uint8_t pwmDuty[3] = {0, 0, 0};
bool pwmMode[3] = {false, false, false};
#define PWM_FREQ 5000
#define PWM_RES 8

#define DEFAULT_AP_SSID "AXIOM-Controller"
#define DEFAULT_AP_PASS "axiom1234"
#define MDNS_HOST "axiom"
const IPAddress AP_IP(192, 168, 4, 1);
const IPAddress AP_GW(192, 168, 4, 1);
const IPAddress AP_SN(255, 255, 255, 0);

WebServer http(80);
WebSocketsServer wsChat(81);
Preferences prefs;
String apSSID, apPass;

String bleResults = "[]";
bool bleScanning = false;
String staConnStatus = "disconnected";
String staSSID = "";
unsigned long staTimeout = 0;

uint32_t touchVal[2] = {0, 0};
bool touchActive[2] = {false, false};
bool prevTouch[2] = {false, false};
String touchAction[2] = {"none", "none"};
#define TOUCH_THRESHOLD 40000

// ─── PACKET SNIFFER STATE ────────────────────────────────────────────────────
#define MAX_PKT_LOG 60
struct PktEntry { char srcMAC[18]; char dstMAC[18]; uint8_t type; uint8_t subtype; int8_t rssi; uint8_t channel; char info[32]; uint32_t ts; };
PktEntry pktLog[MAX_PKT_LOG];
volatile int pktHead = 0, pktTotal = 0;
bool snifferActive = false, deauthMode = false, kismetMode = false, pmkidMode = false;
int snifferChan = 1;
unsigned long lastChanHop = 0;
bool chanHopping = false;

volatile int _deauthCnt = 0;
volatile char _deauthMAC[20] = "--";
int deauthCnt = 0, deauthChan = 1;
String deauthLast = "--";

int beaconCnt = 0;
char beaconSSID[33] = "--";
unsigned long beaconWindow = 0;
int beaconBurst = 0;

#define MAX_AP 20
#define MAX_CLI 30
struct APRecord { char bssid[18]; char ssid[33]; int8_t rssi; uint8_t ch; uint8_t enc; bool valid; uint32_t ts; };
struct CLIRecord { char mac[18]; char bssid[18]; int8_t rssi; uint32_t ts; bool valid; };
APRecord kisAPs[MAX_AP] = {};
CLIRecord kisCLIs[MAX_CLI] = {};

#define MAX_PMKID 10
struct PMKIDEntry { char bssid[18]; char client[18]; char pmkid[40]; uint32_t ts; };
PMKIDEntry pmkidLog[MAX_PMKID] = {};
int pmkidCount = 0;

#define MAX_PROBE 20
struct ProbeEntry { char mac[18]; char ssid[33]; uint32_t ts; };
ProbeEntry probeLog[MAX_PROBE] = {};
int probeCount = 0;

// ─── OUI TABLE ───────────────────────────────────────────────────────────────
struct OuiEntry { uint8_t p[3]; const char *v; };
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
    if (m[0] == OUI[i].p[0] && m[1] == OUI[i].p[1] && m[2] == OUI[i].p[2]) return OUI[i].v;
  return "?";
}

// ─── HELPERS ─────────────────────────────────────────────────────────────────
String jb(bool v) { return v ? "true" : "false"; }
String esc(String s) { s.replace("\\", "\\\\"); s.replace("\"", "\\\""); s.replace("\n", "\\n"); s.replace("\r", "\\r"); s.replace("\t", "\\t"); return s; }
String macStr(const uint8_t *m) { char b[18]; snprintf(b, 18, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]); return b; }
String hexStr(const uint8_t *d, int len) { String s = ""; char h[3]; for (int i = 0; i < len && i < 32; i++) { snprintf(h, 3, "%02X", d[i]); s += h; } return s; }
String nowTs() { unsigned long s = millis() / 1000, m = (s / 60) % 60, h = (s / 3600) % 24; char b[10]; snprintf(b, 10, "%02lu:%02lu:%02lu", h, m, s % 60); return b; }
int pinIndex(int pin) { for (int i = 0; i < OUT_COUNT; i++) if (OUT_PINS[i] == pin) return i; return -1; }
void setNeo(uint8_t r, uint8_t g, uint8_t b) { neo.setPixelColor(0, neo.Color(r, g, b)); neo.show(); }
void broadcastChat(String j) { wsChat.broadcastTXT(j); }

struct ClientRec { uint8_t mac[6]; uint32_t joinMs; bool valid; };
ClientRec clientLog[8] = {};
void logClient(const uint8_t *m) { for (int i = 0; i < 8; i++) if (!clientLog[i].valid) { memcpy(clientLog[i].mac, m, 6); clientLog[i].joinMs = millis(); clientLog[i].valid = true; return; } }
uint32_t clientAge(const uint8_t *m) { for (int i = 0; i < 8; i++) if (clientLog[i].valid && memcmp(clientLog[i].mac, m, 6) == 0) return (millis() - clientLog[i].joinMs) / 1000; return 0; }

String scanPorts(const String &ip) {
  WiFiClient c; String out = "["; bool first = true;
  static const int PORTS[] = {80, 443, 22, 1883, 8080, 5900, 21, 0};
  static const char* SVCS[] = {"HTTP", "HTTPS", "SSH", "MQTT", "Alt", "VNC", "FTP", nullptr};
  for (int i = 0; SVCS[i]; i++) {
    if (c.connect(ip.c_str(), PORTS[i], 80)) {
      if (!first) out += ",";
      out += "{\"p\":" + String(PORTS[i]) + ",\"s\":\"" + SVCS[i] + "\"}";
      first = false; c.stop();
    }
  }
  return out + "]";
}

// ─── PROMISCUOUS CALLBACK ────────────────────────────────────────────────────
void IRAM_ATTR promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (!snifferActive && !deauthMode && !kismetMode && !pmkidMode) return;
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  const uint8_t *pl = pkt->payload;
  uint8_t fc = pl[0], ftyp = (fc >> 2) & 0x03, fsub = (fc >> 4) & 0x0F;
  int8_t rssi = pkt->rx_ctrl.rssi;
  uint8_t ch = pkt->rx_ctrl.channel;

  if (ftyp == 0 && (fsub == 12 || fsub == 10)) { // DEAUTH
    _deauthCnt++;
    if (pkt->rx_ctrl.sig_len >= 16) snprintf((char *)_deauthMAC, 20, "%02X:%02X:%02X:%02X:%02X:%02X", pl[10], pl[11], pl[12], pl[13], pl[14], pl[15]);
  }

  if (ftyp == 0 && fsub == 8 && pkt->rx_ctrl.sig_len > 36) { // BEACON
    uint8_t bssid[6]; memcpy(bssid, pl + 16, 6);
    const uint8_t *tags = pl + 36; int tlen = pkt->rx_ctrl.sig_len - 36; char ssid[33] = {0};
    for (int i = 0; i < tlen - 2;) { if (tags[i] == 0) { int sl = tags[i + 1]; if (sl > 32) sl = 32; memcpy(ssid, tags + i + 2, sl); ssid[sl] = 0; break; } i += 2 + tags[i + 1]; }
    if (kismetMode) {
      bool found = false;
      for (int i = 0; i < MAX_AP; i++) if (kisAPs[i].valid && memcmp(kisAPs[i].bssid, macStr(bssid).c_str(), 17) == 0) { kisAPs[i].rssi = rssi; kisAPs[i].ts = millis(); found = true; break; }
      if (!found) for (int i = 0; i < MAX_AP; i++) if (!kisAPs[i].valid) { strncpy(kisAPs[i].bssid, macStr(bssid).c_str(), 17); strncpy(kisAPs[i].ssid, ssid, 32); kisAPs[i].rssi = rssi; kisAPs[i].ch = ch; kisAPs[i].enc = 0; kisAPs[i].valid = true; kisAPs[i].ts = millis(); break; }
    }
    if (millis() - beaconWindow > 2000) { beaconWindow = millis(); beaconBurst = 0; }
    beaconBurst++;
    if (beaconBurst > 50) strncpy(beaconSSID, ssid, 32);
    beaconCnt = beaconBurst;
  }

  if (ftyp == 0 && fsub == 4 && pkt->rx_ctrl.sig_len > 24) { // PROBE
    uint8_t src[6]; memcpy(src, pl + 10, 6);
    const uint8_t *tags = pl + 24; int tlen = pkt->rx_ctrl.sig_len - 24; char ssid[33] = {0};
    for (int i = 0; i < tlen - 2;) { if (tags[i] == 0) { int sl = tags[i + 1]; if (sl > 0 && sl <= 32) { memcpy(ssid, tags + i + 2, sl); ssid[sl] = 0; } break; } i += 2 + tags[i + 1]; }
    if (strlen(ssid) > 0) {
      bool found = false;
      for (int i = 0; i < probeCount; i++) if (memcmp(probeLog[i].mac, macStr(src).c_str(), 17) == 0 && strcmp(probeLog[i].ssid, ssid) == 0) { probeLog[i].ts = millis(); found = true; break; }
      if (!found && probeCount < MAX_PROBE) { strncpy(probeLog[probeCount].mac, macStr(src).c_str(), 17); strncpy(probeLog[probeCount].ssid, ssid, 32); probeLog[probeCount].ts = millis(); probeCount++; }
    }
  }

  if (pmkidMode && ftyp == 2 && pkt->rx_ctrl.sig_len > 80) { // PMKID
    const uint8_t *data = pl + 32; int dlen = pkt->rx_ctrl.sig_len - 32;
    if (dlen > 32 && data[0] == 0x02 && data[1] == 0x03) {
      uint8_t keyinfo2 = data[6]; bool ack = (keyinfo2 >> 7) & 1, mic = (keyinfo2 >> 0) & 1;
      if (ack && !mic && dlen > 116) {
        const uint8_t *pmkid_ptr = data + 88;
        if (pmkid_ptr[0] == 0xdd && pmkid_ptr[1] == 0x14) {
          uint8_t src[6], dst[6]; memcpy(src, pl + 10, 6); memcpy(dst, pl + 4, 6);
          if (pmkidCount < MAX_PMKID) {
            strncpy(pmkidLog[pmkidCount].bssid, macStr(src).c_str(), 17); strncpy(pmkidLog[pmkidCount].client, macStr(dst).c_str(), 17);
            strncpy(pmkidLog[pmkidCount].pmkid, hexStr(pmkid_ptr + 6, 16).c_str(), 33); pmkidLog[pmkidCount].ts = millis(); pmkidCount++;
          }
        }
      }
    }
  }

  if (snifferActive) { // LOG
    int idx = pktHead % MAX_PKT_LOG;
    if (pkt->rx_ctrl.sig_len >= 16) {
      snprintf(pktLog[idx].srcMAC, 18, "%02X:%02X:%02X:%02X:%02X:%02X", pl[10], pl[11], pl[12], pl[13], pl[14], pl[15]);
      snprintf(pktLog[idx].dstMAC, 18, "%02X:%02X:%02X:%02X:%02X:%02X", pl[4], pl[5], pl[6], pl[7], pl[8], pl[9]);
    }
    pktLog[idx].type = ftyp; pktLog[idx].subtype = fsub; pktLog[idx].rssi = rssi; pktLog[idx].channel = ch; pktLog[idx].ts = millis();
    static const char *mnames[16] = {"ASSOC_REQ","ASSOC_RSP","REASSOC_REQ","REASSOC_RSP","PROBE_REQ","PROBE_RSP","","","BEACON","ATIM","DISASSOC","AUTH","DEAUTH","ACTION","","?"};
    if (ftyp == 0) snprintf(pktLog[idx].info, 32, "MGMT/%s", mnames[fsub & 15]);
    else if (ftyp == 1) snprintf(pktLog[idx].info, 32, "CTRL/0x%X", fsub);
    else if (ftyp == 2) snprintf(pktLog[idx].info, 32, "DATA/0x%X", fsub);
    else snprintf(pktLog[idx].info, 32, "EXT/0x%X", fsub);
    pktHead++; if (pktTotal < MAX_PKT_LOG) pktTotal++;
  }
}

// ─── BLE SCANNER ─────────────────────────────────────────────────────────────
class AxiomBLECb : public BLEAdvertisedDeviceCallbacks {
public:
  String json = "["; int cnt = 0;
  void onResult(BLEAdvertisedDevice d) {
    if (cnt > 0) json += ",";
    String nm = d.haveName() ? d.getName().c_str() : "Unknown"; nm.replace("\"", "'");
    String mfr = "";
    if (d.haveManufacturerData()) {
      String raw = d.getManufacturerData().c_str();
      if (raw.length() >= 2) {
        uint16_t id = (uint8_t)raw[1] << 8 | (uint8_t)raw[0];
        if (id == 0x004C) mfr = "Apple"; else if (id == 0x0006) mfr = "Microsoft"; else if (id == 0x02E5) mfr = "Espressif"; else if (id == 0x0075) mfr = "Samsung";
        else { char h[8]; snprintf(h, 8, "0x%04X", id); mfr = h; }
      }
    }
    json += "{\"n\":\"" + nm + "\",\"a\":\"" + String(d.getAddress().toString().c_str()) + "\",\"r\":" + String(d.getRSSI()) + ",\"m\":\"" + mfr + "\"}";
    cnt++;
  }
};
AxiomBLECb *bleCb = nullptr;
BLEScan *pBLEScan = nullptr;

void wsEvent(uint8_t num, WStype_t type, uint8_t *pl, size_t len) {
  switch (type) {
  case WStype_CONNECTED: broadcastChat("{\"t\":\"sys\",\"msg\":\"User joined\",\"n\":" + String(wsChat.connectedClients()) + "}"); break;
  case WStype_DISCONNECTED: broadcastChat("{\"t\":\"sys\",\"msg\":\"User left\",\"n\":" + String(wsChat.connectedClients()) + "}"); break;
  case WStype_TEXT: {
    StaticJsonDocument<300> doc; if (deserializeJson(doc, (char *)pl)) return;
    if (String((const char *)doc["t"]) == "chat") {
      String nm = String((const char *)doc["n"]).substring(0, 16); String tx = String((const char *)doc["m"]).substring(0, 200);
      nm.replace("\"", "'"); tx.replace("\"", "'");
      broadcastChat("{\"t\":\"chat\",\"n\":\"" + nm + "\",\"m\":\"" + tx + "\",\"ts\":\"" + nowTs() + "\"}");
    }
    break;
  }
  default: break;
  }
}

void startPromiscuous() { if (!snifferActive && !deauthMode && !kismetMode && !pmkidMode) return; esp_wifi_set_promiscuous(true); esp_wifi_set_promiscuous_rx_cb(&promisc_cb); }
void stopPromiscuous() { if (snifferActive || deauthMode || kismetMode || pmkidMode) return; esp_wifi_set_promiscuous(false); esp_wifi_set_promiscuous_rx_cb(nullptr); }

// ══════════════════════════════════════════════════════════════════════════════
//  OLED DISPLAY — REDESIGNED GLITCH-FREE UI
// ══════════════════════════════════════════════════════════════════════════════
String truncateStr(String str, int maxLen) { if (str.length() > maxLen) return str.substring(0, maxLen - 1) + "."; return str; }
String formatTime(unsigned long ms) {
  unsigned long s = ms / 1000, h = s / 3600, m = (s % 3600) / 60; s = s % 60; char buf[12];
  if (h > 0) snprintf(buf, sizeof(buf), "%luh %lum", h, m); else snprintf(buf, sizeof(buf), "%lum %lus", m, s);
  return String(buf);
}

void oledHeader(const char *title) {
  oled.setFont(u8g2_font_6x10_tf);
  oled.drawStr(0, 9, "AXIOM");
  oled.drawStr(128 - (strlen(title) * 6), 9, title);
  oled.drawLine(0, 11, 128, 11);
}

void oledKV(int y, const char *label, String value) {
  oled.drawStr(0, y, label);
  String valStr = truncateStr(value, 13);
  int valWidth = valStr.length() * 6;
  int xPos = 128 - valWidth;
  if (xPos < 60) xPos = 60; 
  oled.drawStr(xPos, y, valStr.c_str());
}

void oledFooter(const char *left, const char *right) {
  oled.drawLine(0, 52, 128, 52);
  oled.drawStr(0, 62, left);
  oled.drawStr(128 - (strlen(right) * 6), 62, right);
}

void drawOled() {
  if (!oledReady || !oledDirty) return;
  oledDirty = false;
  
  oled.clearBuffer();
  oled.setFont(u8g2_font_6x10_tf);
  
  switch (oledPage) {
    case PG_HOME:
      oledHeader("HOME");
      oledKV(23, "Uptime:", formatTime(millis()));
      oledKV(35, "Heap:", String(ESP.getFreeHeap() / 1024) + " KB");
      oledKV(47, "CPU/Temp:", String(getCpuFrequencyMhz()) + "M / " + String((int)temperatureRead()) + "C");
      oledFooter(String("1/" + String(PG_COUNT)).c_str(), WiFi.softAPIP().toString().c_str());
      break;
    case PG_WIFI:
      oledHeader("WIFI");
      oledKV(23, "AP:", truncateStr(apSSID, 13));
      oledKV(35, "STA:", (WiFi.status() == WL_CONNECTED) ? truncateStr(WiFi.SSID(), 13) : "Disconnected");
      oledKV(47, "Clients:", String(WiFi.softAPgetStationNum()));
      oledFooter(String("2/" + String(PG_COUNT)).c_str(), (WiFi.status() == WL_CONNECTED) ? (String(WiFi.RSSI()) + " dBm").c_str() : "--");
      break;
    case PG_SNIFFER:
      oledHeader("SNIFFER");
      oledKV(23, "Status:", snifferActive ? "ACTIVE" : "IDLE");
      oledKV(35, "Channel:", chanHopping ? "HOPPING" : String(snifferChan));
      oledKV(47, "Packets:", String(pktTotal));
      oledFooter(String("3/" + String(PG_COUNT)).c_str(), String("Deauth: " + String(deauthCnt)).c_str());
      break;
    case PG_KISMET: {
      oledHeader("KISMET");
      int apCount = 0; for (int i = 0; i < MAX_AP; i++) if (kisAPs[i].valid) apCount++;
      oledKV(23, "Status:", kismetMode ? "MAPPING" : "IDLE");
      oledKV(35, "APs:", String(apCount));
      oledKV(47, "Probes:", String(probeCount));
      oledFooter(String("4/" + String(PG_COUNT)).c_str(), "CH: HOP");
      break;
    }
    case PG_PMKID:
      oledHeader("PMKID");
      oledKV(23, "Status:", pmkidMode ? "LISTENING" : "IDLE");
      oledKV(35, "Captured:", String(pmkidCount));
      oledKV(47, "Protocol:", "WPA2");
      oledFooter(String("5/" + String(PG_COUNT)).c_str(), "LAB ONLY");
      break;
    case PG_GPIO: {
      oledHeader("GPIO");
      int highCount = 0; for (int i = 0; i < OUT_COUNT; i++) if (gpioStates[i]) highCount++;
      oledKV(23, "Outputs:", String(highCount) + "/" + String(OUT_COUNT) + " HIGH");
      oledKV(35, "Touch 1:", touchActive[0] ? "ACTIVE" : "idle");
      oledKV(47, "Touch 2:", touchActive[1] ? "ACTIVE" : "idle");
      oledFooter(String("6/" + String(PG_COUNT)).c_str(), "ESP32-S3");
      break;
    }
  }
  oled.sendBuffer();
}

// ══════════════════════════════════════════════════════════════════════════════
//  WEB DASHBOARD (SIMPLIFIED CLEAN UI)
// ══════════════════════════════════════════════════════════════════════════════
const char HTML[] PROGMEM = R"=====(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1"/>
<title>AXIOM v11</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Courier New',monospace;background:#0d1117;color:#c9d1d9;padding:12px;max-width:820px;margin:auto}
a{color:#58a6ff;text-decoration:none}
.hdr{display:flex;justify-content:space-between;align-items:center;padding:12px;background:#161b22;border:1px solid #30363d;border-radius:6px;margin-bottom:15px}
.logo{font-size:1.4rem;font-weight:bold;color:#58a6ff;letter-spacing:2px}
.tabs{display:flex;flex-wrap:wrap;gap:5px;margin-bottom:15px}
.tab{padding:8px 12px;background:#161b22;border:1px solid #30363d;color:#8b949e;border-radius:6px;cursor:pointer;font-size:.8rem}
.tab.active{color:#fff;background:#21262d;border-color:#58a6ff}
.card{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:15px;margin-bottom:15px}
.ct{font-size:.8rem;color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:8px;margin-bottom:12px;text-transform:uppercase;letter-spacing:1px}
.row{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #21262d;font-size:.85rem}
.row:last-child{border-bottom:none}
.lbl{color:#8b949e}.val{color:#c9d1d9;text-align:right}
.btn{display:inline-block;background:#21262d;border:1px solid #30363d;color:#c9d1d9;padding:8px 14px;border-radius:6px;cursor:pointer;font-family:inherit;font-size:.8rem;margin:4px 2px}
.btn:hover{border-color:#58a6ff;color:#fff}
.btn.blue{border-color:#58a6ff;color:#58a6ff}.btn.green{border-color:#3fb950;color:#3fb950}.btn.red{border-color:#f85149;color:#f85149}
.grid{display:grid;grid-template-columns:1fr;gap:15px}
@media(min-width:600px){.grid{grid-template-columns:1fr 1fr}}
.grid-3{display:grid;grid-template-columns:repeat(auto-fill,minmax(70px,1fr));gap:8px}
.gpio-btn{padding:8px;background:#0d1117;border:1px solid #30363d;border-radius:6px;text-align:center;cursor:pointer}
.gpio-btn .gn{font-size:.7rem;color:#8b949e;display:block}.gpio-btn .gs{font-size:.75rem;font-weight:bold}
.gpio-btn.on{border-color:#3fb950}.gpio-btn.on .gs{color:#3fb950}
input,select{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:8px;border-radius:6px;width:100%;font-family:inherit;font-size:.85rem;margin-bottom:10px}
table{width:100%;border-collapse:collapse;font-size:.8rem}
th{text-align:left;padding:8px;border-bottom:1px solid #30363d;color:#8b949e}td{padding:8px;border-bottom:1px solid #21262d}
.log-box{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:10px;height:180px;overflow-y:auto;font-size:.75rem}
.warn{background:#f8514922;border:1px solid #f85149;color:#f85149;padding:10px;border-radius:6px;margin-bottom:15px;font-size:.8rem}
.modal-bg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.8);z-index:100;align-items:center;justify-content:center}
.modal-bg.show{display:flex}.modal{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;width:90%;max-width:350px}
</style>
</head>
<body>
<div class="hdr">
  <div class="logo">AXIOM</div>
  <div style="font-size:.75rem"><span id="hIP">192.168.4.1</span> | <span id="staPill" style="color:#f85149">STA OFF</span></div>
</div>
<div class="tabs" id="tabs">
  <button class="tab active" onclick="P('wifi',this)">WIFI</button>
  <button class="tab" onclick="P('gpio',this)">GPIO</button>
  <button class="tab" onclick="P('ble',this)">BLE</button>
  <button class="tab" onclick="P('sniffer',this)">SNIFFER</button>
  <button class="tab" onclick="P('kismet',this)">KISMET</button>
  <button class="tab" onclick="P('pmkid',this)">PMKID</button>
  <button class="tab" onclick="P('recon',this)">RECON</button>
  <button class="tab" onclick="P('data',this)">DATA PANEL</button>
  <button class="tab" onclick="P('display',this)">DISPLAY</button>
  <button class="tab" onclick="P('chat',this)">CHAT</button>
  <button class="tab" onclick="P('system',this)">SYSTEM</button>
</div>

<!-- WIFI -->
<div class="page" id="wifiPage">
  <div class="grid">
    <div class="card" style="grid-column:1/-1">
      <div class="ct">WIFI SCANNER <button class="btn blue" style="float:right" onclick="wScan()">SCAN</button></div>
      <div id="netList"><div style="color:#8b949e;text-align:center;padding:14px">Scan to see networks</div></div>
    </div>
    <div class="card">
      <div class="ct">UPLINK (STA)</div>
      <div class="row"><span class="lbl">STATUS</span><span class="val" id="staSt">—</span></div>
      <div class="row"><span class="lbl">NETWORK</span><span class="val" id="staS">—</span></div>
      <div class="row"><span class="lbl">ESP IP</span><span class="val" id="staI">—</span></div>
      <div class="row"><span class="lbl">RSSI</span><span class="val" id="staR">—</span></div>
      <button class="btn red" id="discBtn" onclick="wDisc()" style="display:none;width:100%;margin-top:10px">DISCONNECT</button>
    </div>
    <div class="card">
      <div class="ct">AP CONFIG</div>
      <input type="text" id="nSsid" placeholder="NEW SSID"/>
      <input type="password" id="nPass" placeholder="NEW PASSWORD"/>
      <input type="password" id="nPassC" placeholder="CONFIRM PASSWORD"/>
      <button class="btn green" onclick="saveAP()" style="width:100%">SAVE & REBOOT</button>
    </div>
  </div>
</div>

<!-- GPIO -->
<div class="page" id="gpioPage" style="display:none">
  <div class="card">
    <div class="ct">OUTPUT PINS</div>
    <div class="grid-3" id="gpioGrid"></div>
  </div>
  <div class="grid">
    <div class="card">
      <div class="ct">PWM CONTROL</div>
      <div style="margin-bottom:10px"><label>GPIO 4</label><input type="range" min="0" max="255" oninput="setPWM(0,this.value)"/><button class="btn blue" style="width:100%" id="pm0" onclick="togPWM(0)">ENABLE PWM</button></div>
      <div style="margin-bottom:10px"><label>GPIO 5</label><input type="range" min="0" max="255" oninput="setPWM(1,this.value)"/><button class="btn blue" style="width:100%" id="pm1" onclick="togPWM(1)">ENABLE PWM</button></div>
      <div><label>GPIO 6</label><input type="range" min="0" max="255" oninput="setPWM(2,this.value)"/><button class="btn blue" style="width:100%" id="pm2" onclick="togPWM(2)">ENABLE PWM</button></div>
    </div>
    <div class="card">
      <div class="ct">INPUTS & TOUCH</div>
      <div class="row"><span class="lbl">GPIO 7</span><span class="val" id="in0">—</span></div>
      <div class="row"><span class="lbl">GPIO 8</span><span class="val" id="in1">—</span></div>
      <div class="row"><span class="lbl">TOUCH 1</span><span class="val" id="tv0">—</span></div>
      <div class="row"><span class="lbl">TOUCH 2</span><span class="val" id="tv1">—</span></div>
    </div>
  </div>
</div>

<!-- BLE -->
<div class="page" id="blePage" style="display:none">
  <div class="card">
    <div class="ct">BLUETOOTH LE <button class="btn blue" style="float:right" onclick="bScan()">SCAN BLE</button></div>
    <table><thead><tr><th>NAME</th><th>MAC</th><th>MFR</th><th>RSSI</th></tr></thead><tbody id="bT"><tr><td colspan="4" style="text-align:center;color:#8b949e">Scan to find devices</td></tr></tbody></table>
  </div>
</div>

<!-- SNIFFER -->
<div class="page" id="snifferPage" style="display:none">
  <div class="warn">AUTHORIZED LAB USE ONLY. Capturing 802.11 frames on networks you do not own is illegal.</div>
  <div class="card">
    <div class="ct">PACKET SNIFFER <span id="snifSt" style="float:right;color:#8b949e"></span></div>
    <button class="btn green" id="snifBtn" onclick="togSniffer()">START CAPTURE</button>
    <button class="btn blue" onclick="clearPkts()">CLEAR</button>
    <select id="chanSel" style="width:auto;display:inline-block"><option value="0">ALL CH (hop)</option><option value="1">CH 1</option><option value="6">CH 6</option><option value="11">CH 11</option></select>
    <div class="log-box" id="pktLog" style="margin-top:10px">Start capture to see packets...</div>
    <div style="display:flex;justify-content:space-between;margin-top:8px;font-size:.75rem;color:#8b949e">
      <span>TOTAL: <span id="pktTotal" style="color:#58a6ff">0</span></span><span>MGMT: <span id="pktMgmt" style="color:#58a6ff">0</span></span><span>DATA: <span id="pktData" style="color:#3fb950">0</span></span><span>CTRL: <span id="pktCtrl" style="color:#d29922">0</span></span>
    </div>
  </div>
</div>

<!-- KISMET -->
<div class="page" id="kismetPage" style="display:none">
  <div class="warn">AUTHORIZED LAB USE ONLY. Passively maps all visible APs and clients.</div>
  <div class="card">
    <div class="ct">KISMET MAPPER <span id="kisSt" style="float:right;color:#8b949e"></span></div>
    <button class="btn green" id="kisBtn" onclick="togKismet()">START KISMET</button>
    <button class="btn blue" onclick="clearKismet()">CLEAR</button>
  </div>
  <div class="card">
    <div class="ct">ACCESS POINTS</div>
    <table><thead><tr><th>BSSID</th><th>SSID</th><th>CH</th><th>RSSI</th></tr></thead><tbody id="kApT"><tr><td colspan="4" style="text-align:center;color:#8b949e">No APs yet</td></tr></tbody></table>
  </div>
  <div class="card">
    <div class="ct">PROBE REQUESTS</div>
    <table><thead><tr><th>CLIENT MAC</th><th>PROBED SSID</th></tr></thead><tbody id="kProbeT"><tr><td colspan="2" style="text-align:center;color:#8b949e">No probes yet</td></tr></tbody></table>
  </div>
</div>

<!-- PMKID -->
<div class="page" id="pmkidPage" style="display:none">
  <div class="warn">AUTHORIZED LAB USE ONLY. PMKID capture for WPA2 offline analysis.</div>
  <div class="card">
    <div class="ct">PMKID CAPTURE <span id="pmkSt" style="float:right;color:#8b949e"></span></div>
    <button class="btn green" id="pmkBtn" onclick="togPMKID()">START CAPTURE</button>
    <table style="margin-top:10px"><thead><tr><th>AP BSSID</th><th>CLIENT MAC</th><th>PMKID HASH</th></tr></thead><tbody id="pmkT"><tr><td colspan="3" style="text-align:center;color:#8b949e">No PMKID captured yet</td></tr></tbody></table>
  </div>
</div>

<!-- RECON -->
<div class="page" id="reconPage" style="display:none">
  <div class="card">
    <div class="ct">CLIENT RECON <span id="rSt" style="float:right;color:#8b949e"></span></div>
    <button class="btn blue" onclick="doRecon()">SCAN CLIENTS</button>
    <table style="margin-top:10px"><thead><tr><th>VENDOR</th><th>IP</th><th>MAC</th><th>PORTS</th></tr></thead><tbody id="rT"><tr><td colspan="4" style="text-align:center;color:#8b949e">No scan yet</td></tr></tbody></table>
  </div>
</div>

<!-- DATA PANEL -->
<div class="page" id="dataPage" style="display:none">
  <div class="card">
    <div class="ct">REST DATA ENDPOINTS</div>
    <button class="btn green" onclick="fetchApiData('/data')">GET /data</button>
    <button class="btn blue" onclick="fetchApiData('/gpio')">GET /gpio</button>
    <button class="btn blue" onclick="fetchApiData('/wifi')">GET /wifi</button>
    <button class="btn blue" onclick="fetchApiData('/bluetooth')">GET /bluetooth</button>
    <a href="/data" target="_blank" class="btn red">OPEN /data IN TAB</a>
    <pre id="jsonViewer" style="background:#0d1117;border:1px solid #30363d;padding:12px;border-radius:6px;font-size:.75rem;overflow:auto;max-height:300px;margin-top:10px;color:#3fb950">Loading telemetry...</pre>
  </div>
</div>

<!-- DISPLAY -->
<div class="page" id="displayPage" style="display:none">
  <div class="card">
    <div class="ct">OLED SH1106 1.3" (SPI)</div>
    <div class="row"><span class="lbl">CURRENT PAGE</span><span class="val" id="oledPg">—</span></div>
    <div style="display:flex;gap:10px;margin-top:10px">
      <button class="btn blue" style="flex:1" onclick="oledNav('prev')">PREV</button>
      <button class="btn blue" style="flex:1" onclick="oledNav('next')">NEXT</button>
    </div>
    <div class="grid-3" id="oledPages" style="margin-top:10px"></div>
  </div>
</div>

<!-- CHAT -->
<div class="page" id="chatPage" style="display:none">
  <div class="card" style="display:flex;flex-direction:column;height:calc(100vh - 220px)">
    <div class="ct">AXIOM LAN CHAT <span id="onl" style="float:right;color:#8b949e">0 ONLINE</span></div>
    <div id="cMsgs" style="flex:1;overflow-y:auto;margin-bottom:10px;font-size:.8rem"></div>
    <div style="display:flex;gap:5px">
      <input id="nIn" type="text" placeholder="NAME" style="width:80px"/>
      <input id="mIn" type="text" placeholder="Message..." onkeydown="if(event.key==='Enter')sChat()"/>
      <button class="btn green" onclick="sChat()">SEND</button>
    </div>
  </div>
</div>

<!-- SYSTEM -->
<div class="page" id="systemPage" style="display:none">
  <div class="grid">
    <div class="card">
      <div class="ct">ESP32-S3 INFO</div>
      <div class="row"><span class="lbl">UPTIME</span><span class="val" id="upt">—</span></div>
      <div class="row"><span class="lbl">FREE HEAP</span><span class="val" id="hp">—</span></div>
      <div class="row"><span class="lbl">CHIP TEMP</span><span class="val" id="tmp">—</span></div>
      <div class="row"><span class="lbl">CPU FREQ</span><span class="val" id="cpu">—</span></div>
      <div class="row"><span class="lbl">AP CLIENTS</span><span class="val" id="sCl">—</span></div>
    </div>
    <div class="card">
      <div class="ct">CONTROLS</div>
      <label>CPU FREQUENCY</label>
      <select id="cpuF"><option value="240">240 MHz</option><option value="160">160 MHz</option><option value="80">80 MHz</option></select>
      <button class="btn blue" onclick="setCPU()" style="width:100%">APPLY CPU</button>
      <label style="margin-top:10px">DEEP SLEEP (s)</label>
      <input type="number" id="slpS" value="30" min="5" max="3600"/>
      <button class="btn red" onclick="doSleep()" style="width:100%">SLEEP</button>
      <button class="btn red" onclick="doReboot()" style="width:100%;margin-top:5px">REBOOT</button>
    </div>
  </div>
</div>

<div class="modal-bg" id="cModal">
  <div class="modal">
    <h3 style="color:#58a6ff;margin-bottom:15px">CONNECT TO NETWORK</h3>
    <label>SSID</label><input type="text" id="mSSID" readonly/>
    <label>PASSWORD</label><input type="password" id="mPw" placeholder="Enter password..."/>
    <span id="mSt" style="font-size:.75rem;display:block;margin-bottom:10px"></span>
    <button class="btn green" onclick="doConn()" style="width:100%">CONNECT</button>
    <button class="btn red" onclick="closeM()" style="width:100%;margin-top:5px">CANCEL</button>
  </div>
</div>

<script>
const $=id=>document.getElementById(id);
function set(id,v){const e=$(id);if(e)e.textContent=v;}
function P(n,el){
  document.querySelectorAll('.page').forEach(p=>p.style.display='none');
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  $(n+'Page').style.display='block';
  if(el)el.classList.add('active');
  if(n==='chat'&&!ws)initWS();
  if(n==='data')fetchApiData('/data');
}

// GPIO GRID
const OUT_PINS=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,17,18,21,38,39,40,41,42,45,46];
const gpioState={};
function buildGPIOGrid(){
  const g=$('gpioGrid');g.innerHTML='';
  OUT_PINS.forEach(p=>{
    gpioState[p]=false;
    const d=document.createElement('div');
    d.className='gpio-btn';d.id='gp'+p;
    d.innerHTML='<span class="gn">GPIO '+p+'</span><span class="gs">LOW</span>';
    d.onclick=()=>toggleGPIO(p);g.appendChild(d);
  });
}
function toggleGPIO(pin){
  fetch('/gpio/pin?pin='+pin+'&state='+(gpioState[pin]?0:1)).then(r=>r.json()).then(d=>{
    gpioState[pin]=d.state;
    const el=$('gp'+pin);el.className='gpio-btn '+(d.state?'on':'');
    el.querySelector('.gs').textContent=d.state?'HIGH':'LOW';
  });
}
buildGPIOGrid();

// POLLING
function poll(){
  fetch('/status').then(r=>r.json()).then(d=>{
    set('upt',Math.floor(d.uptime/3600000)+'h '+Math.floor((d.uptime/60000)%60)+'m '+(d.uptime/1000%60)+'s');
    set('hp',(d.heap/1024).toFixed(1)+' KB');set('tmp',d.temp.toFixed(1)+'C');set('cpu',d.cpu+' MHz');set('sCl',d.clients);
    const connected=d.sta==='connected';
    const stP=$('staPill');
    if(connected){
      stP.textContent='STA: '+(d.staSSID||'');stP.style.color='#3fb950';
      set('staSt','CONNECTED');set('staS',d.staSSID||'—');set('staI',d.staIp||'—');set('staR',d.staRSSI+' dBm');
      $('discBtn').style.display='block';
    } else {
      stP.textContent='STA OFF';stP.style.color='#f85149';
      set('staSt',(d.sta||'—').toUpperCase());set('staS','—');set('staI','—');set('staR','—');
      $('discBtn').style.display='none';
    }
    set('in0',d.inputs[0]?'HIGH':'LOW');set('in1',d.inputs[1]?'HIGH':'LOW');
    set('tv0',d.touch[0]);set('tv1',d.touch[1]);
  });
}
poll();setInterval(poll,2000);

// WIFI
let lastNets=[];
function wScan(){fetch('/wifi/scan').then(()=>setTimeout(wRes,5500));}
function wRes(){
  fetch('/wifi/results').then(r=>r.json()).then(d=>{
    if(d.status==='scanning'){setTimeout(wRes,1500);return;}
    lastNets=d.networks;const nl=$('netList');
    if(!d.networks.length){nl.innerHTML='<div style="color:#8b949e;text-align:center;padding:14px">No networks found</div>';return;}
    nl.innerHTML=d.networks.map(n=>'<div class="row" style="cursor:pointer" onclick="selNetwork(\''+n.ssid.replace(/'/g,"\\'")+'\')"><span><div style="color:#fff">'+(n.ssid||'<em>Hidden</em>')+'</div><div style="font-size:.7rem;color:#8b949e">CH '+n.channel+' · '+n.rssi+' dBm · '+(n.enc?'WPA':'OPEN')+'</div></span><span style="color:#3fb950">'+n.rssi+'</span></div>').join('');
  });
}
function selNetwork(ssid){$('mSSID').value=ssid;$('mPw').value='';$('mSt').textContent='';$('cModal').classList.add('show');}
function closeM(){$('cModal').classList.remove('show');}
function doConn(){
  $('mSt').textContent='Connecting...';$('mSt').style.color='#d29922';
  fetch('/wifi/connect',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'ssid='+encodeURIComponent($('mSSID').value)+'&pass='+encodeURIComponent($('mPw').value)})
  .then(r=>r.json()).then(d=>{if(d.status==='connecting'){$('mSt').textContent='Sent!';$('mSt').style.color='#3fb950';setTimeout(closeM,4000);}else{$('mSt').textContent='Error';$('mSt').style.color='#f85149';}});
}
function wDisc(){fetch('/wifi/disconnect');}
function saveAP(){
  const ss=$('nSsid').value.trim(),pw=$('nPass').value,pc=$('nPassC').value;
  if(!ss||pw.length<8||pw!==pc){alert('Invalid input');return;}
  fetch('/ap/config',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'ssid='+encodeURIComponent(ss)+'&pass='+encodeURIComponent(pw)}).then(()=>alert('Saved! Rebooting...'));
}

// OLED
const OLED_PAGES=['HOME','WIFI','SNIFFER','KISMET','PMKID','GPIO'];
function buildOledPages(){$('oledPages').innerHTML=OLED_PAGES.map((n,i)=>'<div class="gpio-btn" onclick="oledGoto('+i+')"><span class="gn">'+n+'</span></div>').join('');}
function highlightOledPage(id){document.querySelectorAll('#oledPages .gpio-btn').forEach((b,i)=>b.classList.toggle('on',i===id));}
function oledNav(dir){fetch('/display/'+dir).then(r=>r.json()).then(d=>{set('oledPg',d.name);highlightOledPage(d.page);});}
function oledGoto(id){fetch('/display/page?id='+id).then(r=>r.json()).then(d=>{set('oledPg',d.name);highlightOledPage(d.page);});}
buildOledPages();fetch('/display/status').then(r=>r.json()).then(d=>{set('oledPg',d.name);highlightOledPage(d.page);});

// GPIO PWM
function setPWM(ch,v){fetch('/gpio/pwm?ch='+ch+'&duty='+v);}
function togPWM(ch){fetch('/gpio/pwmmode?ch='+ch).then(r=>r.json()).then(d=>{$('pm'+ch).textContent=d.pwm?'DISABLE PWM':'ENABLE PWM';});}

// BLE
function bScan(){fetch('/ble/scan').then(()=>setTimeout(bRes,7000));}
function bRes(){
  fetch('/ble/results').then(r=>r.json()).then(d=>{
    if(d.status==='scanning'){setTimeout(bRes,1000);return;}
    const tb=$('bT');
    if(!d.devices.length){tb.innerHTML='<tr><td colspan="4" style="text-align:center;color:#8b949e">No BLE devices</td></tr>';return;}
    tb.innerHTML=d.devices.map(v=>'<tr><td>'+v.n+'</td><td>'+v.a+'</td><td>'+(v.m||'—')+'</td><td>'+v.r+'</td></tr>').join('');
  });
}

// SNIFFER
let snifOn=false,pktMgmt=0,pktData=0,pktCtrl=0,snifPoll=null;
function togSniffer(){
  snifOn=!snifOn;const ch=parseInt($('chanSel').value)||0;
  fetch('/sniffer?active='+snifOn+'&ch='+ch).then(()=>{
    $('snifBtn').textContent=snifOn?'STOP CAPTURE':'START CAPTURE';
    $('snifBtn').className=snifOn?'btn red':'btn green';
    set('snifSt',snifOn?'CAPTURING...':'STOPPED');
    if(snifOn)snifPoll=setInterval(fetchPkts,800);else clearInterval(snifPoll);
  });
}
function clearPkts(){pktMgmt=0;pktData=0;pktCtrl=0;set('pktTotal',0);set('pktMgmt',0);set('pktData',0);set('pktCtrl',0);$('pktLog').innerHTML='Cleared.';fetch('/sniffer/clear');}
function fetchPkts(){
  fetch('/sniffer/log').then(r=>r.json()).then(d=>{
    if(!d.pkts||!d.pkts.length)return;const log=$('pktLog');log.innerHTML='';
    d.pkts.forEach(p=>{
      let cls='#8b949e';if(p.t===2)cls='#3fb950';else if(p.t===1)cls='#d29922';else if(p.t===3)cls='#f85149';
      if(p.t===0)pktMgmt++;else if(p.t===2)pktData++;else if(p.t===1)pktCtrl++;
      const e=document.createElement('div');e.style.color=cls;e.style.marginBottom='4px';
      e.textContent=p.info+' '+p.src+' -> '+p.dst+' CH'+p.ch+' '+p.rssi+'dBm';
      log.appendChild(e);
    });
    set('pktTotal',d.total);set('pktMgmt',pktMgmt);set('pktData',pktData);set('pktCtrl',pktCtrl);
  });
}

// KISMET
let kisOn=false,kisPoll=null;
function togKismet(){
  kisOn=!kisOn;fetch('/kismet?active='+kisOn).then(()=>{
    $('kisBtn').textContent=kisOn?'STOP KISMET':'START KISMET';
    $('kisBtn').className=kisOn?'btn red':'btn green';
    set('kisSt',kisOn?'MAPPING...':'STOPPED');
    if(kisOn)kisPoll=setInterval(fetchKismet,2000);else clearInterval(kisPoll);
  });
}
function clearKismet(){fetch('/kismet/clear');$('kApT').innerHTML='<tr><td colspan="4" style="text-align:center;color:#8b949e">Cleared</td></tr>';$('kProbeT').innerHTML='<tr><td colspan="2" style="text-align:center;color:#8b949e">Cleared</td></tr>';}
function fetchKismet(){
  fetch('/kismet/data').then(r=>r.json()).then(d=>{
    const tb=$('kApT');
    tb.innerHTML=d.aps.length?d.aps.map(a=>'<tr><td>'+a.b+'</td><td>'+(a.s||'hidden')+'</td><td>'+a.c+'</td><td>'+a.r+'</td></tr>').join(''):'<tr><td colspan="4" style="text-align:center;color:#8b949e">No APs yet</td></tr>';
    const pt=$('kProbeT');
    pt.innerHTML=d.probes.length?d.probes.map(p=>'<tr><td>'+p.m+'</td><td>'+p.s+'</td></tr>').join(''):'<tr><td colspan="2" style="text-align:center;color:#8b949e">No probes yet</td></tr>';
  });
}

// PMKID
let pmkOn=false,pmkPoll=null;
function togPMKID(){
  pmkOn=!pmkOn;fetch('/pmkid?active='+pmkOn).then(()=>{
    $('pmkBtn').textContent=pmkOn?'STOP CAPTURE':'START CAPTURE';
    $('pmkBtn').className=pmkOn?'btn red':'btn green';
    set('pmkSt',pmkOn?'LISTENING...':'STOPPED');
    if(pmkOn)pmkPoll=setInterval(fetchPMKID,3000);else clearInterval(pmkPoll);
  });
}
function fetchPMKID(){
  fetch('/pmkid/data').then(r=>r.json()).then(d=>{
    const tb=$('pmkT');
    tb.innerHTML=d.entries.length?d.entries.map(e=>'<tr><td>'+e.b+'</td><td>'+e.c+'</td><td style="font-size:.7rem;color:#3fb950">'+e.p+'</td></tr>').join(''):'<tr><td colspan="3" style="text-align:center;color:#8b949e">No PMKID captured yet</td></tr>';
  });
}

// RECON
function doRecon(){
  set('rSt','SCANNING...');fetch('/recon').then(r=>r.json()).then(d=>{
    set('rSt',d.clients.length+' CLIENT(S)');const tb=$('rT');
    tb.innerHTML=d.clients.length?d.clients.map(c=>'<tr><td>'+c.vendor+'</td><td>'+c.ip+'</td><td>'+c.mac+'</td><td>'+(c.ports.length?c.ports.map(p=>p.s).join(','):'none')+'</td></tr>').join(''):'<tr><td colspan="4" style="text-align:center;color:#8b949e">No clients</td></tr>';
  });
}

// SYSTEM
function setCPU(){fetch('/system/cpu?freq='+$('cpuF').value);}
function doSleep(){fetch('/system/sleep?sec='+($('slpS').value||30));}
function doReboot(){fetch('/system/reboot');}

// CHAT
let ws=null,myN='';
function initWS(){
  ws=new WebSocket('ws://'+location.hostname+':81');
  ws.onopen=()=>{set('onl','1 ONLINE');addSys('Connected');};
  ws.onclose=()=>{set('onl','0 ONLINE');ws=null;setTimeout(initWS,3000);};
  ws.onmessage=e=>{try{const d=JSON.parse(e.data);if(d.t==='chat')apMsg(d.n,d.m);else if(d.t==='sys')addSys(d.msg);}catch(e){}};
}
function sChat(){
  const n=$('nIn').value.trim()||'ANON',t=$('mIn').value.trim();myN=n;
  if(!t||!ws||ws.readyState!==1)return;ws.send(JSON.stringify({t:'chat',n,m:t}));$('mIn').value='';
}
function apMsg(nm,tx){
  const b=$('cMsgs');const d=document.createElement('div');d.style.cssText='margin-bottom:8px'+(nm===myN?';text-align:right':'');
  const meta=document.createElement('div');meta.style.cssText='font-size:.7rem;color:#8b949e;margin-bottom:2px';meta.textContent=nm;
  const bub=document.createElement('div');bub.style.cssText='display:inline-block;padding:6px 10px;background:'+(nm===myN?'#1a3b29':'#1f2937')+';border:1px solid #30363d;border-radius:6px';
  bub.textContent=tx;d.appendChild(meta);d.appendChild(bub);b.appendChild(d);b.scrollTop=b.scrollHeight;
}
function addSys(t){const b=$('cMsgs');const d=document.createElement('div');d.style.cssText='text-align:center;font-size:.7rem;color:#8b949e;margin:6px 0';d.textContent='-- '+t+' --';b.appendChild(d);b.scrollTop=b.scrollHeight;}

// DATA PANEL
function fetchApiData(ep){
  fetch(ep).then(r=>r.json()).then(d=>{
    $('jsonViewer').textContent=JSON.stringify(d,null,2);
  }).catch(e=>$('jsonViewer').textContent='Error: '+e);
}
</script>
</body>
</html>
)=====";

// ══════════════════════════════════════════════════════════════════════════════
//  HTTP ROUTE HANDLERS
// ══════════════════════════════════════════════════════════════════════════════
void handleRoot() { http.send_P(200, "text/html", HTML); }
void handleStatus() {
  String j = "{\"uptime\":" + String(millis()) + ",\"heap\":" + String(ESP.getFreeHeap()) + ",\"temp\":" + String(temperatureRead(), 1) + ",\"cpu\":" + String(getCpuFrequencyMhz()) + ",\"clients\":" + String(WiFi.softAPgetStationNum()) + ",\"deauth\":" + String(deauthCnt) + ",\"beaconCnt\":" + String(beaconCnt) + ",\"snifferOn\":" + jb(snifferActive) + ",\"kismetOn\":" + jb(kismetMode) + ",\"pmkidOn\":" + jb(pmkidMode) + ",\"deauthOn\":" + jb(deauthMode) + ",\"inputs\":[" + jb(digitalRead(7)) + "," + jb(digitalRead(8)) + "],\"touch\":[" + String(touchVal[0]) + "," + String(touchVal[1]) + "]";
  if (WiFi.status() == WL_CONNECTED) j += ",\"sta\":\"connected\",\"staSSID\":\"" + esc(WiFi.SSID()) + "\",\"staIp\":\"" + WiFi.localIP().toString() + "\",\"staRSSI\":" + String(WiFi.RSSI());
  else j += ",\"sta\":\"" + staConnStatus + "\"";
  j += "}";
  http.send(200, "application/json", j);
}
void handleGPIOPin() {
  if (!http.hasArg("pin") || !http.hasArg("state")) { http.send(400, "application/json", "{\"e\":\"missing\"}"); return; }
  int pin = http.arg("pin").toInt(), state = http.arg("state").toInt(), idx = pinIndex(pin);
  if (idx < 0) { http.send(404, "application/json", "{\"e\":\"invalid pin\"}"); return; }
  if ((pin==GPIO_OUT_1||pin==GPIO_OUT_2||pin==GPIO_OUT_3) && pwmMode[(pin==GPIO_OUT_1)?0:(pin==GPIO_OUT_2)?1:2]) { http.send(409, "application/json", "{\"e\":\"pwm active\"}"); return; }
  pinMode(pin, OUTPUT); gpioStates[idx] = (state == 1); digitalWrite(pin, state ? HIGH : LOW);
  http.send(200, "application/json", "{\"pin\":" + String(pin) + ",\"state\":" + jb(gpioStates[idx]) + "}");
}
void handlePWMSet() { int ch = http.arg("ch").toInt(), duty = constrain(http.arg("duty").toInt(), 0, 255); if(ch>=0&&ch<=2){pwmDuty[ch]=duty; if(pwmMode[ch]){int g[3]={4,5,6}; ledcWrite(g[ch], duty);}} http.send(200, "application/json", "{\"ok\":true}"); }
void handlePWMMode() { int ch = http.arg("ch").toInt(); if(ch>=0&&ch<=2){pwmMode[ch]=!pwmMode[ch]; int g[3]={4,5,6}; if(pwmMode[ch]){ledcAttach(g[ch],5000,8); ledcWrite(g[ch],pwmDuty[ch]);} else {ledcDetach(g[ch]); pinMode(g[ch],OUTPUT); digitalWrite(g[ch],LOW);}} http.send(200, "application/json", "{\"pwm\":" + jb(pwmMode[ch]) + "}"); }
void handleWifiScan() { WiFi.scanNetworks(true); http.send(200, "application/json", "{\"status\":\"scanning\"}"); }
void handleWifiResults() {
  int n = WiFi.scanComplete();
  if (n == WIFI_SCAN_RUNNING) { http.send(200, "application/json", "{\"status\":\"scanning\"}"); return; }
  String j = "{\"status\":\"done\",\"networks\":[";
  for (int i = 0; i < n; i++) { if(i>0)j+=","; j += "{\"ssid\":\"" + esc(WiFi.SSID(i)) + "\",\"rssi\":" + String(WiFi.RSSI(i)) + ",\"channel\":" + String(WiFi.channel(i)) + ",\"enc\":" + jb(WiFi.encryptionType(i) != WIFI_AUTH_OPEN) + "}"; }
  j += "]}"; WiFi.scanDelete(); http.send(200, "application/json", j);
}
void handleWifiConnect() {
  if (!http.hasArg("ssid")) { http.send(400, "application/json", "{\"status\":\"error\"}"); return; }
  String ss = http.arg("ssid"), pw = http.hasArg("pass") ? http.arg("pass") : "";
  http.send(200, "application/json", "{\"status\":\"connecting\"}");
  WiFi.mode(WIFI_AP_STA); WiFi.softAPConfig(AP_IP, AP_GW, AP_SN); WiFi.softAP(apSSID.c_str(), apPass.c_str()); WiFi.disconnect(false);
  if (pw.length() > 0) WiFi.begin(ss.c_str(), pw.c_str()); else WiFi.begin(ss.c_str());
  staConnStatus = "connecting"; staSSID = ss; staTimeout = millis() + 18000;
}
void handleWifiDisconnect() { http.send(200, "application/json", "{\"status\":\"disconnected\"}"); WiFi.disconnect(false); staConnStatus = "disconnected"; WiFi.mode(WIFI_AP); WiFi.softAPConfig(AP_IP, AP_GW, AP_SN); WiFi.softAP(apSSID.c_str(), apPass.c_str()); }
void handleBleScan() {
  if (bleScanning || (chanHopping && (snifferActive || kismetMode || deauthMode || pmkidMode))) { http.send(409, "application/json", "{\"status\":\"busy\"}"); return; }
  bleScanning = true; if (bleCb) delete bleCb; bleCb = new AxiomBLECb();
  pBLEScan->setAdvertisedDeviceCallbacks(bleCb); pBLEScan->setActiveScan(true); pBLEScan->start(6, [](BLEScanResults r){ bleCb->json += "]"; bleResults = bleCb->json; bleScanning = false; }, false);
  http.send(200, "application/json", "{\"status\":\"scanning\"}");
}
void handleBleResults() { http.send(200, "application/json", bleScanning ? "{\"status\":\"scanning\"}" : "{\"status\":\"done\",\"devices\":" + bleResults + "}"); }
void handleSniffer() {
  bool active = http.hasArg("active") && http.arg("active") == "true"; int ch = http.hasArg("ch") ? http.arg("ch").toInt() : 0;
  snifferActive = active;
  if (active) { if (ch > 0 && ch <= 13) { esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE); chanHopping = false; } else chanHopping = true; startPromiscuous(); } else stopPromiscuous();
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
    j += "{\"src\":\"" + String(pktLog[idx].srcMAC) + "\",\"dst\":\"" + String(pktLog[idx].dstMAC) + "\",\"t\":" + String(pktLog[idx].type) + ",\"info\":\"" + String(pktLog[idx].info) + "\",\"rssi\":" + String(pktLog[idx].rssi) + ",\"ch\":" + String(pktLog[idx].channel) + "}";
  }
  j += "],\"total\":" + String(pktTotal) + "}"; http.send(200, "application/json", j);
}
void handleSnifferClear() { pktHead = 0; pktTotal = 0; http.send(200, "application/json", "{\"ok\":true}"); }
void handleKismet() { kismetMode = http.hasArg("active") && http.arg("active") == "true"; probeCount = 0; if (kismetMode) { chanHopping = true; startPromiscuous(); } else stopPromiscuous(); http.send(200, "application/json", "{\"active\":" + jb(kismetMode) + "}"); }
void handleKismetData() {
  String j = "{\"aps\":[";
  bool first = true;
  for (int i = 0; i < MAX_AP; i++) {
    if (kisAPs[i].valid) {
      if (!first) j += ",";
      first = false;
      j += "{\"b\":\"" + String(kisAPs[i].bssid) + "\",\"s\":\"" + esc(String(kisAPs[i].ssid)) + "\",\"c\":" + String(kisAPs[i].ch) + ",\"r\":" + String(kisAPs[i].rssi) + "}";
    }
  }
  j += "],\"probes\":[";
  first = true;
  for (int i = 0; i < probeCount; i++) {
    if (!first) j += ",";
    first = false;
    j += "{\"m\":\"" + String(probeLog[i].mac) + "\",\"s\":\"" + esc(String(probeLog[i].ssid)) + "\"}";
  }
  j += "]}"; http.send(200, "application/json", j);
}
void handleKismetClear() { for (int i = 0; i < MAX_AP; i++) kisAPs[i].valid = false; probeCount = 0; http.send(200, "application/json", "{\"ok\":true}"); }
void handlePMKID() { pmkidMode = http.hasArg("active") && http.arg("active") == "true"; if (pmkidMode) startPromiscuous(); else stopPromiscuous(); http.send(200, "application/json", "{\"active\":" + jb(pmkidMode) + "}"); }
void handlePMKIDData() {
  String j = "{\"entries\":[";
  bool first = true;
  for (int i = 0; i < pmkidCount; i++) {
    if (!first) j += ",";
    first = false;
    j += "{\"b\":\"" + String(pmkidLog[i].bssid) + "\",\"c\":\"" + String(pmkidLog[i].client) + "\",\"p\":\"" + String(pmkidLog[i].pmkid) + "\"}";
  }
  j += "]}"; http.send(200, "application/json", j);
}
void handleDeauth() { deauthMode = http.hasArg("active") && http.arg("active") == "true"; if (deauthMode) { chanHopping = true; startPromiscuous(); } else stopPromiscuous(); http.send(200, "application/json", "{\"active\":" + jb(deauthMode) + "}"); }
void handleRecon() {
  wifi_sta_list_t sl; esp_wifi_ap_get_sta_list(&sl);
  esp_netif_t *apif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
  String j = "{\"clients\":[";
  for (int i = 0; i < sl.num; i++) {
    if (i > 0) j += ","; const uint8_t *m = sl.sta[i].mac; char mac[18]; snprintf(mac, 18, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]); logClient(m);
    char ip[16] = "N/A"; if (apif) { esp_netif_pair_mac_ip_t ci; memcpy(ci.mac, m, 6); if (esp_netif_dhcps_get_clients_by_mac(apif, 1, &ci) == ESP_OK) snprintf(ip, 16, IPSTR, IP2STR(&ci.ip)); }
    j += "{\"ip\":\"" + String(ip) + "\",\"mac\":\"" + String(mac) + "\",\"vendor\":\"" + String(lookupOUI(m)) + "\",\"ports\":" + ((String(ip)!="N/A")?scanPorts(String(ip)):"[]") + "}";
  }
  j += "]}"; http.send(200, "application/json", j);
}
void handleTouchActions() { if (http.hasArg("t1")) touchAction[0] = http.arg("t1"); if (http.hasArg("t2")) touchAction[1] = http.arg("t2"); http.send(200, "application/json", "{\"ok\":true}"); }
void fireTouchAction(int idx) {
  String &a = touchAction[idx]; int i;
  if (a == "gpio0") { i = pinIndex(GPIO_OUT_1); gpioStates[i] = !gpioStates[i]; digitalWrite(GPIO_OUT_1, gpioStates[i] ? HIGH : LOW); }
  else if (a == "gpio1") { i = pinIndex(GPIO_OUT_2); gpioStates[i] = !gpioStates[i]; digitalWrite(GPIO_OUT_2, gpioStates[i] ? HIGH : LOW); }
  else if (a == "gpio2") { i = pinIndex(GPIO_OUT_3); gpioStates[i] = !gpioStates[i]; digitalWrite(GPIO_OUT_3, gpioStates[i] ? HIGH : LOW); }
  else if (a == "sleep") { esp_sleep_enable_timer_wakeup(30ULL * 1000000ULL); esp_sleep_enable_touchpad_wakeup(); esp_deep_sleep_start(); }
}
void handleAPConfig() {
  if (!http.hasArg("ssid") || !http.hasArg("pass")) { http.send(400, "application/json", "{\"status\":\"error\"}"); return; }
  String ns = http.arg("ssid"), np = http.arg("pass");
  if (ns.length() == 0 || np.length() < 8) { http.send(400, "application/json", "{\"status\":\"error\"}"); return; }
  prefs.begin("axiom", false); prefs.putString("apSSID", ns); prefs.putString("apPass", np); prefs.end();
  http.send(200, "application/json", "{\"status\":\"saved\"}"); delay(3000); ESP.restart();
}
void handleCPU() { int f = http.arg("freq").toInt(); if (f == 240 || f == 160 || f == 80) setCpuFrequencyMhz(f); http.send(200, "application/json", "{\"freq\":" + String(getCpuFrequencyMhz()) + "}"); }
void handleSleep() { int s = constrain(http.arg("sec").toInt(), 5, 3600); http.send(200, "application/json", "{\"ok\":true}"); delay(200); esp_sleep_enable_timer_wakeup((uint64_t)s * 1000000ULL); esp_sleep_enable_touchpad_wakeup(); esp_deep_sleep_start(); }
void handleReboot() { http.send(200, "application/json", "{\"ok\":true}"); delay(500); ESP.restart(); }

void handleDataEndpoint() {
  String j = "{\"system\":{\"uptime\":" + String(millis()) + ",\"heapFree\":" + String(ESP.getFreeHeap()) + ",\"cpuFreqMHz\":" + String(getCpuFrequencyMhz()) + ",\"tempC\":" + String(temperatureRead(), 1) + "},\"wifi\":{\"apSSID\":\"" + esc(apSSID) + "\",\"apClients\":" + String(WiFi.softAPgetStationNum()) + ",\"staStatus\":\"" + staConnStatus + "\"},\"gpio\":{\"outputs\":[";
  bool first = true;
  for (int i = 0; i < OUT_COUNT; i++) {
    if (!first) j += ",";
    first = false;
    j += "{\"pin\":" + String(OUT_PINS[i]) + ",\"state\":" + jb(gpioStates[i]) + "}";
  }
  j += "],\"inputs\":[";
  first = true;
  for (int i = 0; i < IN_COUNT; i++) {
    if (!first) j += ",";
    first = false;
    j += "{\"pin\":" + String(IN_PINS[i]) + ",\"val\":" + String(digitalRead(IN_PINS[i])) + "}";
  }
  j += "]}}"; http.send(200, "application/json", j);
}
void handleGPIOEndpoint() {
  String j = "{\"outputs\":[";
  bool first = true;
  for (int i = 0; i < OUT_COUNT; i++) {
    if (!first) j += ",";
    first = false;
    j += "{\"pin\":" + String(OUT_PINS[i]) + ",\"state\":" + jb(gpioStates[i]) + "}";
  }
  j += "],\"inputs\":[";
  first = true;
  for (int i = 0; i < IN_COUNT; i++) {
    if (!first) j += ",";
    first = false;
    j += "{\"pin\":" + String(IN_PINS[i]) + ",\"val\":" + String(digitalRead(IN_PINS[i])) + "}";
  }
  j += "]}"; http.send(200, "application/json", j);
}
void handleWifiEndpoint() {
  String j = "{\"ap\":{\"ssid\":\"" + esc(apSSID) + "\",\"ip\":\"" + WiFi.softAPIP().toString() + "\",\"clients\":" + String(WiFi.softAPgetStationNum()) + "},\"sta\":{\"status\":\"" + staConnStatus + "\"}}";
  http.send(200, "application/json", j);
}
void handleBluetoothEndpoint() { http.send(200, "application/json", "{\"status\":\"" + String(bleScanning ? "scanning" : "ready") + "\",\"devices\":" + (bleResults.length() > 0 ? bleResults : "[]") + "}"); }
void handleNotFound() { http.send(404, "text/plain", "AXIOM 404"); }

void sendOledPageJSON() { http.send(200, "application/json", "{\"page\":" + String(oledPage) + ",\"name\":\"" + String(oledPageNames[oledPage]) + "\"}"); }
void handleDisplayNext() { oledPage = (oledPage + 1) % PG_COUNT; oledDirty = true; drawOled(); sendOledPageJSON(); }
void handleDisplayPrev() { oledPage = (oledPage - 1 + PG_COUNT) % PG_COUNT; oledDirty = true; drawOled(); sendOledPageJSON(); }
void handleDisplayPage() { if (http.hasArg("id")) { int id = http.arg("id").toInt(); if (id >= 0 && id < PG_COUNT) oledPage = id; } oledDirty = true; drawOled(); sendOledPageJSON(); }
void handleDisplayStatus() { sendOledPageJSON(); }

// ══════════════════════════════════════════════════════════════════════════════
//  SETUP
// ══════════════════════════════════════════════════════════════════════════════
void setup() {
  Serial.begin(115200); delay(400);
  Serial.println("\n+-------------------------------+");
  Serial.println("| AXIOM v11.2 CYBERTECH EDITION |");
  Serial.println("+-------------------------------+");

  neo.begin(); neo.setBrightness(60); setNeo(131, 111, 255);

  // OLED init with safe SPI speed to prevent WiFi DMA contention
  oled.setBusClock(8000000); 
  oledReady = oled.begin();
  if (oledReady) drawOled();

  for (int p : {GPIO_OUT_1, GPIO_OUT_2, GPIO_OUT_3}) { pinMode(p, OUTPUT); digitalWrite(p, LOW); }
  pinMode(7, INPUT_PULLDOWN); pinMode(8, INPUT_PULLDOWN);

  touch_pad_init();
  touch_pad_set_voltage(TOUCH_HVOLT_2V7, TOUCH_LVOLT_0V5, TOUCH_HVOLT_ATTEN_1V);
  touch_pad_config(TOUCH_PAD_NUM1); touch_pad_config(TOUCH_PAD_NUM2);
  touch_pad_fsm_start();

  prefs.begin("axiom", true);
  apSSID = prefs.getString("apSSID", DEFAULT_AP_SSID);
  apPass = prefs.getString("apPass", DEFAULT_AP_PASS);
  prefs.end();

  WiFi.mode(WIFI_AP); WiFi.softAPConfig(AP_IP, AP_GW, AP_SN); WiFi.softAP(apSSID.c_str(), apPass.c_str());
  if (MDNS.begin(MDNS_HOST)) { MDNS.addService("http", "tcp", 80); MDNS.addService("ws", "tcp", 81); }

  BLEDevice::init("AXIOM"); pBLEScan = BLEDevice::getScan(); pBLEScan->setInterval(100); pBLEScan->setWindow(99);

  http.on("/", HTTP_GET, handleRoot);
  http.on("/status", HTTP_GET, handleStatus);
  http.on("/gpio/pin", HTTP_GET, handleGPIOPin);
  http.on("/gpio/pwm", HTTP_GET, handlePWMSet);
  http.on("/gpio/pwmmode", HTTP_GET, handlePWMMode);
  http.on("/wifi/scan", HTTP_GET, handleWifiScan);
  http.on("/wifi/results", HTTP_GET, handleWifiResults);
  http.on("/wifi/connect", HTTP_POST, handleWifiConnect);
  http.on("/wifi/disconnect", HTTP_GET, handleWifiDisconnect);
  http.on("/ble/scan", HTTP_GET, handleBleScan);
  http.on("/ble/results", HTTP_GET, handleBleResults);
  http.on("/sniffer", HTTP_GET, handleSniffer);
  http.on("/sniffer/log", HTTP_GET, handleSnifferLog);
  http.on("/sniffer/clear", HTTP_GET, handleSnifferClear);
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
  http.on("/data", HTTP_GET, handleDataEndpoint);
  http.on("/gpio", HTTP_GET, handleGPIOEndpoint);
  http.on("/wifi", HTTP_GET, handleWifiEndpoint);
  http.on("/bluetooth", HTTP_GET, handleBluetoothEndpoint);
  http.on("/bt", HTTP_GET, handleBluetoothEndpoint);
  http.onNotFound(handleNotFound);

  http.begin(); wsChat.begin(); wsChat.onEvent(wsEvent);
  setNeo(21, 245, 186); delay(200); setNeo(131, 111, 255); delay(200); setNeo(21, 245, 186);
}

// ══════════════════════════════════════════════════════════════════════════════
//  LOOP
// ══════════════════════════════════════════════════════════════════════════════
void loop() {
  http.handleClient();
  wsChat.loop();

  // STA watchdog
  if (staConnStatus == "connecting") {
    if (WiFi.status() == WL_CONNECTED) {
      staConnStatus = "connected"; setNeo(21, 245, 186);
    } else if (millis() > staTimeout) {
      staConnStatus = "failed"; setNeo(255, 30, 0);
      static unsigned long failLEDTime = 0;
      if (failLEDTime == 0) failLEDTime = millis() + 2000;
      if (millis() > failLEDTime) { setNeo(131, 111, 255); failLEDTime = 0; }
    }
  }

  // Channel hopping
  if (chanHopping && !bleScanning && (snifferActive || kismetMode || deauthMode || pmkidMode) && millis() - lastChanHop > 350) {
    deauthChan = (deauthChan % 13) + 1; esp_wifi_set_channel(deauthChan, WIFI_SECOND_CHAN_NONE); lastChanHop = millis();
    deauthCnt = _deauthCnt; deauthLast = String((char *)_deauthMAC);
  }

  // Touch polling
  static unsigned long lastTouchPoll = 0;
  if (millis() - lastTouchPoll > 150) {
    lastTouchPoll = millis(); uint32_t v0 = 0, v1 = 0;
    touch_pad_read_raw_data(TOUCH_PAD_NUM1, &v0); touch_pad_read_raw_data(TOUCH_PAD_NUM2, &v1);
    touchVal[0] = v0; touchVal[1] = v1; touchActive[0] = (v0 < TOUCH_THRESHOLD); touchActive[1] = (v1 < TOUCH_THRESHOLD);
    for (int i = 0; i < 2; i++) { if (touchActive[i] && !prevTouch[i]) fireTouchAction(i); prevTouch[i] = touchActive[i]; }
  }

  // OLED refresh (1s) + Periodic contrast reset to prevent charge pump inversion
  static unsigned long lastOledRefresh = 0, lastContrastReset = 0;
  if (oledReady && (oledDirty || millis() - lastOledRefresh > 1000)) {
    lastOledRefresh = millis(); oledDirty = true; drawOled();
  }
  if (oledReady && millis() - lastContrastReset > 5000) {
    lastContrastReset = millis(); oled.setContrast(255); // Force display state hold
  }
}