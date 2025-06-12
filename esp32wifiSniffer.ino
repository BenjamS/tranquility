#include "types.h"
#include "parsers.h"

// Other includes and definitions
#include <WiFi.h>
#include <SPI.h>
#include <SD.h>
#include "nvs_flash.h"

// ---- USER CONFIG ----
const unsigned long SCAN_DURATION   = 30000;  // 30 seconds per scan
const unsigned long SLEEP_DURATION  = 60000;  // 60 seconds sleep
const int           MAX_DEVICES     = 100;    // Max devices tracked
const int           CHANNELS[]      = {1, 6, 11};
const int           CHANNEL_COUNT   = sizeof(CHANNELS) / sizeof(CHANNELS[0]);

// ---- SCAN STATE ----
bool          scanning        = true;
unsigned long scanStart       = 0;
unsigned long sleepStart      = 0;
unsigned long lastChannelSwitch = 0;
int           channelIndex    = 0;


//===========================================================
// Sniffer
//===========================================================
void sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (!scanning) return;
  const wifi_promiscuous_pkt_t* ppkt = (const wifi_promiscuous_pkt_t*)buf;
  //auto *ppkt = (wifi_promiscuous_pkt_t *)buf;
  //const uint8_t* frame = ppkt->payload;
  //uint16_t len = ppkt->rx_ctrl.sig_len;
  //int8_t rssi = ppkt->rx_ctrl.rssi;
  //uint8_t channel = ppkt->rx_ctrl.channel;
  //auto *ppkt = (wifi_promiscuous_pkt_t *)buf;
  //const wifi_ieee80211_hdr* hdr = (const wifi_ieee80211_hdr*)ppkt->payload;
  //const uint8_t *payload = ppkt->payload;
  DeviceCapture cap;
  parseGlobalItems(ppkt, cap);
  //debugPrintGlobalInfo(cap); // [DEBUG] See if parseGlobalItems() successfully captured everything it's supposed to
  //Serial.printf("[DEBUG] type: %02X, subtype: %02X, dir: %d\n", fType, subtype, direction);
  updateMacStatsFromGlobalItems(cap);
  //----------------------------------------------------------------
  //Keeping track of all unique frame type/subtype/direction combos encountered during scan
  // Map direction string to numeric code
  uint8_t dirCode = (uint8_t)cap.directionCode;
  // STA↔STA and unknown remain 0
  FrameStatKey key = {
   .type = cap.frameType,
   .subtype = cap.subtype,
   .direction = dirCode
  };
  globalFrameStats[key]++;
  //----------------------------------------------------------------
  // Look only at frames of interest
  bool isMgmtFrame = (cap.frameType == 0x00 &&
    (cap.subtype == 0x00 ||  // Association Request
    cap.subtype == 0x02 ||  // Reassociation Request
    cap.subtype == 0x04 ||  // Probe Request
    cap.subtype == 0x0B ||  // Authentication
    cap.subtype == 0x08 ||  // Beacon
    (cap.subtype == 0x0C && cap.directionCode == DIR_CLIENT_TO_AP) ||  // Deauthentication
    (cap.subtype == 0x0A && cap.directionCode == DIR_CLIENT_TO_AP)));  // Disassociation
  bool isDataFrame = (cap.frameType == 0x02);
  if (!isMgmtFrame && !isDataFrame) return;
  //----------------------------------------------------------------
  // Type 2 frames (QoS and non-QoS data frames)
  if(isDataFrame){ 
    parseDataFrame(ppkt->payload, ppkt->rx_ctrl.sig_len, cap);
    //debugPrintMacStats(cap.srcMac);
  }
  //-------------------------------------------------------------
  //Type 0 frames (management frames)
  if(isMgmtFrame){
     // [DEBUG]--------------
    if(cap.subtype == 0x04){
    Serial.println("\n=== Data Frame Raw Frame Hex Dump ===");
    Serial.printf("[FRAME] type: %02X, subtype: %02X, dir: %s\n", cap.frameType, cap.subtype, cap.directionText);
    Serial.println("Sender MAC: " + cap.senderMac);
    //int offset = (cap.subtype == 0x04) ? 24 : 36; //Mngmnt frame probe request (0x04->24) or association request (0x00->36)
    int offset;
switch (cap.subtype) {
  case 0x04: offset = 28; break; // Probe Request
  case 0x00: // Assoc Req
  case 0x01: // Assoc Resp
  case 0x05: // Probe Resp
  case 0x08: // Beacon
    offset = 36; break;
  default:
    Serial.printf("[WARN] Unhandled management subtype: 0x%02X\n", cap.subtype);
    return;
}
    int ieLen = ppkt->rx_ctrl.sig_len - offset;
    const uint8_t* ieData = ppkt->payload + offset;
    printIEsDebug(ieData, ieLen);
    hexDump(ppkt->payload, ppkt->rx_ctrl.sig_len);
      //Serial.printf("[DEBUG] Frame Ctrl: 0x%04X | Type: %u | Subtype: 0x%02X\n", fctl, type, subtype);
      //parseDataFrame(frame, ppkt->rx_ctrl.sig_len);
    }
    //----------------------
    // Parse Information Elements
    parseMgmtFrame(ppkt->payload, ppkt->rx_ctrl.sig_len, cap);
    // Merge extracted mgmtInfo into per-MAC stats
    MacStats& stats = macStatsMap[cap.senderMac];

    if (cap.mgmtInfo.ssid.length()) {
      stats.mgmt.ssid = cap.mgmtInfo.ssid;
    }

    if (cap.mgmtInfo.wps.wpsSumFxd.length()) {
     stats.mgmt.wps = cap.mgmtInfo.wps;
    }

    if (cap.mgmtInfo.asciiHints.length()) {
      stats.mgmt.asciiHints = cap.mgmtInfo.asciiHints;
    } 
  }

}

//============================================================
// Setup
//============================================================
void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n[INFO] Starting sniffer...");
  initSD();

  nvs_flash_init();
  esp_netif_init();
  //tcpip_adapter_init();
  esp_event_loop_create_default();

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);

  // allow all 1–13
  wifi_country_t country = {.cc="CN",.schan=1,.nchan=13};
  esp_wifi_set_country(&country);

  wifi_promiscuous_filter_t filt;
  //filt.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA;
  filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
  //filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MISC; //Doesn't seem to capture anything
  //filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT; //Best for accurate (not garbled) unique device fingerprinting
  //filt.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL; //Captures everything but noisy, garbled
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();
  esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
  esp_wifi_set_promiscuous(true);

  // init timing
  scanStart = millis();
  lastChannelSwitch = millis();
  esp_wifi_set_channel(CHANNELS[0], WIFI_SECOND_CHAN_NONE);
}

//============================================================
// Main loop
//============================================================
void loop() {
  unsigned long now = millis();
  // rotate channels during scan
  if (scanning && now - lastChannelSwitch >= SCAN_DURATION/CHANNEL_COUNT) {
    channelIndex = (channelIndex+1)%CHANNEL_COUNT;
    esp_wifi_set_channel(CHANNELS[channelIndex], WIFI_SECOND_CHAN_NONE);
    lastChannelSwitch = now;
    Serial.printf("[DEBUG] Switching to channel %d\n", CHANNELS[channelIndex]);
  }

  // end-of-scan: print & sleep
  if (scanning && now - scanStart >= SCAN_DURATION) {
    scanning = false;
    sleepStart = now;
    esp_wifi_set_promiscuous(false);
    String timestamp = getScanTimestamp();
    //logToCSV(timestamp); // Save to SD
    esp_wifi_stop();
//    bool printed[MAX_DEVICES] = {false};
    //---print table here
    //printScanSummaryTable();
    printGlobalFrameStats();
    printGlobalMacStats();
    Serial.println("\n[INFO] Scan done, sleeping...\n");
  // sleep between scans
  }
  else if (!scanning && now - sleepStart >= SLEEP_DURATION) {
    Serial.println("[INFO] Waking up, new scan starts...\n");
    // reset for next cycle
    //nextUdfId = 1;
    Serial.printf("[DEBUG] Free heap before clearing captures: %lu\n", ESP.getFreeHeap());
    //captures.clear();
    globalFrameStats.clear();
    Serial.printf("[DEBUG] Free heap after clearing captures: %lu\n", ESP.getFreeHeap());
    scanning = true;
    scanStart = now;
    channelIndex = 0;
    lastChannelSwitch = now;
    esp_wifi_start();
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(CHANNELS[0], WIFI_SECOND_CHAN_NONE);
  }

  delay(50);
}
