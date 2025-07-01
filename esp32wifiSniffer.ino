#include "types.h"
#include "parsers.h"

// Other includes and definitions
#include <WiFi.h>
#include <SPI.h>
#include <SD.h>
#include "nvs_flash.h"

// ---- USER CONFIG ----
const unsigned long SCAN_DURATION   = 10000;  // 1000 = 1 sec
const unsigned long SLEEP_DURATION  = 40000;  // 1000 = 1 sec
const int           MAX_DEVICES     = 100;    // Max devices tracked
const int           CHANNELS[]      = {1, 6, 11};
const int           CHANNEL_COUNT   = sizeof(CHANNELS) / sizeof(CHANNELS[0]);
const uint32_t CHANNEL_SWITCH_INTERVAL = 5000;  // 1000 = 1 second

// ---- SCAN STATE ----
bool          scanning        = true;
unsigned long scanStart       = 0;
unsigned long sleepStart      = 0;
unsigned long lastChannelSwitch = 0;
int           channelIndex    = 0;

// ---- Heap memory monitoring ----
static unsigned long lastHeapLogTime = 0;
const uint32_t HEAP_LOG_INTERVAL = 2000;  // 1000 = 1 second

// ---- Ephemeral probe request counter ----
unsigned int ephemeralProbeCount = 0;

//===========================================================
// Sniffer
//===========================================================
void sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (!scanning) return;
  const wifi_promiscuous_pkt_t* ppkt = (const wifi_promiscuous_pkt_t*)buf;
  uint16_t len = ppkt->rx_ctrl.sig_len;
  if (len < 24) return;
  const uint8_t* frame = ppkt->payload;
  uint16_t fctl = *(const uint16_t*)frame;
  uint8_t frameType = (fctl >> 2) & 0x03;
  uint8_t subtype = (fctl >> 4) & 0x0F;
  bool toDS = fctl & (1 << 8);
  bool fromDS = fctl & (1 << 9);
    // Set enum and string version of direction
  uint8_t dirCode = (uint8_t)DIR_UNKNOWN;
  if (toDS && !fromDS) {
    dirCode = DIR_CLIENT_TO_AP;
  } else if (!toDS && fromDS) {
    dirCode = DIR_AP_TO_CLIENT;
  } else if (!toDS && !fromDS) {
    dirCode = DIR_STA_STA;
  } else if (toDS && fromDS) {
    dirCode = DIR_WDS;
  }
  //int8_t rssi = ppkt->rx_ctrl.rssi;
  //uint8_t ch = ppkt->rx_ctrl.channel;
  //----------------------------------------------------------------
  //Keeping track of all unique frame type/subtype/direction combos encountered during scan
  // Map direction string to numeric code
  // STA↔STA and unknown remain 0
  FrameStatKey key = {
   .type = frameType,
   .subtype = subtype,
   .direction = dirCode
  };
  globalFrameStats[key]++;
  //----------------------------------------------------------------
  // Look only at frames of interest
  bool isMgmtFrame = (frameType == 0x00 &&
    (subtype == 0x00 ||  // Association Request
    subtype == 0x02 ||  // Reassociation Request
    subtype == 0x04 ||  // Probe Request
    subtype == 0x0B ||  // Authentication
    //subtype == 0x08 ||  // Beacon
    (subtype == 0x0C && dirCode == DIR_CLIENT_TO_AP) ||  // Deauthentication
    (subtype == 0x0A && dirCode == DIR_CLIENT_TO_AP)));  // Disassociation
  bool isDataFrame = (frameType == 0x02);
  if (!isMgmtFrame && !isDataFrame) return;
  //----------------------------------------------------------------
  DeviceCapture cap; //Initialize capture
  //----------------------------------------------------------------
  // Parse global items
  parseGlobalItems(ppkt, cap);
  //debugPrintGlobalInfo(cap); // [DEBUG] See if parseGlobalItems() successfully captured everything it's supposed to
  //Serial.printf("[DEBUG] type: %02X, subtype: %02X, dir: %d\n", fType, subtype, direction);
  //updateMacStatsFromGlobalItems(cap);
  //----------------------------------------------------------------
  // Type 2 frames (QoS and non-QoS data frames)
  if(isDataFrame){ 
    Serial.printf("[DATA FRAME] type: %02X, subtype: %02X, dir: %s\n", cap.frameType, cap.subtype, cap.directionText);
    Serial.println("Sender MAC: " + cap.senderMac);
    //hexDump(ppkt->payload, ppkt->rx_ctrl.sig_len);
    updateMacStatsFromGlobalItems(cap);
    parseDataFrame(ppkt->payload, ppkt->rx_ctrl.sig_len, cap);
  }
  //-------------------------------------------------------------
  //Type 0 frames (management frames)
  if(isMgmtFrame){
    // ---Handle deauth frames---
    if (frameType == 0 && subtype == 0x0C) {
      parseDeauthFrame(frame, len, millis());
    }
    // ------
    // Set parsing offset according to subtype
    uint16_t offset;
    switch (cap.subtype) {
    case 0x04: {  // Probe Request
      // Start from base MAC header (24 bytes)
      offset = 24;

      // Defensive check: make sure there’s room for at least one TLV
      if (offset + 2 > ppkt->rx_ctrl.sig_len) {
        ephemeralProbeCount++;
        return;
      }

      // Calculate remaining length for IEs
      int ieLen = ppkt->rx_ctrl.sig_len - offset;
      if (ieLen <= 0) {
        ephemeralProbeCount++;
        return;
      }
      break;
      //bool foundValidTag = false;
      // Scan forward for the first valid tag
      //while (offset + 2 < ppkt->rx_ctrl.sig_len) {
      //  uint8_t tag = ppkt->payload[offset];
      //  uint8_t len = ppkt->payload[offset + 1];
      //  if ((tag <= 0x7F || tag == 0xDD) && (offset + 2 + len <= ppkt->rx_ctrl.sig_len)) {
      //      foundValidTag = true;
      //      break;
      //  }
      //  offset++;
      //}
      //if (!foundValidTag) {
      //  ephemeralProbeCount++;
      //  return;
      //}
    }
    case 0x00:  // Association Request
    case 0x01:  // Association Response
    case 0x05:  // Probe Response
    case 0x08:  // Beacon
    offset = 36;  // MAC header (24) + fixed fields (12)
    break;
    default:
    Serial.printf("[WARN] Unhandled management subtype: 0x%02X\n", cap.subtype);
    return;
    }
    int ieLen = ppkt->rx_ctrl.sig_len - offset;
    if (ieLen <= 0) {
      if (frameType == 0 && subtype == 0x04) {
        ephemeralProbeCount++;
      }
      return;  // Always bail if IEs are invalid
    }
    const uint8_t* ieData = ppkt->payload + offset;
    // [DEBUG]--------------
    if(cap.subtype == 0x04){
    //Serial.println("\n=== Data Frame Raw Frame Hex Dump ===");
    //Serial.printf("[FRAME] type: %02X, subtype: %02X, dir: %s\n", cap.frameType, cap.subtype, cap.directionText);
    //Serial.println("Sender MAC: " + cap.senderMac);
    //Serial.printf("[DEBUG] sig_len=%d, offset=%d, ieLen=%d\n", ppkt->rx_ctrl.sig_len, offset, ieLen);
    //printIEsDebug(ieData, ieLen);
    //hexDump(ppkt->payload, ppkt->rx_ctrl.sig_len);
    //String ssid = extractSsid(ieData, ieLen);
    //if (ssid.length()) {
      //cap.mgmtInfo.ssid = ssid;
      //Serial.println("📶 [SSID] Extracted (extractSsid): \"" + ssid + "\"");
    //}
      //Serial.printf("[DEBUG] Frame Ctrl: 0x%04X | Type: %u | Subtype: 0x%02X\n", fctl, type, subtype);
      //parseDataFrame(frame, ppkt->rx_ctrl.sig_len);
    }
    //----------------------
    // Parse Information Elements
    //parseMgmtFrame(ieData, ieLen, cap);
    // Parse all IEs including WPS
    cap.mgmtInfo = MgmtInfo();  // clears ssid, wps, asciiHints, etc.
    parseMgmtIEs(ieData, ieLen, cap);
    static String ssid;
    ssid = "";  // clear it before reuse
    extractSsid(ieData, ieLen, ssid);
    if (ssid == "@ " || ssid == "@#") {
        Serial.println("[DEBUG] Suspicious SSID '@ ' detected from MAC: " + cap.senderMac);
        hexDump(ppkt->payload, ppkt->rx_ctrl.sig_len);  // Print the whole raw frame
    }
    bool isProbeRequest = (frameType == 0 && subtype == 0x04);
    bool noSSID = ssid.length() == 0;
    bool noWPS = cap.mgmtInfo.wps.wpsSumFxd.length() == 0;
    //bool noVendor = (getVendorName(cap.senderMac).length() == 0);  // Or however you check vendor
    //bool shortDuration = cap.durationMs < 3;
    if (isProbeRequest && noSSID && noWPS) {
      ephemeralProbeCount++;  // ✅ Count but skip
     return;  // ❌ Don’t store in macStatsMap
    }
    Serial.printf("[MGMT FRAME] type: %02X, subtype: %02X, dir: %s\n", cap.frameType, cap.subtype, cap.directionText);
    Serial.println("Sender MAC: " + cap.senderMac);
    updateMacStatsFromGlobalItems(cap);
    if (ssid.length()) {
      cap.mgmtInfo.ssid = ssid;
      Serial.println("📶 [SSID] Extracted (extractSsid): \"" + ssid + "\"");
      addSsidToStats(macStatsMap[cap.senderMac], ssid);
      //Serial.println("[🧪DEBUG] SSIDs currently stored for " + cap.senderMac + ":");
      //for (const String& s : macStatsMap[cap.senderMac].mgmt.seenSsids) {
      //  Serial.println("  • " + s);
      //}

    }
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

    if (cap.mgmtInfo.countryCode.length()) {
      stats.mgmt.countryCode = cap.mgmtInfo.countryCode;
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
  if (scanning && now - lastChannelSwitch >= CHANNEL_SWITCH_INTERVAL) {
    channelIndex = (channelIndex + 1) % CHANNEL_COUNT;
    esp_wifi_set_channel(CHANNELS[channelIndex], WIFI_SECOND_CHAN_NONE);
    lastChannelSwitch = now;
    Serial.printf("[DEBUG] Switching to channel %d\n", CHANNELS[channelIndex]);
}

  //if (scanning && now - lastChannelSwitch >= SCAN_DURATION/CHANNEL_COUNT) {
  //  channelIndex = (channelIndex+1)%CHANNEL_COUNT;
  //  esp_wifi_set_channel(CHANNELS[channelIndex], WIFI_SECOND_CHAN_NONE);
  //  lastChannelSwitch = now;
  //  Serial.printf("[DEBUG] Switching to channel %d\n", CHANNELS[channelIndex]);
  //}

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
    Serial.printf("🧹 Ephemeral probes skipped: %u (%.1f%% of total MACs)\n",
      ephemeralProbeCount,
      100.0 * ephemeralProbeCount / (ephemeralProbeCount + macStatsMap.size()));
    ephemeralProbeCount = 0;  // reset for next scan
    printMacStats();
    Serial.println("\n[INFO] Scan done, sleeping...\n");
  // sleep between scans
  }
  else if (!scanning && now - sleepStart >= SLEEP_DURATION) {
    Serial.println("[INFO] Waking up, new scan starts...\n");
    // reset for next cycle
    //nextUdfId = 1;
    Serial.printf("[DEBUG] Free heap before clearing captures: %lu\n", ESP.getFreeHeap());
    macStatsMap.clear();
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

    // Log heap every few seconds during scan
if (scanning) {
  unsigned long now = millis();
  if (now - lastHeapLogTime >= HEAP_LOG_INTERVAL) {
    lastHeapLogTime = now;

    size_t freeHeap = ESP.getFreeHeap();
    size_t largest = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);

    Serial.printf("🧠 [HEAP MONITOR] Free: %6lu B | 📦 Largest Block: %6lu B\n",
                  freeHeap, largest);

    if (freeHeap < 60000 || largest < 20000) {
      Serial.println("🚨 [WARNING] Heap low — consider stopping scan or resetting!");
    }
  }
}


  delay(50);
}
