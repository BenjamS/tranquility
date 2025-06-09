#include "types.h"
#include "parsers.h"

// Other includes and definitions
#include <WiFi.h>
#include <SPI.h>
#include <SD.h>

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
  DeviceCapture cap;
  parseGlobalItems(ppkt, cap);
  debugPrintGlobalDebugInfo(cap); // [DEBUG] See if parseGlobalItems() successfully captured everything it's supposed to
  //Serial.printf("[DEBUG] type: %02X, subtype: %02X, dir: %d\n", fType, subtype, direction);
  updateMacStatsFromGlobalItems(cap, rssi, channel);
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
  bool isMgmtFrame = (cap.frameType == 0x00 && (cap.subtype == 0x00 || cap.subtype == 0x02 || cap.subtype == 0x04 ||
                         cap.subtype == 0x0B || 
                         (cap.subtype == 0x0C && dirCode == 0) || 
                         (cap.subtype == 0x0A && dirCode == 0)));
  bool isDataFrame = (cap.frameType == 0x02);
  if (!isMgmt && !isType02) return;
  //----------------------------------------------------------------
  // Type 2 frames (QoS and non-QoS data frames)
  if(isDataFrame){ 
    // [DEBUG]--------------
    //if(cap.subtype == 0x0c || cap.subtype == 0x0d || cap.subtype == 0x08 || cap.subtype == 0x09){
      //Serial.println("\n=== Data Frame Raw Frame Hex Dump ===");
      //hexDump(frame, ppkt->rx_ctrl.sig_len)
      //Serial.printf("[DEBUG] Frame Ctrl: 0x%04X | Type: %u | Subtype: 0x%02X\n", fctl, type, subtype);
      //parseDataFrame(frame, ppkt->rx_ctrl.sig_len);
    //}
    //----------------------
    parseDataFrame(ppkt->payload, ppkt->rx_ctrl.sig_len, cap);
    debugPrintMacStats(cap.srcMac);
  }
  //-------------------------------------------------------------
  //Type 0 frames (management frames)
  if(isMgmtFrame){

  //...
  }

}



  //-------------------------------------------------------------
  // Register new/update existing device entry
bool found = false;

for (DeviceCapture& existing : captures) {
  if (existing.primaryMac == cap.primaryMac) {
    // Update stats for existing MAC
    existing.packetCount++;
    existing.lastSeen = millis();

    if (rssi < existing.rssiMin) existing.rssiMin = rssi;
    if (rssi > existing.rssiMax) existing.rssiMax = rssi;

    existing.channelMask |= (1 << (ch - 1));

    if (existing.frameSubtypeStr.indexOf(combo) == -1) {
      if (existing.frameSubtypeStr.length() > 0) {
        existing.frameSubtypeStr += ",";
      }
      existing.frameSubtypeStr += combo;
    }

    found = true;
    break;  // Exit loop once found
  }
}

if (!found) {
  // First time seeing this MAC, initialize stats
  cap.packetCount = 1;
  cap.firstSeen = millis();
  cap.lastSeen = millis();
  cap.rssiMin = rssi;
  cap.rssiMax = rssi;
  cap.channelMask = (1 << (ch - 1));
  cap.frameSubtypeStr = combo;
  captures.push_back(cap);
}
  //-------------------------------------------------------------


  //const wifi_ieee80211_hdr* hdr = (const wifi_ieee80211_hdr*)ppkt->payload;
  //const uint8_t *payload = ppkt->payload;

  //const uint8_t* srcMac = hdr->addr2;
  //char macStr[18];
  //sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X",
  //      srcMac[0], srcMac[1], srcMac[2],
  //      srcMac[3], srcMac[4], srcMac[5]);

// hdr->frame_ctrl is already in host byte order — do NOT call ntohs()
//  uint16_t fctl = ntohs(hdr->frame_ctrl);
  //uint16_t fctl = hdr->frame_ctrl;

//printf("fctl: 0x%04X | type: %d, subtype: %d, toDS: %d, fromDS: %d\n",
//       fctl, (fctl >> 2) & 0x3, (fctl >> 4) & 0xF,
//       (fctl >> 8) & 0x1, (fctl >> 9) & 0x1);

//  Serial.printf("[DEBUG] hdr->frame_ctrl (raw): 0x%04X\n", hdr->frame_ctrl);
//  Serial.printf("[DEBUG] fctl (host-order):     0x%04X\n", fctl);
  //uint8_t* fcBytes = (uint8_t*)&hdr->frame_ctrl;
//  Serial.printf("[DEBUG] Frame Control Bytes: 0x%02X 0x%02X\n", fcBytes[0], fcBytes[1]);
  //uint8_t fType = (fctl >> 2) & 0x03;
  //uint8_t subtype = (fctl >> 4) & 0x0F;
//  Serial.printf("[DEBUG] Frame Type: 0x%02X, Subtype: 0x%02X\n", fType, subtype);
 // char comboRaw[10];
 // snprintf(comboRaw, sizeof(comboRaw), "%02X/%02X", fType, subtype);

//--trying something new----------
//bool toDS   = fctl & 0x0100;
//bool fromDS = fctl & 0x0200;
//bool qos    = ((fctl >> 7) & 0x01);  // QoS bit
//int offset = 24;  // base MAC header
//if (toDS && fromDS) offset += 6;   // Address4 field
//if (qos && ((fctl & 0x000C) == 0x0008)) offset += 2;  // QoS Control (for data subtype 0x08)
//int ieLen = ppkt->rx_ctrl.sig_len - offset;
//const uint8_t* ieData = payload + offset;
//-------------------------------

//FrameStatKey statKey;
//statKey.type = fType;
//statKey.subtype = subtype;

//  bool toDS   = fctl & (1 << 8);
//  bool fromDS = fctl & (1 << 9);
//    uint8_t toDS = (fctl >> 8) & 0x01;
//    uint8_t fromDS = (fctl >> 9) & 0x01;
//bool toDS = ((fctl >> 8) & 0x01);
//bool fromDS = ((fctl >> 9) & 0x01);
//uint8_t direction = 0;
//if (toDS == 1 && fromDS == 0) {
    // From station to AP
//    direction = 1;
//} else if (toDS == 0 && fromDS == 1) {
    // From AP to station
//    direction = 2;
//} else if (toDS == 0 && fromDS == 0) {
    // Station to station (ad-hoc)
//    direction = 0;
//} else if (toDS == 1 && fromDS == 1) {
    // AP to AP (WDS)
//    direction = 3;
//}

 // uint8_t direction = 0;
 // if (toDS && fromDS) direction = 3;
 // else if (toDS)      direction = 1;
 // else if (fromDS)    direction = 2;
  

//uint8_t direction = 0;
//if (toDS && !fromDS) direction = 1;
//else if (!toDS && fromDS) direction = 2;
//else if (toDS && fromDS) direction = 3;
//statKey.direction = direction;
//Serial.printf("[FRAME] type: %02X, subtype: %02X, dir: %d\n", fType, subtype, direction);
//Serial.printf("[INSERT] %02X/%02X dir=%d\n", statKey.type, statKey.subtype, statKey.direction);
//globalFrameStats[statKey]++;

  // Only interested in certain management/data frame subtypes
  /*
  if (fType != 0x00 || !(subtype == 0x00 || subtype == 0x02 || subtype == 0x04 ||
                         subtype == 0x0B || 
                         (subtype == 0x0C && !toDS && !fromDS) || 
                         (subtype == 0x0A && !toDS && !fromDS))) {
    return;
  }
*/
  bool isMgmt = (fType == 0x00 && (subtype == 0x00 || subtype == 0x02 || subtype == 0x04 ||
                         subtype == 0x0B || 
                         (subtype == 0x0C && !toDS && !fromDS) || 
                         (subtype == 0x0A && !toDS && !fromDS)));
  bool isQoSData = (fType == 0x02 && subtype == 0x0C && toDS && !fromDS);
  bool isType02 = (fType == 0x02);

  //if (!isMgmt) return;

//----------------[DEBUG] PACKET HEX DUMP----------------------
  if (!isMgmt && !isType02) return;
//  if (!isMgmt && !isQoSData) return;
//if ((isMgmt && subtype == 0x02) || isType02) {
//  if (isQoSData) {
//if (type == 0x02 && (subtype == 0x04 || subtype == 0x00) || (type == 0x00 && subtype == 0x0B)) {
  if (type == 0x00 && subtype == 0x0B) {
  //int thisLen = ppkt->rx_ctrl.sig_len;
  //const uint8_t* printData = payload;
//  Serial.printf("[FRAME] type: %02X, subtype: %02X, dir: %d\n", fType, subtype, direction);
//  Serial.println("[DEBUG] Raw Packet Hex Dump:");
//  printIEsDebug(ieData, ieLen);
//  Serial.println("\n=== QoS Data Frame Detected ===");
    Serial.println("\n=== Raw Frame Hex Dump ===");
    Serial.printf("Frame Ctrl: 0x%04X | Type: %u | Subtype: 0x%02X\n", fctl, type, subtype);
    const uint8_t* frame = ppkt->payload;
    dump_packet_hex(frame, ppkt->rx_ctrl.sig_len);
}
//----------------[END DEBUG]-------------------
  DeviceCapture cap;
  if (isMgmt && ppkt->rx_ctrl.sig_len < 40) return;
  //if (ppkt->rx_ctrl.sig_len < 40) return;
  // MNGMNT FRAME (CLIENT ASSOC/PROBE REQ) PARSING
  int offset = (subtype == 0x04) ? 24 : 36; //Mngmnt frame probe request (0x04->24) or association request (0x00->36)
  if (isQoSData) offset = 26;  // typical QoS data frame has 2-byte QoS Control
  int ieLen = ppkt->rx_ctrl.sig_len - offset;
  const uint8_t* ieData = payload + offset;

  sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X",
      hdr->addr2[0], hdr->addr2[1], hdr->addr2[2],
      hdr->addr2[3], hdr->addr2[4], hdr->addr2[5]);
  cap.macVendors[macStr] = lookupVendor(hdr->addr2);
  
  cap.primaryMac = String(macStr);
  cap.macAddresses.insert(cap.primaryMac);
  cap.SSIDs = extractSsid(ieData, ieLen);
  uint8_t ch = ppkt->rx_ctrl.channel;
  //cap.channelMask |= (1 << (ch - 1));
  char combo[6];
  snprintf(combo, sizeof(combo), "%1X%02X", fType, subtype);
  // Only append if this combo doesn't already exist
  if (cap.frameSubtypeStr.indexOf(combo) == -1) {
    if (cap.frameSubtypeStr.length() > 0) {
      cap.frameSubtypeStr += ",";
    }
    cap.frameSubtypeStr += String(combo);
  }

    int rssi = ppkt->rx_ctrl.rssi;
  cap.rssiMin = cap.rssiMax = rssi;
  cap.packetCount = 1;
  cap.firstSeen = cap.lastSeen = millis();


 if(isMgmt){ 
  parseWpsAndVendorIEs(ieData, ieLen, cap);
  if(cap.wps.wpsSum.length()){
    //Serial.println("[DEBUG] WPS Summary: " + cap.wps.wpsSum);
    cap.wps.shortWpsFP = shortHash(cap.wps.wpsSum);
    //Serial.println("[DEBUG] Short WPS FP: " + cap.wps.shortWpsFP);
  }

  //---Check if UUID ends with MAC address
  if (cap.wps.uuid.length() == 36) {
    char macStr[13];
    sprintf(macStr, "%02X%02X%02X%02X%02X%02X",
          ppkt->payload[10], ppkt->payload[11], ppkt->payload[12],
          ppkt->payload[13], ppkt->payload[14], ppkt->payload[15]);

    String uuidStr = cap.wps.uuid;
    uuidStr.replace("-", "");
    String uuidMacSuffix = uuidStr.substring(uuidStr.length() - 12);
    if (uuidMacSuffix.equalsIgnoreCase(String(macStr))) {
      cap.uuidMatchesMac = true;
      //Serial.println("[DEBUG] UUID matches MAC suffix — likely non-randomized.");
    }
  }
  //---
  cap.htMcsVhtCaps = parseHtVhtCapabilities(ieData, ieLen);
  cap.htMcsVhtCaps.shortHtMcsVhtFP = shortHash(cap.htMcsVhtCaps.htMcsVhtFP);
  bool powerManagement = fctl & (1 << 12);  // Bit 12
  if (powerManagement) {
    cap.sawPowerSaveFrame = true;
  }

  //cap.macAddresses.insert(mac);
 // cap.heuristicIEInfo = scanIEPayload(ieData, ieLen);
  parseSecMiscCaps(ieData, ieLen, cap);
  cap.security.secSum = buildSecSummary(cap.security);

  String secFP_temp;
  if(cap.security.hasRsn){
    secFP_temp += cap.security.rawRsnHex;
  }
  if(cap.security.hasWpa){
    secFP_temp += cap.security.rawWpaHex;
  }
  if(secFP_temp.length() > 0){
    cap.security.shortSecFP = shortHash(secFP_temp);
  }
  cap.miscCapSum = buildMiscCapsSum(cap);
  if(cap.miscCapSum.length()){
   cap.shortMiscCapsFP = shortHash(cap.miscCapSum);
  }
  if(cap.unknownAsciiTags.length()){
   cap.shortUnknwnAsciiFP = shortHash(cap.unknownAsciiTags);
  }

  cap.FP = cap.wps.shortWpsFP + "|" +
   cap.htMcsVhtCaps.shortHtMcsVhtFP + "|" +
   cap.security.shortSecFP + "|" +
   cap.shortMiscCapsFP + "|" +
   cap.vendorInfo + "|" +
   cap.shortUnknwnAsciiFP; 
  cap.shortFP = shortHash(cap.FP);
}

//  if (isEmpty(cap)) return;

  bool matched = false;
  
  for (DeviceCapture& existing : captures) {
    bool matchMAC = existing.macAddresses.count(cap.primaryMac) > 0;

    bool matchMACnByteDiff = macsDifferByAtMostNbytes(existing.primaryMac, cap.primaryMac, 1);

    bool matchFP = cap.shortFP == existing.shortFP;

    //bool matchUUID = !cap.wps.uuid.isEmpty() &&
    //             cap.wps.uuid == existing.wps.uuid;

    //bool matchCAP = !cap.htmcsvhtcaps.htMcsVhtFP.isEmpty() &&
    //                cap.htmcsvhtcaps.htMcsVhtFP == existing.htmcsvhtcaps.htMcsVhtFP;

    //bool matchSSID = cap.wps.wpsFP.isEmpty() &&
    //                 cap.htmcsvhtcaps.htMcsVhtFP.isEmpty() &&
    //                 cap.SSIDs == existing.SSIDs;
/*
    Serial.println("[DEBUG] Comparing with existing device...");
    Serial.println("  → WPS FP: " + cap.wps.shortWpsFP + " vs " + existing.wps.shortWpsFP);
    Serial.println("  → Cap FP: " + cap.htmcsvhtcaps.shortHtMcsVhtFP + " vs " + existing.htmcsvhtcaps.shortHtMcsVhtFP);
    Serial.println("  → WPS Match: " + String(matchWPS ? "YES" : "NO"));
    Serial.println("  → Cap Match: " + String(matchCAP ? "YES" : "NO"));
    Serial.println("  → FPs empty but SSIDs match: " + String(matchSSID ? "YES" : "NO"));
*/
//    if ((matchCAP && matchUUID) ||
//      matchSSID ||
//      (matchMACnByteDiff && (matchCAP || matchUUID)) ||
//       matchMAC) {
  if(matchMAC || matchFP || matchMACnByteDiff) {
/*
      Serial.println("[DEBUG] This device FP MATCHES previously found FP...");
      Serial.println("  → WPS FP: " + cap.wps.shortWpsFP + " vs " + existing.wps.shortWpsFP);
      Serial.println("  → Cap FP: " + cap.htmcsvhtcaps.shortHtMcsVhtFP + " vs " + existing.htmcsvhtcaps.shortHtMcsVhtFP);
      Serial.println("  → WPS Match: " + String(matchWPS ? "YES" : "NO"));
      Serial.println("  → Cap Match: " + String(matchCAP ? "YES" : "NO"));
      Serial.println("  → FPs empty but SSIDs match: " + String(matchSSID ? "YES" : "NO"));
      Serial.println("[DEBUG] Checking RSSI...");
*/
      int avgRssi = (existing.rssiMin + existing.rssiMax) / 2;
      int delta = abs(rssi - avgRssi);
      //Serial.println("  → RSSI Current: " + String(rssi) + " | Avg: " + String(avgRssi) + " | Δ: " + String(delta));

      if (delta < 1195) { //Set RSSI divergence threshold
        //Serial.println("[DEBUG] RSSI matches too. Full Match. Updating device info...");
        // Update existing capture
        existing.packetCount++;
        existing.lastSeen = millis();
        if (rssi < existing.rssiMin) existing.rssiMin = rssi;
        if (rssi > existing.rssiMax) existing.rssiMax = rssi;
        // Update channel mask
        existing.channelMask |= (1 << (ch - 1));  // Channel 1 = bit 0, etc.
        if (existing.frameSubtypeStr.indexOf(combo) == -1) {
          if (existing.frameSubtypeStr.length() > 0) {
          existing.frameSubtypeStr += ",";
          }
          existing.frameSubtypeStr += combo;
        }
        //String combo = "0x" + String(fType, HEX) + "/0x" + String(subtype, HEX);
        //if (!existing.frameSubtypeStr.indexOf(combo) == -1) {
        //  existing.frameSubtypeStr += (existing.frameSubtypeStr.length() > 0 ? "," : "") + combo;
        //}

        if(isMgmt){
        if (cap.SSIDs.length() > 0 && existing.SSIDs.indexOf(cap.SSIDs) == -1) {
          if (existing.SSIDs.length() > 0) existing.SSIDs += "; ";
          existing.SSIDs += cap.SSIDs;
        }
        //existing.heuristicIEInfo = scanIEPayload(ieData, ieLen);
        //existing.macAddresses.insert(mac);
        //if (cap.primaryMac.length()) {
        //  existing.macAddresses.insert(cap.primaryMac);
        //}

        if (cap.primaryMac.length()) {
          existing.macAddresses.insert(cap.primaryMac);
          if (existing.macVendors.find(cap.primaryMac) == existing.macVendors.end()) {
           uint8_t macBytes[6];
           sscanf(cap.primaryMac.c_str(), "%hhX:%hhX:%hhX:%hhX:%hhX:%hhX",
           &macBytes[0], &macBytes[1], &macBytes[2],
           &macBytes[3], &macBytes[4], &macBytes[5]);
           existing.macVendors[cap.primaryMac] = lookupVendor(macBytes);
          }
        }

        existing.uuidMatchesMac |= cap.uuidMatchesMac;

        // Update WPS info only if new info is present and existing is missing
        if (cap.wps.deviceName.length() > existing.wps.deviceName.length())
          existing.wps.deviceName = cap.wps.deviceName;

        if (cap.wps.modelName.length() > existing.wps.modelName.length())
          existing.wps.modelName = cap.wps.modelName;

        if (cap.wps.serialNumber.length() > existing.wps.serialNumber.length())
          existing.wps.serialNumber = cap.wps.serialNumber;

        if (cap.wps.modNumDetail.length() > existing.wps.modNumDetail.length())
          existing.wps.modNumDetail = cap.wps.modNumDetail;

        if (cap.wps.primaryDeviceType.length() > existing.wps.primaryDeviceType.length())
          existing.wps.primaryDeviceType = cap.wps.primaryDeviceType;

        if (cap.wps.rfBand.length() > existing.wps.rfBand.length())
          existing.wps.rfBand = cap.wps.rfBand;

        if (cap.wps.vendorExt.length() > existing.wps.vendorExt.length())
          existing.wps.vendorExt = cap.wps.vendorExt;

        // Prefer configMethod if previously zero
        if (cap.wps.configMethods != 0 && existing.wps.configMethods == 0)
          existing.wps.configMethods = cap.wps.configMethods;

        // Prefer devicePasswordId if previously zero
        if (cap.wps.devicePasswordId != 0 && existing.wps.devicePasswordId == 0)
          existing.wps.devicePasswordId = cap.wps.devicePasswordId;

        // Replace wpsSum if it's clearly longer (more complete)
        if (cap.wps.wpsSum.length() > existing.wps.wpsSum.length())
          existing.wps.wpsSum = cap.wps.wpsSum;

        // Also consider merging UUID if needed (should be equal in most merge cases)
        if (existing.wps.uuid.isEmpty() && cap.wps.uuid.length())
          existing.wps.uuid = cap.wps.uuid;

        existing.sawPowerSaveFrame |= cap.sawPowerSaveFrame;

        }
        matched = true;
        break;
      } else {
       //Serial.println("[DEBUG] FPs match but RSSI too different to be same device. Adding as new device...");
       
      }

    }
  }

  // If no match found, store as new device
  if (!matched && captures.size() < MAX_DEVICES) {
    cap.udfId = nextUdfId++;
    captures.push_back(cap);
    ESP.getFreeHeap();
    // Optional debug analysis
    Serial.print("[DEBUG] New device found:");
    Serial.println();
    //Serial.println(cap.udfId);
    Serial.println("[DEBUG] Assign UDF ID#: " + String(cap.udfId));
    Serial.println("[DEBUG] Short HT/MCS/VHT Fingerprint: " + cap.htMcsVhtCaps.shortHtMcsVhtFP);
    Serial.println("[DEBUG] Short WPS Fingerprint: " + cap.wps.shortWpsFP);
    Serial.println("[DEBUG] SSID: " + cap.SSIDs);
    Serial.println("[DEBUG] Vendor Info: " + cap.vendorInfo);
    if (cap.wps.deviceName.length())  Serial.println("[DEBUG] WPS Device Name: " + cap.wps.deviceName);
    if (cap.wps.modelName.length())   Serial.println("[DEBUG] WPS Model: " + cap.wps.modelName);
    if (cap.wps.uuid.length())        Serial.println("[DEBUG] WPS UUID: " + cap.wps.uuid);
    Serial.println("[DEBUG] MCS Set: " + mcsSetToString(cap.htMcsVhtCaps.mcsSet));
    Serial.println("[DEBUG] RSSI: " + String(rssi));
    Serial.printf("[DEBUG] First Seen: %s\n", formatTimestamp(cap.firstSeen).c_str());
    Serial.println("[DEBUG] HT/MCS/VHT Fingerprint: " + cap.htMcsVhtCaps.htMcsVhtFP);
    if(cap.wps.wpsSum.length()){Serial.println("[DEBUG] WPS Fingerprint: " + cap.wps.wpsSum);}
    if (cap.uuidMatchesMac) Serial.println("UUID ↔ MAC:         ✅ Match (likely non-randomized)");
    //Serial.println("[DEBUG] Heuristic payload scan:");
    //Serial.println(cap.heuristicIEInfo);

  }
}

// === SETUP & LOOP ===
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
    logToCSV(timestamp); // Save to SD
    esp_wifi_stop();
//    bool printed[MAX_DEVICES] = {false};
    //---print table here
    printScanSummaryTable();
    printGlobalFrameStats();
    printMacStats();
    Serial.println("\n[INFO] Scan done, sleeping...\n");
  // sleep between scans
  }
  else if (!scanning && now - sleepStart >= SLEEP_DURATION) {
    Serial.println("[INFO] Waking up, new scan starts...\n");
    // reset for next cycle
    nextUdfId = 1;
    Serial.printf("[DEBUG] Free heap before clearing captures: %lu\n", ESP.getFreeHeap());
    captures.clear();
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