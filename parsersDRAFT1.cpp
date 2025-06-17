#include "parsers.h"
#include "esp_wifi.h"
#include <stdio.h>
#include <SD.h>
#include "nvs_flash.h"
#include <map>
#include <set>
#include <vector>   // ← Fixes the error you're seeing
#include <algorithm>  // ← Required for std::sort

#define SD_CS 5  // or your CS pin

std::map<String, MacStats> macStatsMap;
std::map<FrameStatKey, int> globalFrameStats;

//=============================================================
// Helpers
//=============================================================
bool isLikelyEui64(const uint8_t* addr) {
  // Check for FF:FE at positions 11 and 12 (bytes 8 and 9 of the IID)
  return (addr[11] == 0xFF && addr[12] == 0xFE);
}

String extractMacFromEUI64(const uint8_t* addr) {
  uint8_t mac[6];
  mac[0] = addr[8] ^ 0x02; // Flip the U/L bit
  mac[1] = addr[9];
  mac[2] = addr[10];
  mac[3] = addr[13];
  mac[4] = addr[14];
  mac[5] = addr[15];

  char macStr[18];
  snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  return String(macStr);
}

void printFlowSummary(const std::map<String, uint32_t>& flowCounts,
                      const std::map<String, uint64_t>& flowBytes,
                      const std::map<String, uint64_t>& flowBytesSq,
                      const char* label = "Flows",
                      size_t maxToShow = 7) {
  if (flowCounts.empty()) return;

  Serial.printf("📶 %s:\n", label);

  // Convert to vector for sorting
  std::vector<std::pair<String, uint32_t>> sorted(flowCounts.begin(), flowCounts.end());

  std::sort(sorted.begin(), sorted.end(),
            [](const std::pair<String, uint32_t>& a, const std::pair<String, uint32_t>& b) {
              return a.second > b.second;
            });

  size_t shown = 0;
  uint32_t totalShown = 0;

  for (const auto& pair : sorted) {
    const String& flow = pair.first;
    uint32_t count = pair.second;

    if (shown++ < maxToShow) {
      uint32_t totalBytes = flowBytes.count(flow) ? flowBytes.at(flow) : 0;
      float mean = (count > 0) ? ((float)totalBytes / count) : 0.0;

      // For now, assume no per-packet size tracking, so stdDev is zero
      // You can later add stdDevBytes[flow] if needed
      Serial.printf("  %s : %u pkts, %.1f B/packet\n", flow.c_str(), count, mean);

      totalShown += count;
    } else {
      break;
    }
  }

  if (flowCounts.size() > maxToShow) {
    size_t remaining = flowCounts.size() - maxToShow;
    Serial.printf("  + %zu more flows not shown\n", remaining);
  }
}

/*
void printIpv4FlowSummary(const std::map<String, uint32_t>& ipv4Flows,
                          const std::map<String, uint64_t>& ipv4FlowBytes,
                          const std::map<String, std::set<String>>& dnsHostnamesByFlow,
                          int maxFlows = 7) {
  if (ipv4Flows.empty()) return;

  Serial.println("    🧭 IPv4 Flows:");

  // Sort by count descending
  std::vector<std::pair<String, uint32_t>> flowVec(ipv4Flows.begin(), ipv4Flows.end());
  std::sort(flowVec.begin(), flowVec.end(),
          [](const std::pair<String, uint32_t>& a, const std::pair<String, uint32_t>& b) {
              return a.second > b.second;
          });


  int shown = 0;

  for (const auto& kv : flowVec) {
    if (shown >= maxFlows) break;

    const String& flowKey = kv.first;
    uint32_t pktCount = kv.second;
    uint64_t byteCount = 0;

    auto itByte = ipv4FlowBytes.find(flowKey);
    if (itByte != ipv4FlowBytes.end()) {
      byteCount = itByte->second;
    }

    Serial.printf("        • %s : %u pkts, %.1f KB\n", flowKey.c_str(), pktCount, byteCount / 1024.0);

    auto itHost = dnsHostnamesByFlow.find(flowKey);
    if (itHost != dnsHostnamesByFlow.end() && !itHost->second.empty()) {
      Serial.print("          Hostnames: ");
      int i = 0;
      for (const String& hostname : itHost->second) {
        if (i++ > 0) Serial.print(" | ");
        Serial.print(hostname);
      }
      Serial.println();
    }

    ++shown;
  }

  int extra = flowVec.size() - shown;
  if (extra > 0) {
    Serial.printf("        ... + %d more flows\n", extra);
  }
}

void printIpv6FlowSummary(const std::map<String, uint32_t>& ipv6Flows,
                          const std::map<String, uint64_t>& ipv6FlowBytes,
                          int maxFlows = 7) {
  if (ipv6Flows.empty()) return;

  Serial.println("    🧭 IPv6 Flows:");

  std::vector<std::pair<String, uint32_t>> flowVec(ipv6Flows.begin(), ipv6Flows.end());
  std::sort(flowVec.begin(), flowVec.end(),
          [](const std::pair<String, uint32_t>& a, const std::pair<String, uint32_t>& b) {
              return a.second > b.second;
          });

  int shown = 0;

  for (const auto& kv : flowVec) {
    if (shown >= maxFlows) break;

    const String& flowKey = kv.first;
    uint32_t pktCount = kv.second;
    uint64_t byteCount = 0;

    auto itByte = ipv6FlowBytes.find(flowKey);
    if (itByte != ipv6FlowBytes.end()) {
      byteCount = itByte->second;
    }

    Serial.printf("        • %s : %u pkts, %.1f KB\n", flowKey.c_str(), pktCount, byteCount / 1024.0);
    ++shown;
  }

  int extra = flowVec.size() - shown;
  if (extra > 0) {
    Serial.printf("        ... + %d more flows\n", extra);
  }
}
*/

String extractIPv6Prefix(const uint8_t* addr) {
  char prefix[40];
  snprintf(prefix, sizeof(prefix), "%02x%02x:%02x%02x:%02x%02x:%02x%02x::/64",
           addr[0], addr[1], addr[2], addr[3],
           addr[4], addr[5], addr[6], addr[7]);
  return String(prefix);
}

String formatIPv6(const uint8_t* addr, bool annotate = true) {
  char buf[40];
  snprintf(buf, sizeof(buf),
           "%02X%02X:%02X%02X:%02X%02X:%02X%02X:"
           "%02X%02X:%02X%02X:%02X%02X:%02X%02X",
           addr[0], addr[1], addr[2], addr[3],
           addr[4], addr[5], addr[6], addr[7],
           addr[8], addr[9], addr[10], addr[11],
           addr[12], addr[13], addr[14], addr[15]);

  String ip(buf);

  if (!annotate) return ip;

  // Append helpful labels
  if (ip.startsWith("FE80")) ip += " 🔗 link-local";
  else if (ip.startsWith("FF02::1")) ip += " 🔉 all-nodes";
  else if (ip.startsWith("FF02::2")) ip += " 📣 all-routers";
  else if (ip.startsWith("2001:4860:4860::8888")) ip += " 🌐 Google DNS";

  if (isLikelyEui64(addr)) {
    String mac = extractMacFromEUI64(addr);
    ip += " 🧬 EUI-64 MAC: " + mac;
  }

  return ip;
}

const char* directionToStr(FrameDirection dir) {
  switch (dir) {
    case DIR_CLIENT_TO_AP: return "Cl→AP";
    case DIR_AP_TO_CLIENT: return "AP→Cl";
    case DIR_STA_STA:      return "STA↔STA";
    case DIR_WDS:          return "WDS";
    default:               return "Unknown";
  }
}

void addSsidToStats(MacStats& stats, const String& ssid) {
  if (ssid.length() == 0) return;

  if (stats.mgmt.seenSsids.insert(ssid).second) {
    Serial.println("[📡] New SSID discovered for MAC (addSsidToStats): \"" + ssid + "\"");
  }
}

void parseUnknownAsciiIe(uint8_t tagId, const uint8_t* tagData, uint8_t tagLen, String& output) {
  // Known tags — ignore these
  static const uint8_t knownTags[] = {
    0x00, 0x01, 0x03, 0x05, 0x07, 0x0B, 0x2A, 0x2D, 0x32,
    0x3D, 0x30, 0xDD, 0x7F, 0x46, 0x23, 0x22, 0x24, 0x36
  };
  for (uint8_t i = 0; i < sizeof(knownTags); ++i)
    if (tagId == knownTags[i]) return;

  if (tagLen < 4) return;

  // Check all chars printable
  for (int i = 0; i < tagLen; ++i)
    if (tagData[i] < 32 || tagData[i] > 126) return;

  // Build string
  String result = "";
  for (int i = 0; i < tagLen; ++i)
    result += (char)tagData[i];

  // Skip duplicates or overflow
  const int MAX_ASCII_TOTAL = 100;
  if (output.indexOf(result) != -1 || output.length() + result.length() + 1 > MAX_ASCII_TOTAL)
    return;

  // Append
  if (output.length()) output += ";";
  output += result;

  // Print once
  Serial.printf("  🔍 [ASCII Tag] 0x%02X (%3d): \"%s\"\n", tagId, tagId, result.c_str());
}

String extractSsid(const uint8_t* payload, int len) {
  int offset = 0;
  while (offset + 2 <= len) {
    uint8_t id = payload[offset];
    uint8_t tagLen = payload[offset + 1];

    if (offset + 2 + tagLen > len) break;
    Serial.printf("[DEBUG extractSsid] tagLen=%d, offset=%d, ieLen=%d\n", tagLen, offset, len);
    if (id == 0 && tagLen <= 32) {  // SSID tag
      if (tagLen == 0) return "";  // hidden SSID

      String ssid = "";
      for (int i = 0; i < tagLen; ++i) {
        char c = payload[offset + 2 + i];
        if (c >= 32 && c <= 126) ssid += c;
      }

      return ssid.length() ? ssid : "";
    }

    offset += 2 + tagLen;
  }

  return "";
}

String abbreviateMacPurpose(const String& purpose) {
  if (purpose == "Broadcast") return "BC";
  if (purpose == "IPv6 mDNS (33:33:00:00:00:01)") return "mDNS6";
  if (purpose == "IPv6 Multicast") return "MC6";
  if (purpose == "IPv4 mDNS (224.0.0.251)") return "mDNS4";
  if (purpose == "SSDP / UPnP (239.255.255.250)") return "SSDP";
  if (purpose == "IPv4 Multicast (01:00:5E)") return "MC4";
  if (purpose == "IEEE Reserved Multicast") return "IEEE";
  if (purpose == "Cisco Discovery Protocol (CDP)") return "CDP";
  if (purpose == "LLDP (Link Layer Discovery Protocol)") return "LLDP";
  if (purpose == "Multicast (Unknown or Vendor-Specific)") return "MC?";
  return purpose; //If no match then assume its a vendor name (Unicast) and pass through
}

void initSD() {
  if (!SD.begin(SD_CS)) {
    Serial.println("[ERROR] SD card initialization failed!");
  } else {
    Serial.println("[INFO] SD card initialized.");
  }
}

String getScanTimestamp() {
  unsigned long ms = millis();
  int sec = ms / 1000;
  int min = (sec / 60) % 60;
  int hr  = (sec / 3600) % 24;
  char buf[12];
  snprintf(buf, sizeof(buf), "%02d:%02d:%02d", hr, min, sec % 60);
  return String(buf);
}
String formatTimestamp(unsigned long ms) {
  int sec = ms / 1000;
  int min = (sec / 60) % 60;
  int hr  = (sec / 3600) % 24;
  char buf[12];
  snprintf(buf, sizeof(buf), "%02d:%02d:%02d", hr, min, sec % 60);
  return String(buf);
}
String lookupVendor(const uint8_t* mac) {
  for (size_t i = 0; i < vendorCount; ++i) {
    if (memcmp(mac, vendorTable[i].prefix, 3) == 0) {
      return vendorTable[i].name;
    }
  }
  return "Unknwn";
}
// Convert bitmask → channel list string
String formatChannelList(uint16_t mask) {
  String result = "";
  for (int i = 0; i < 13; i++) {
    if (mask & (1 << i)) {
      if (result.length() > 0) result += ",";
      result += String(i + 1);
    }
  }
  return result;
}
String extractAsciiPayloadFromDF(const uint8_t* payload, uint16_t len) {
  String result = "";
  String temp = "";
  for (uint16_t i = 0; i < len; i++) {
    char c = (char)payload[i];
    if (isPrintable(c)) {
      temp += c;
    } else {
      if (temp.length() >= 3) {
        if (!result.isEmpty()) result += "|";
        result += temp;
      }
      temp = "";
    }
  }
  // Add any trailing valid string
  if (temp.length() >= 3) {
    if (!result.isEmpty()) result += "|";
    result += temp;
  }
  return result;
}

void hexDump(const uint8_t* data, int len) {
  Serial.println("[DEBUG] Full packet hex dump:");
  for (int i = 0; i < len; ++i) {
    if (i % 16 == 0) {
      if (i != 0) Serial.println();         // New line after 16 bytes
      Serial.printf("%04X: ", i);           // Offset
    }
    Serial.printf("%02X ", data[i]);        // Hex byte
  }
  Serial.println();
}

//String hexDump(const uint8_t* data, int len) {
//  char buf[4];  // enough for 2-digit hex + null + separator
//  String out = "";
//  for (int i = 0; i < len; ++i) {
//    if (i > 0) out += ":";
//    sprintf(buf, "%02X", data[i]);
//    out += buf;
//  }
//  return out;
//}

void printIEsDebug(const uint8_t* ieData, int ieLen) {
  Serial.println("[DEBUG] Scanning Information Elements:");
  int pos = 0;

  while (pos + 2 <= ieLen) {
    uint8_t tagNumber = ieData[pos];
    uint8_t tagLength = ieData[pos + 1];

    if (pos + 2 + tagLength > ieLen) {
      Serial.printf("  [WARN] IE tag 0x%02X at offset %d exceeds bounds\n", tagNumber, pos);
      break;
    }

    // Identify tag name
    String tagName;
    switch (tagNumber) {
      case 0x00: tagName = "SSID"; break;
      case 0x01: tagName = "Supported Rates"; break;
      case 0x03: tagName = "DS Parameter Set (Channel)"; break;
      case 0x07: tagName = "Country Code"; break;
      case 0x2A: tagName = "Power Capability"; break;
      case 0x2B: tagName = "Supported Channels"; break;
      case 0x2D: tagName = "HT Capabilities"; break;
      case 0x30: tagName = "RSN"; break;
      case 0x32: tagName = "Extended Supported Rates"; break;
      case 0x36: tagName = "HT Capabilities"; break;
      case 0x3D: tagName = "HT Information"; break;
      case 0x46: tagName = "QoS Capability"; break;
      case 0x4A: tagName = "Neighbor Report"; break;
      case 0x7F: tagName = "Extended Capabilities"; break;
      case 0xDD: tagName = "Vendor Specific"; break;
      default:   tagName = "Unknown"; break;
    }

    Serial.printf("  Tag: 0x%02X (%3d) %-25s Len: %2d → ", tagNumber, tagNumber, tagName.c_str(), tagLength);

    // Special case for Country Code
    if (tagNumber == 0x07 && tagLength >= 3) {
      char country[4] = {0};
      country[0] = (char)ieData[pos + 2];
      country[1] = (char)ieData[pos + 3];
      country[2] = (char)ieData[pos + 4];
      Serial.print("Country Code: ");
      Serial.println(country);
    } else {
      // ASCII or hex content
      bool printable = true;
      for (int i = 0; i < tagLength; ++i) {
        if (ieData[pos + 2 + i] < 32 || ieData[pos + 2 + i] > 126) {
          printable = false;
          break;
        }
      }

      if (printable && tagLength > 0) {
        Serial.print("ASCII: ");
        for (int i = 0; i < tagLength; ++i) {
          Serial.print((char)ieData[pos + 2 + i]);
        }
        Serial.println();
      } else {
        Serial.print("HEX: ");
        for (int i = 0; i < tagLength; ++i) {
          Serial.printf("%02X ", ieData[pos + 2 + i]);
        }
        Serial.println();
      }
    }

    pos += 2 + tagLength;
  }

  if (pos != ieLen) {
    Serial.printf("[WARN] Remaining %d bytes at end of IE section\n", ieLen - pos);
  }
}


String classifyDestMacPurpose(const uint8_t* mac) {
  // Broadcast
  if (mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF &&
      mac[3] == 0xFF && mac[4] == 0xFF && mac[5] == 0xFF)
    return "Broadcast";

  // IPv6 multicast (33:33:xx:xx:xx:xx)
  if (mac[0] == 0x33 && mac[1] == 0x33) {
    if (mac[5] == 0x01)
      return "IPv6 mDNS (33:33:00:00:00:01)";
    return "IPv6 Multicast";
  }

  // IPv4 multicast (01:00:5E:xx:xx:xx)
  if (mac[0] == 0x01 && mac[1] == 0x00 && mac[2] == 0x5E) {
    if (mac[3] == 0x00 && mac[4] == 0x00 && mac[5] == 0xFB)
      return "IPv4 mDNS (224.0.0.251)";
    if (mac[3] == 0x00 && mac[4] == 0x00 && mac[5] == 0xFC)
      return "SSDP / UPnP (239.255.255.250)";
    return "IPv4 Multicast (01:00:5E)";
  }

  // IEEE Reserved Multicast (Spanning Tree, LLDP, etc.)
  if (mac[0] == 0x01 && mac[1] == 0x80 && mac[2] == 0xC2 &&
      mac[3] == 0x00 && mac[4] == 0x00 &&
      mac[5] >= 0x00 && mac[5] <= 0x0F)
    return "IEEE Reserved Multicast";

  // Cisco Discovery Protocol (CDP)
  if (mac[0] == 0x01 && mac[1] == 0x00 && mac[2] == 0x0C &&
      mac[3] == 0xCC && mac[4] == 0xCC && mac[5] == 0xCC)
    return "Cisco Discovery Protocol (CDP)";

  // LLDP
  if (mac[0] == 0x01 && mac[1] == 0x80 && mac[2] == 0xC2 &&
      mac[3] == 0x00 && mac[4] == 0x00 && mac[5] == 0x0E)
    return "LLDP (Link Layer Discovery Protocol)";

  // Multicast flag
  if ((mac[0] & 0x01) != 0)
    return "Multicast (Unknown or Vendor-Specific)";

  return "Unicast";
}

//=============================================================
// Main parsers
//=============================================================
//----Global items (common to both data and management frames) parsing--------
void parseGlobalItems(const wifi_promiscuous_pkt_t* ppkt, DeviceCapture& cap) {
  const uint8_t* frame = ppkt->payload;
  uint16_t len = ppkt->rx_ctrl.sig_len;
  int8_t rssi = ppkt->rx_ctrl.rssi;
  uint8_t ch = ppkt->rx_ctrl.channel;

  if (len < 24) return;

  uint16_t fctl = *(const uint16_t*)frame;
  uint8_t type = (fctl >> 2) & 0x03;
  uint8_t subtype = (fctl >> 4) & 0x0F;
  bool toDS = fctl & (1 << 8);
  bool fromDS = fctl & (1 << 9);

  // Set enum and string version of direction
  if (toDS && !fromDS) {
    cap.directionCode = DIR_CLIENT_TO_AP;
  } else if (!toDS && fromDS) {
    cap.directionCode = DIR_AP_TO_CLIENT;
  } else if (!toDS && !fromDS) {
    cap.directionCode = DIR_STA_STA;
  } else if (toDS && fromDS) {
    cap.directionCode = DIR_WDS;
  } else {
    cap.directionCode = DIR_UNKNOWN;
  }

  cap.directionText = String(directionToStr(cap.directionCode));
  cap.frameType = type;
  cap.subtype = subtype;
  cap.length = len;
  cap.rssi = rssi;
  cap.timeSeen = millis();

  const uint8_t* addr1 = frame + 4;   // Receiver
  const uint8_t* addr2 = frame + 10;  // Transmitter
  const uint8_t* addr3 = frame + 16;  // BSSID or STA addr

  char mac1[18], mac2[18], mac3[18];
  snprintf(mac1, sizeof(mac1), "%02X:%02X:%02X:%02X:%02X:%02X", addr1[0], addr1[1], addr1[2], addr1[3], addr1[4], addr1[5]);
  snprintf(mac2, sizeof(mac2), "%02X:%02X:%02X:%02X:%02X:%02X", addr2[0], addr2[1], addr2[2], addr2[3], addr2[4], addr2[5]);
  snprintf(mac3, sizeof(mac3), "%02X:%02X:%02X:%02X:%02X:%02X", addr3[0], addr3[1], addr3[2], addr3[3], addr3[4], addr3[5]);

  cap.senderMac = String(mac2);
  cap.receiverMac = String(mac1);
  cap.bssidMac = String(mac3);

  cap.srcVendor = lookupVendor(addr2);
  cap.dstMacPurpose = classifyDestMacPurpose(addr1);
  if (cap.dstMacPurpose == "Unicast") {
    cap.dstMacPurpose = lookupVendor(addr1);
  }
  cap.bssidVendor = lookupVendor(addr3);

  if (ch >= 1 && ch <= 14)
    cap.channelMask |= (1 << (ch - 1));
}

void updateMacStatsFromGlobalItems(const DeviceCapture& cap) {
  MacStats& stats = macStatsMap[cap.senderMac];

  // First seen
  if (stats.packetCount == 0) {
    stats.firstSeen = cap.timeSeen;
    stats.vendor = cap.srcVendor;
  }

  // Last seen always updated
  stats.lastSeen = cap.timeSeen;

  // Packet count
  stats.packetCount++;

  // RSSI
  if (cap.rssi < stats.rssiMin) stats.rssiMin = cap.rssi;
  if (cap.rssi > stats.rssiMax) stats.rssiMax = cap.rssi;

  // Channel tracking
  //cap.channelMask |= (1 << (ch - 1));
  stats.channelsSeen |= cap.channelMask;

  // Frame combo key (e.g. "020C(Cl→AP)")
  FrameStatKey key = {
    .type = cap.frameType,
    .subtype = cap.subtype,
    .direction = static_cast<uint8_t>(cap.directionCode)
  };
  stats.frameCombos[key]++;
  stats.lenSum += cap.length;
  stats.lenSqSum += cap.length * cap.length;

  String rxPrefix = cap.receiverMac.substring(0, 8);  // First 3 bytes
  String rxSummary = rxPrefix + "(" + abbreviateMacPurpose(cap.dstMacPurpose) + ")";
  stats.rxMacSummaries.insert(rxSummary);
  String bssidPrefix = cap.bssidMac.substring(0, 8);  // First 3 bytes
  String bssidSummary = bssidPrefix + "(" + cap.bssidVendor + ")";
  stats.bssidSummaries.insert(bssidSummary);
  
}
//---Data frame parsing---------------------

void parseDataFrame(const uint8_t* frame, uint16_t len, const DeviceCapture& cap) {
  if (cap.frameType != 2) return;

  const String& macKey = cap.senderMac;
  MacStats& stats = macStatsMap[macKey];

  uint8_t macHeaderLen = 24;
  if (cap.directionCode == DIR_WDS) macHeaderLen += 6;
  //bool isQoS = (cap.subtype == 0x0C || cap.subtype == 0x0D);
  //bool isQoS = (cap.subtype & 0x08); // bits 2-3 indicate QoS frame
  bool isQoS = cap.subtype >= 0x08 && cap.subtype <= 0x0F;

  if (isQoS) macHeaderLen += 2;

  if (len < macHeaderLen) return;

  if (isQoS) {
    const uint8_t* qosCtrl = frame + macHeaderLen - 2;
    uint8_t qos1 = qosCtrl[0];
    uint8_t tid = qos1 & 0x0F;
    bool eosp = qos1 & 0x10;
    bool amsdu = qos1 & 0x20;

    if (cap.directionCode == DIR_CLIENT_TO_AP) {
      stats.df.qosUpCount++;
      stats.df.tidUpSum += tid;
      stats.df.tidUpSqSum += tid * tid;
      stats.df.amsduUpSum += amsdu;
      stats.df.eospUpSum += eosp;
      stats.df.qosLenUpSum += cap.length;
      stats.df.qosLenUpSqSum += cap.length * cap.length;
      if (cap.isEncrypted) stats.df.encryptedUpCount++;
    } else if (cap.directionCode == DIR_AP_TO_CLIENT) {
      stats.df.qosDownCount++;
      stats.df.tidDownSum += tid;
      stats.df.tidDownSqSum += tid * tid;
      stats.df.amsduDownSum += amsdu;
      stats.df.eospDownSum += eosp;
      stats.df.qosLenDownSum += cap.length;
      stats.df.qosLenDownSqSum += cap.length * cap.length;
      if (cap.isEncrypted) stats.df.encryptedDownCount++;
    }

    Serial.printf("🎯 QoS Control: TID = %u | A-MSDU = %s | EOSP = %s%s\n",
      tid, amsdu ? "Yes" : "No", eosp ? "Yes" : "No",
      cap.isEncrypted ? " | 🔐 Encrypted" : "");

    if (tid >= 4 && tid < 6) Serial.println("🟡 Possibly video (TID 4-5)");
    else if (tid >= 6 && tid < 8) Serial.println("🚨 High-priority traffic (TID 6-7)");
  }

  if (cap.isEncrypted) return;
  if (len < macHeaderLen + 8) return;

  const uint8_t* llc = frame + macHeaderLen;
  if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03) return;

  uint32_t oui = (llc[3] << 16) | (llc[4] << 8) | llc[5];
  uint16_t etherType = (llc[6] << 8) | llc[7];
  Serial.printf("[DEBUG] EtherType detected: 0x%04X\n", etherType);
  switch (etherType) {
    case 0x0806: stats.df.etherTypeSummaryCounts["ARP"]++; break;
    case 0x888E: stats.df.etherTypeSummaryCounts["EAPOL"]++; break;
    case 0x8100: stats.df.etherTypeSummaryCounts["802.1Q VLAN"]++; break;
    case 0x8847: stats.df.etherTypeSummaryCounts["MPLS"]++; break;
    case 0x8864: stats.df.etherTypeSummaryCounts["PPP-over-E"]++; break;
    case 0x88CC: stats.df.etherTypeSummaryCounts["LLDP"]++; break;
    default: {
      // Only count this if it’s not IPv4/IPv6, those are parsed further below
      if (etherType != 0x0800 && etherType != 0x86DD) {
       char label[16];
       snprintf(label, sizeof(label), "0x%04X", etherType);
       stats.df.etherTypeSummaryCounts[label]++;
      }
      break;
    }
  }
Serial.printf("[DEBUG] EtherType categorized and counted: 0x%04X\n", etherType);

  const uint8_t* payload = llc + 8;
  uint16_t payloadLen = len - (macHeaderLen + 8);

  stats.df.etherTypes.insert(etherType);
  Serial.printf("\n📦 EtherType: 0x%04X\n", etherType);
  if (oui != 0x000000) {
    Serial.printf("🔧 OUI: 0x%06X (non-standard encapsulation)\n", oui);
  }

  // ---------- IPv4 ----------
  if (etherType == 0x0800 && payloadLen >= 20) {
    Serial.println("🌐 IPv4 Packet");
    const uint8_t* ip = payload;
    uint8_t ihl = (ip[0] & 0x0F) * 4;
    uint8_t protocol = ip[9];

char srcIp[16], dstIp[16];
snprintf(srcIp, sizeof(srcIp), "%u.%u.%u.%u", ip[12], ip[13], ip[14], ip[15]);
snprintf(dstIp, sizeof(dstIp), "%u.%u.%u.%u", ip[16], ip[17], ip[18], ip[19]);

String flowKey = String(srcIp) + " → " + String(dstIp);
String label = "IPv4/Other";

// Add detail based on transport protocol
if (protocol == 0x11 && payloadLen >= ihl + 8) {
  // UDP
  const uint8_t* udp = ip + ihl;
  uint16_t srcPort = (udp[0] << 8) | udp[1];
  uint16_t dstPort = (udp[2] << 8) | udp[3];

  if (dstPort == 53 || srcPort == 53)
    label = "IPv4/UDP/DNS";
  else if (dstPort == 5353 || srcPort == 5353)
    label = "IPv4/UDP/mDNS";
  else
    label = "IPv4/UDP";
}
else if (protocol == 0x06 && payloadLen >= ihl + 20) {
  label = "IPv4/TCP";
}

flowKey = String(srcIp) + " → " + String(dstIp) + " (" + label + ")";
stats.df.ipv4Flows[flowKey]++;
Serial.printf("🧭 IPv4 Flow: %s | +1 pkt, +%u bytes [%s]\n", 
              flowKey.c_str(), payloadLen, label.c_str());
stats.df.ipv4FlowBytes[flowKey] += payloadLen;
stats.df.ipv4FlowBytesSqSum[flowKey] += static_cast<uint64_t>(payloadLen) * payloadLen;
Serial.printf("📊 Total bytes so far for %s: %llu\n", 
              flowKey.c_str(), stats.df.ipv4FlowBytes[flowKey]);


    // ---------- UDP ----------
    if (protocol == 0x11 && payloadLen >= ihl + 8) {
      const uint8_t* udp = ip + ihl;
      uint16_t srcPort = (udp[0] << 8) | udp[1];
      uint16_t dstPort = (udp[2] << 8) | udp[3];
      stats.df.udpPorts.insert(srcPort);
      stats.df.udpPorts.insert(dstPort);
      Serial.printf("UDP: %u → %u\n", srcPort, dstPort);

      const uint8_t* dns = udp + 8;
      if (dstPort == 53 || srcPort == 53 || dstPort == 5353 || srcPort == 5353) {
        if (dstPort == 53 || srcPort == 53) {
          stats.df.etherTypeSummaryCounts["IPv4/UDP/DNS"]++;
        } else if (dstPort == 5353 || srcPort == 5353) {
          stats.df.etherTypeSummaryCounts["IPv4/UDP/mDNS"]++;
        } else{
          stats.df.etherTypeSummaryCounts["IPv4/UDP"]++;
        }
        const uint8_t* ptr = dns + 12;
        String hostname;
        while (*ptr && ptr < payload + payloadLen) {
          uint8_t len = *ptr++;
          for (uint8_t i = 0; i < len && ptr < payload + payloadLen; ++i)
            hostname += (char)(*ptr++);
          hostname += ".";
        }
        hostname.trim();
        if (hostname.length()) {
            stats.df.dnsHostnames.insert(hostname);  // (optional global set)
            stats.df.dnsHostnamesByFlow[flowKey].insert(hostname);
            Serial.printf("🔍 DNS Query: %s\n", hostname.c_str());
        }
      }
    }

    // ---------- TCP ----------
    else if (protocol == 0x06 && payloadLen >= ihl + 20) {
      const uint8_t* tcp = ip + ihl;
      uint16_t srcPort = (tcp[0] << 8) | tcp[1];
      uint16_t dstPort = (tcp[2] << 8) | tcp[3];
      uint8_t flags = tcp[13];
      stats.df.tcpPorts.insert(srcPort);
      stats.df.tcpPorts.insert(dstPort);

      Serial.printf("TCP: %u → %u | Flags:", srcPort, dstPort);
      if (flags & 0x02) Serial.print(" SYN");
      if (flags & 0x10) Serial.print(" ACK");
      if (flags & 0x01) Serial.print(" FIN");
      Serial.println();
      stats.df.etherTypeSummaryCounts["IPv4/TCP"]++;
    } else {
        stats.df.etherTypeSummaryCounts["IPv4/Other"]++;
    }

    extractAsciiPayloadFromDF(payload, payloadLen);
  }

  // ---------- IPv6 ----------
else if (etherType == 0x86DD && payloadLen >= 40) {
  Serial.println("🌐 IPv6 Packet");
  const uint8_t* ip6 = payload;
  uint8_t nextHeader = ip6[6];
  uint8_t hopLimit = ip6[7];

  //---- Optional MAC extraction
  if (isLikelyEui64(ip6)) {
    String recoveredMac = extractMacFromEUI64(ip6);
    Serial.println("🔍 EUI-64 detected. MAC reconstructed: " + recoveredMac);
    // stats.df.eui64Macs.insert(recoveredMac);  // optional
  }

  // Format full IPv6 addresses
  String srcPlain = formatIPv6(ip6 + 8, /*annotate=*/false);
  String dstPlain = formatIPv6(ip6 + 24, /*annotate=*/false);
  String label = "IPv6/Other";

  // ---------- ICMPv6 ----------
  if (nextHeader == 58 && payloadLen >= 44) {
    const uint8_t* icmp6 = ip6 + 40;
    uint8_t type = icmp6[0];

    switch (type) {
      case 133: label = "IPv6/ICMPv6/RS"; break;
      case 134: label = "IPv6/ICMPv6/RA"; break;
      case 135: label = "IPv6/ICMPv6/NS"; break;
      case 136: label = "IPv6/ICMPv6/NA"; break;
      default:  label = "IPv6/ICMPv6/Other"; break;
    }

    stats.df.icmpv6Types.insert(label);
  }

  // ---------- TCP ----------
  else if (nextHeader == 6 && payloadLen >= 60) {
    label = "IPv6/TCP";
  }

  // ---------- UDP ----------
  else if (nextHeader == 17 && payloadLen >= 48) {
    label = "IPv6/UDP";
  }

  // Track flow *after* determining the label
  stats.df.etherTypeSummaryCounts[label]++;
  String flowKey = srcPlain + " → " + dstPlain + " (" + label + ")";
  stats.df.ipv6Flows[flowKey]++;
  Serial.printf("🧭 IPv6 Flow: %s | +1 pkt, +%u bytes [%s]\n", 
              flowKey.c_str(), payloadLen, label.c_str());
  stats.df.ipv6FlowBytes[flowKey] += payloadLen;
  stats.df.ipv6FlowBytesSqSum[flowKey] += static_cast<uint64_t>(payloadLen) * payloadLen;
  Serial.printf("📊 Total bytes so far for %s: %llu\n", 
              flowKey.c_str(), stats.df.ipv6FlowBytes[flowKey]);


  extractAsciiPayloadFromDF(payload, payloadLen);
}

  // ---------- Raw / Vendor Multicast ----------
  else if (etherType < 0x0600) {
    Serial.printf("📎 Possibly Length: %d — Vendor tag or raw payload?\n", etherType);
    stats.df.etherTypeSummaryCounts["Raw/Vendor"]++;
    extractAsciiPayloadFromDF(payload, payloadLen);
  }
  //Serial.printf("🧾 EtherType Summary: %s → count: %u\n", 
  //            label.c_str(), stats.df.etherTypeSummaryCounts[label]);

  // ---------- Save ASCII from QoS frames ----------
  if (isQoS) {
    String ascii = extractAsciiPayloadFromDF(payload, payloadLen);
    if (ascii.length()) stats.asciiStrings.insert(ascii);
  }
}

//---Mgmt frame parsing---------------------
void parseMgmtFrame(const uint8_t* frame, uint16_t len, DeviceCapture& cap) {
  if (len < 24) return;  // sanity check

  uint8_t subtype = (frame[0] >> 4) & 0x0F;  // subtype is bits 4–7 of byte 0
  uint16_t offset;

switch (subtype) {
  case 0x00:  // Association Request
    if (len < 28) return;
    offset = 28;
    break;

  case 0x01:  // Association Response
    if (len < 30) return;
    offset = 30;
    break;

//  case 0x04:  // Probe Request
//    if (len < 24) return;
//    offset = 24;
//    break;
  case 0x04: {  // Probe Request
    // Start from base MAC header (24 bytes)
    offset = 24;
    // Scan forward for the first valid tag
    while (offset + 2 < len) {
      uint8_t tag = frame[offset];
      uint8_t len = frame[offset + 1];
      if ((tag <= 0x7F || tag == 0xDD) && (offset + 2 + len <= len)) {
        break;  // Found valid tag-length pair
      }
      offset++;
    }
    break;
  }

  case 0x05:  // Probe Response
  case 0x08:  // Beacon
    if (len < 36) return;
    offset = 36;
    break;

  default:
    return;  // unsupported subtype
}

const uint8_t* ieData = frame + offset;
uint16_t ieLen = len - offset;
//  const uint8_t* ieData = frame + 36;  // 24 header + 12 fixed mgmt
//  uint16_t ieLen = len - 36;

  // Parse all IEs including WPS
  cap.mgmtInfo = MgmtInfo();  // clears ssid, wps, asciiHints, etc.
  parseMgmtIEs(ieData, ieLen, cap);
}

void parseMgmtIEs(const uint8_t* data, uint16_t len, DeviceCapture& cap) {
  int offset = 0;

  while (offset + 2 <= len) {
    uint8_t id = data[offset];
    uint8_t tagLen = data[offset + 1];

    if (offset + 2 + tagLen > len) break;
    
    //Serial.printf("[DEBUG parseMgmtIEs] tagLen=%d, offset=%d, ieLen=%d\n", tagLen, offset, len);

    const uint8_t* tagData = data + offset + 2;
    //Serial.printf("[DEBUG parseMgmtIEs] tagLen=%d, offset=%d, ieLen=%d\n", tagLen, offset, ieLen);
    /* SSID extreaction not working here - Do it outside of parseMgmtIEs using extractSsid() which works
    // ✅ SSID parsing (copy of working extractSsid logic)
    if (id == 0 && tagLen <= 32) {
      if (tagLen == 0) {
        cap.mgmtInfo.ssid = "";
      } else {
        String ssid = "";
        for (int i = 0; i < tagLen; ++i) {
          char c = data[offset + 2 + i];
          //char c = tagData[i];
          if (c >= 32 && c <= 126) ssid += c;
        }
        Serial.println("📶 [SSID] Extracted (parseMgmtIEs 1): \"" + ssid + "\"");
        cap.mgmtInfo.ssid = ssid.length() ? ssid : "";
        //cap.mgmtInfo.ssid = ssid;
        if (ssid.length()) {
          Serial.println("📶 [SSID] Extracted (parseMgmtIEs 2): \"" + ssid + "\"");

          // Register in global MAC stats
          addSsidToStats(macStatsMap[cap.senderMac], ssid);

        }
      }
    }
    END SSID EXTRACTION BLOCK */

    // WPS IE
    //else if (id == 221 && tagLen >= 4 &&
    if (id == 221 && tagLen >= 4 &&
             tagData[0] == 0x00 && tagData[1] == 0x50 &&
             tagData[2] == 0xF2 && tagData[3] == 0x04) {
      cap.mgmtInfo.wps = parseWpsIE(tagData + 4, tagLen - 4);
    }
        // Country Code
    else if (id == 0x07 && tagLen >= 3) {
      String cc = "";
      for (int i = 0; i < 3; ++i) {
        char c = data[offset + 2 + i];
        if (c >= 32 && c <= 126) cc += c;  // Printable ASCII
      }
      if (cc.length() == 3) {
        cap.mgmtInfo.countryCode = cc;
        Serial.println("🌍 [Country Code] Detected: " + cc);
      }
    }


    // Other ASCII-looking IEs
    parseUnknownAsciiIe(id, tagData, tagLen, cap.mgmtInfo.asciiHints);

    offset += 2 + tagLen;
  }
}

/*
void parseMgmtIEs(const uint8_t* ieData, uint16_t ieLen, DeviceCapture& cap) {
  int pos = 0;
  bool foundSsid = false;

  while (pos + 2 <= ieLen) {
    uint8_t tagNumber = ieData[pos];
    uint8_t tagLength = ieData[pos + 1];

    if (pos + 2 + tagLength > ieLen) {
      // Don't proceed beyond bounds
      break;
    }

    const uint8_t* tagData = ieData + pos + 2;

    // SSID (tag 0)
    if (tagNumber == 0x00 && tagLength <= 32 && !foundSsid) {
      String ssid = "";
      for (int i = 0; i < tagLength; ++i) {
        ssid += (char)tagData[i];  // Accept even non-printable
      }

      if (tagLength > 0) {
        cap.mgmtInfo.ssid = ssid;
        Serial.println("📶 [SSID] Extracted: \"" + ssid + "\"");
        MacStats& stats = macStatsMap[cap.senderMac];
        addSsidToStats(stats, ssid);
        foundSsid = true;
      }

    }

    // WPS IE: tag 0xDD + OUI 00:50:F2 + type 0x04
    else if (tagNumber == 0xDD && tagLength >= 4 &&
             tagData[0] == 0x00 && tagData[1] == 0x50 &&
             tagData[2] == 0xF2 && tagData[3] == 0x04) {
      cap.mgmtInfo.wps = parseWpsIE(tagData + 4, tagLength - 4);
    }

    // ASCII-looking unknown tags
    parseUnknownAsciiIe(tagNumber, tagData, tagLength, cap.mgmtInfo.asciiHints);

    pos += 2 + tagLength;
  }
}
*/
/*
void parseMgmtIEs(const uint8_t* data, uint16_t len, DeviceCapture& cap) {
  int offset = 0;
  bool foundSsid = false;
  while (offset + 2 <= len) {
    uint8_t id = data[offset];
    uint8_t tagLen = data[offset + 1];
    if (offset + 2 + tagLen > len) break;

    const uint8_t* tagData = data + offset + 2;

    if (id == 0 && tagLen <= 32) {
      if(!foundSsid) {
      String ssid = "";
      for (int i = 0; i < tagLen; ++i) {
        char c = tagData[i];
        if (c >= 32 && c <= 126) ssid += c;
      }
      Serial.println("📶 [SSID] Extracted (1): \"" + ssid + "\"");
      // Only store the first non-empty SSID
      if (ssid.length()) {
        cap.mgmtInfo.ssid = ssid;
        Serial.println("📶 [SSID] Extracted (2): \"" + ssid + "\"");
        MacStats& stats = macStatsMap[cap.senderMac];
        addSsidToStats(stats, ssid);
        foundSsid = true;  // lock in first valid SSID 
      }
      }
    }
//    if (id == 0 && tagLen <= 32) {
//      String ssid = extractSsid(data + offset, len - offset);
//      if (ssid.length()) cap.mgmtInfo.ssid = ssid;
//      Serial.println("📶 [SSID] Extracted: \"" + ssid + "\"");
//    }

    else if (id == 221 && tagLen >= 4 &&
             tagData[0] == 0x00 && tagData[1] == 0x50 && tagData[2] == 0xF2 && tagData[3] == 0x04) {
      cap.mgmtInfo.wps = parseWpsIE(tagData + 4, tagLen - 4);
    }

    // Check unknowns
    parseUnknownAsciiIe(id, tagData, tagLen, cap.mgmtInfo.asciiHints);

    offset += 2 + tagLen;
  }
}
*/

wpsFingerprint parseWpsIE(const uint8_t* data, int len) {
  wpsFingerprint fp;
  int offset = 0;

  while (offset + 4 <= len) {
    uint16_t type = (data[offset] << 8) | data[offset + 1];
    uint16_t length = (data[offset + 2] << 8) | data[offset + 3];
    if (offset + 4 + length > len) break;

    const uint8_t* value = data + offset + 4;
    String strValue = "";

    for (int i = 0; i < length; i++) {
      char c = value[i];
      if (c >= 32 && c <= 126) strValue += c;
    }

    switch (type) {
      case 0x1011: fp.deviceName = strValue; break;
      case 0x1012: fp.modelName = strValue; break;
      case 0x1023: fp.modNumDetail = strValue; break;
      case 0x1024: fp.serialNumber = strValue; break;

      case 0x1044: // UUID-E
      case 0x1047: {
        if (length == 16) {
          char uuidStr[37];
          snprintf(uuidStr, sizeof(uuidStr),
            "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            value[0], value[1], value[2], value[3],
            value[4], value[5],
            value[6], value[7],
            value[8], value[9],
            value[10], value[11], value[12], value[13], value[14], value[15]);
          fp.uuid = String(uuidStr);
        } else if (length == 1 || length == 2) {
          fp.devicePasswordId = (length == 2) ? (value[0] << 8) | value[1] : value[0];
        }
        break;
      }

      case 0x1054:  // Primary Device Type
        if (length == 8) {
          char typeStr[25];
          snprintf(typeStr, sizeof(typeStr),
            "%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
            value[0], value[1], value[2], value[3],
            value[4], value[5], value[6], value[7]);
          fp.primaryDeviceType = String(typeStr);
        }
        break;

      case 0x103C:  // RF Band
        if (length == 1) {
          uint8_t band = value[0];
          fp.rfBand = (band == 1) ? "2.4GHz" :
                      (band == 2) ? "5GHz" :
                      (band == 3) ? "Dual" : "Unknown";
        }
        break;

      case 0x1009:  // Device Password ID
        if (length == 1 || length == 2) {
          fp.devicePasswordId = (length == 2) ? (value[0] << 8) | value[1] : value[0];
        }
        break;

      case 0x1008:  // Config Methods
        if (length == 2) {
          fp.configMethods = (value[0] << 8) | value[1];
        }
        break;

      case 0x1049:  // Vendor Extension
        if (length >= 3) {
          char ouiStr[9];
          snprintf(ouiStr, sizeof(ouiStr), "%02X:%02X:%02X", value[0], value[1], value[2]);
          String vendor = lookupVendor(value);
          fp.vendorExt = String(ouiStr);
          if (vendor != "Unknwn") fp.vendorExt += " (" + vendor + ")";
        }
        break;

      case 0x104A:  // Auth Info
        if (length > 0) {
          String hexStr;
          for (int i = 0; i < length; ++i) {
            if (i > 0) hexStr += ":";
            if (value[i] < 0x10) hexStr += "0";
            hexStr += String(value[i], HEX);
          }
          fp.authInfo = "104A=" + hexStr;
        }
        break;

      default:
        break;
    }

    offset += 4 + length;
  }

  // Build summary strings

  // 🔐 Fixed Identity Fingerprint
  String fxd = "";
  if (fp.uuid.length())              fxd += "uuid=" + fp.uuid + ";";
  if (fp.modelName.length())         fxd += "model=" + fp.modelName + ";";
  if (fp.modNumDetail.length())      fxd += "detail=" + fp.modNumDetail + ";";
  if (fp.serialNumber.length())      fxd += "serial=" + fp.serialNumber + ";";
  if (fp.deviceName.length())        fxd += "name=" + fp.deviceName + ";";
  if (fp.primaryDeviceType.length()) fxd += "type=" + fp.primaryDeviceType + ";";
  if (fp.vendorExt.length())         fxd += "vendor=" + fp.vendorExt + ";";

  // ⚙️ Variable Config Fingerprint
  String var = "";
  if (fp.authInfo.length())          var += fp.authInfo + ";";
  if (fp.rfBand.length())            var += "band=" + fp.rfBand + ";";
  if (fp.devicePasswordId != 0) {
    char pwBuf[5];
    sprintf(pwBuf, "%04X", fp.devicePasswordId);
    var += "pass=" + String(pwBuf) + ";";
  }
  if (fp.configMethods != 0) {
    char cfgBuf[5];
    sprintf(cfgBuf, "%04X", fp.configMethods);
    var += "config=" + String(cfgBuf) + ";";
  }

  fp.wpsSumFxd = fxd;
  fp.wpsSumVar = var;

  // Optional short summary
//  if (fp.deviceName.length() || fp.modelName.length()) {
//    fp.shortWpsFP = fp.deviceName;
//    if (fp.modelName.length()) fp.shortWpsFP += " (" + fp.modelName + ")";
//  }

Serial.println(F("📡 [WPS DEBUG] WPS Information Element Parsed:"));

if (fp.uuid.length())              Serial.println("  UUID             : " + fp.uuid);
if (fp.deviceName.length())        Serial.println("  Device Name      : " + fp.deviceName);
if (fp.modelName.length())         Serial.println("  Model Name       : " + fp.modelName);
if (fp.modNumDetail.length())      Serial.println("  Model Detail     : " + fp.modNumDetail);
if (fp.serialNumber.length())      Serial.println("  Serial Number    : " + fp.serialNumber);
if (fp.primaryDeviceType.length()) Serial.println("  Device Type      : " + fp.primaryDeviceType);
if (fp.vendorExt.length())         Serial.println("  Vendor Extension : " + fp.vendorExt);
if (fp.rfBand.length())            Serial.println("  RF Band          : " + fp.rfBand);
if (fp.authInfo.length())          Serial.println("  Auth Info        : " + fp.authInfo);

if (fp.devicePasswordId != 0)
  Serial.printf("  Device Password  : 0x%04X\n", fp.devicePasswordId);

if (fp.configMethods != 0)
  Serial.printf("  Config Methods   : 0x%04X\n", fp.configMethods);

if (fp.wpsSumFxd.length())
  Serial.println("  🧬 WPS Fingerprint Fxd : " + fp.wpsSumFxd);

if (fp.wpsSumVar.length())
  Serial.println("  ⚙️  WPS Fingerprint Var : " + fp.wpsSumVar);


  return fp;
}

//====================================================
// Print functions
//====================================================
void debugPrintGlobalInfo(const DeviceCapture& cap) {
  Serial.println(F("🔍 Global Frame Metadata:"));
  Serial.printf("  • Type/Subtype   : %u / 0x%02X\n", cap.frameType, cap.subtype);
  Serial.printf("  • Direction      : %s\n", cap.directionText.c_str());
  Serial.printf("  • Length         : %u bytes\n", cap.length);

  Serial.printf("  • Sender MAC     : %s\n", cap.senderMac.c_str());
  Serial.printf("  • Dest MAC       : %s\n", cap.receiverMac.c_str());
  Serial.printf("  • BSSID MAC      : %s\n", cap.bssidMac.c_str());

  Serial.printf("  • Sender Vendor  : %s\n", cap.srcVendor.c_str());
  Serial.printf("  • Dest Purp/Vend : %s\n", cap.dstMacPurpose.c_str());
  Serial.printf("  • BSSID Vendor   : %s\n", cap.bssidVendor.c_str());

  Serial.printf("  • RSSI           : %d dBm\n", cap.rssi);
  Serial.printf("  • Time Seen      : %lu ms since boot\n", cap.timeSeen);
  Serial.printf("  • Channels Seen  : %s\n", formatChannelList(cap.channelMask).c_str());
}

void printGlobalMacStats() {
  Serial.println(F("\n📊 Device Summary After Scan"));
  Serial.println(F("MAC(ven)                     Combos         Cty   Pkts   LenAvg/Std   Chs    RSSImin/max  First/Last (s)"));
  Serial.println(F("---------------------------------------------------------------------------------------------------------"));
  int ephemeralProberCount = 0;
  for (const auto& kv : macStatsMap) {
    const String& mac = kv.first;
    const MacStats& stats = kv.second;

    // Only show if some data frames were captured
    if (stats.packetCount == 0) continue;

    // MAC vendor (sender)
    String macShort = mac;//mac.substring(0, 8);  // first 3 bytes
    String vendor = stats.vendor;

    // Combo list
    String comboStr;
    for (const auto& combo : stats.frameCombos) {
      const FrameStatKey& k = combo.first;
      uint32_t count = combo.second;
      char abbrev[16];
      snprintf(abbrev, sizeof(abbrev), "%u%02X%u%u ", k.type, k.subtype, k.direction, count);
      comboStr += abbrev;
    }

    // Time seen
    uint32_t first = stats.firstSeen / 1000;
    uint32_t last  = stats.lastSeen  / 1000;

    // Set aside ephemeral probers to declutter table — unless they revealed an SSID
    comboStr.trim();
    if (vendor == "Unknwn" &&
        stats.packetCount <= 3 &&
        (comboStr == "00411" || comboStr == "00412") &&
        (last - first <= 2) &&
        stats.rxMacSummaries.count("FF:FF:FF(BC)") &&
        stats.bssidSummaries.count("FF:FF:FF(Unknwn)") &&
        stats.mgmt.seenSsids.empty()) {  // ← allow if we saw an SSID
      ephemeralProberCount++;
      continue;  // ✅ Don't print this device in the table
    }

    // Length mean/std dev
    float meanLen = stats.packetCount > 0 ? (float)stats.lenSum / stats.packetCount : 0;
    float stdDevLen = 0;
    if (stats.packetCount > 1) {
      float variance = ((float)stats.lenSqSum / stats.packetCount) - (meanLen * meanLen);
      stdDevLen = sqrtf(variance);
    }

    // RSSI
    int8_t rssiMin = stats.rssiMin;
    int8_t rssiMax = stats.rssiMax;

    const char* cc = stats.mgmt.countryCode.length() ? stats.mgmt.countryCode.c_str() : "-";

    Serial.printf("%-10s %-20s   %s   %5u   %5.1f/%-5.1f   %s  %3d/%-3d     %5lus/%5lus\n",
              (macShort + "(" + vendor + ")").c_str(),
              comboStr.c_str(),
              cc,  // ✅ now safe, format matches %s
              stats.packetCount,
              meanLen, stdDevLen,
              formatChannelList(stats.channelsSeen).c_str(),
              rssiMin, rssiMax,
              first, last);

    if (!stats.rxMacSummaries.empty()) {
      Serial.print("    → Rx MACs: ");
      int count = 0;
      for (const String& entry : stats.rxMacSummaries) {
        if (count++ > 0) Serial.print("|");
        Serial.print(entry);
      }
      Serial.println();
    }

    if (!stats.bssidSummaries.empty()) {
      Serial.print(" → BSSID MACs: ");
      int count = 0;
      for (const String& entry : stats.bssidSummaries) {
        if (count++ > 0) Serial.print("|");
        Serial.print(entry);
      }
      Serial.println();
    }

    if (!stats.mgmt.seenSsids.empty()){
      Serial.print(" → SSIDs seen: ");
      int count = 0;
      for (const String& entry : stats.mgmt.seenSsids) {
        if (count++ > 0) Serial.print("|");
        Serial.print(entry);
      }
      Serial.println();
    }

    if (stats.mgmt.asciiHints.length())
      Serial.println("    → ASCII: " + stats.mgmt.asciiHints);

    if (stats.mgmt.wps.wpsSumFxd.length())
      Serial.println("    → WPS Fxd: " + stats.mgmt.wps.wpsSumFxd);

    // QoS Uplink
    if (stats.df.qosUpCount > 0) {
      float meanTidUp = (float)stats.df.tidUpSum / stats.df.qosUpCount;
      float stdTidUp = sqrt((float)stats.df.tidUpSqSum / stats.df.qosUpCount - meanTidUp * meanTidUp);

      float meanLenUp = (float)stats.df.qosLenUpSum / stats.df.qosUpCount;
      float stdLenUp = sqrt((float)stats.df.qosLenUpSqSum / stats.df.qosUpCount - meanLenUp * meanLenUp);

      float amsduRateUp = (float)stats.df.amsduUpSum / stats.df.qosUpCount;
      float eospRateUp = (float)stats.df.eospUpSum / stats.df.qosUpCount;
      float encRateUp  = (float)stats.df.encryptedUpCount / stats.df.qosUpCount;

      Serial.printf("    ↑ Up QoS:   pkts=%3u  TID=%.1f/%.1f  Len=%.1f/%.1f  A-MSDU=%.2f  EOSP=%.2f  ENC=%.2f\n",
      stats.df.qosUpCount, meanTidUp, stdTidUp, meanLenUp, stdLenUp,
      amsduRateUp, eospRateUp, encRateUp);
    }

    // QoS Downlink
    if (stats.df.qosDownCount > 0) {
      float meanTidDown = (float)stats.df.tidDownSum / stats.df.qosDownCount;
      float stdTidDown = sqrt((float)stats.df.tidDownSqSum / stats.df.qosDownCount - meanTidDown * meanTidDown);

      float meanLenDown = (float)stats.df.qosLenDownSum / stats.df.qosDownCount;
      float stdLenDown = sqrt((float)stats.df.qosLenDownSqSum / stats.df.qosDownCount - meanLenDown * meanLenDown);

      float amsduRateDown = (float)stats.df.amsduDownSum / stats.df.qosDownCount;
      float eospRateDown  = (float)stats.df.eospDownSum / stats.df.qosDownCount;
      float encRateDown   = (float)stats.df.encryptedDownCount / stats.df.qosDownCount;

      Serial.printf("    ↓ Down QoS: pkts=%3u  TID=%.1f/%.1f  Len=%.1f/%.1f  A-MSDU=%.2f  EOSP=%.2f  ENC=%.2f\n",
      stats.df.qosDownCount, meanTidDown, stdTidDown, meanLenDown, stdLenDown,
      amsduRateDown, eospRateDown, encRateDown);
    }

    if (!stats.df.etherTypeSummaryCounts.empty()) {
      Serial.print("    🔗 EtherTypes: ");

      // Convert map to vector for sorting
      std::vector<std::pair<String, uint32_t>> sorted(stats.df.etherTypeSummaryCounts.begin(), stats.df.etherTypeSummaryCounts.end());
      std::sort(sorted.begin(), sorted.end(),
          [](const std::pair<String, uint32_t>& a, const std::pair<String, uint32_t>& b) {
            return a.second < b.second;
          });
      //std::sort(sorted.begin(), sorted.end(), [](auto& a, auto& b) {
      //  return b.second < a.second;  // descending order
      //});

      int total = 0;
      for (auto& pair : sorted) total += pair.second;

      int shown = 0;
      for (auto& pair : sorted) {
        if (shown < 3 || pair.second > 1) {  // top 3 or repeated types
          Serial.printf("%s(%u)  ", pair.first.c_str(), pair.second);
          shown++;
        }
      }

      if (shown < (int)sorted.size()) {
        int otherCount = 0;
        for (size_t i = shown; i < sorted.size(); ++i) {
          otherCount += sorted[i].second;
        }
        Serial.printf("Other(%d)", otherCount);
      }

      printFlowSummary(
        stats.df.ipv4Flows,
        stats.df.ipv4FlowBytes,
        stats.df.ipv4FlowBytesSqSum,
        "IPv4 Flows",
        7 //maxToShow
      );

      printFlowSummary(
        stats.df.ipv6Flows,
        stats.df.ipv6FlowBytes,
        stats.df.ipv6FlowBytesSqSum,
        "IPv6 Flows",
        7 // maxToShow
      );

      Serial.println();
    }

  } // End for loop

  Serial.println("-----------------------------------------------------------------------------------------------------\n");
  if (ephemeralProberCount > 0) {
  Serial.printf("📉 %d ephemeral probers (1–2 probe requests, short lifespan, unknown vendor, no/only wildcard probed SSIDs detected)\n", ephemeralProberCount);
}

}


/*
void debugPrintMacStats(const String& macKey) {
  if (macStatsMap.find(macKey) == macStatsMap.end()) {
    Serial.printf("[DEBUG] No stats found for MAC: %s\n", macKey.c_str());
    return;
  }

  const MacStats& s = macStatsMap[macKey];
  Serial.printf("\n[DEBUG] Stats for MAC: %s\n", macKey.c_str());

  // Basic
  Serial.printf("  Total Data Frames: %lu\n", s.packetCount);
  Serial.printf("  Len Sum: %lu | Len^2 Sum: %lu\n", s.lenSum, s.lenSqSum);

  // QoS Up
  Serial.printf("  🔼 Cl→AP QoS Frames: %lu | Encrypted: %lu\n", s.qosUpCount, s.encryptedUpCount);
  Serial.printf("    TID Sum: %lu | TID^2 Sum: %lu\n", s.tidUpSum, s.tidUpSqSum);
  Serial.printf("    A-MSDU Sum: %lu | EOSP Sum: %lu\n", s.amsduUpSum, s.eospUpSum);
  Serial.printf("    QoS Len Sum: %lu | Len^2 Sum: %lu\n", s.qosLenUpSum, s.qosLenUpSqSum);

  // QoS Down
  Serial.printf("  🔽 AP→Cl QoS Frames: %lu | Encrypted: %lu\n", s.qosDownCount, s.encryptedDownCount);
  Serial.printf("    TID Sum: %lu | TID^2 Sum: %lu\n", s.tidDownSum, s.tidDownSqSum);
  Serial.printf("    A-MSDU Sum: %lu | EOSP Sum: %lu\n", s.amsduDownSum, s.eospDownSum);
  Serial.printf("    QoS Len Sum: %lu | Len^2 Sum: %lu\n", s.qosLenDownSum, s.qosLenDownSqSum);

  // DNS/mDNS
  Serial.printf("  DNS: %lu | mDNS: %lu\n", s.dnsCount, s.mdnsCount);

  // First Encrypted Frame
  if (s.seenEncrypted) {
    Serial.printf("  First Encrypted Dir: %s | Subtype: 0x%02X | Len: %u | EtherType: 0x%04X\n",
                  s.firstEncryptedDir.c_str(),
                  s.firstEncryptedSubtype,
                  s.firstEncryptedLen,
                  s.firstEncryptedEtherType);
    if (s.firstEncryptedAscii.length())
      Serial.printf("  First Encrypted ASCII: \"%s\"\n", s.firstEncryptedAscii.c_str());
  }

  // EtherTypes
  if (!s.etherTypes.empty()) {
    Serial.print("  EtherTypes: ");
    for (uint16_t e : s.etherTypes)
      Serial.printf("0x%04X ", e);
    Serial.println();
  }

  // ASCII
  if (!s.asciiStrings.empty()) {
    Serial.print("  ASCII Payloads: ");
    for (const String& ascii : s.asciiStrings)
      Serial.printf("|%s", ascii.c_str());
    Serial.println();
  }

  // Dest MACs
  if (!s.destMacs.empty()) {
    Serial.print("  Dest MACs Seen: ");
    for (const String& d : s.destMacs)
      Serial.printf("%s ", d.c_str());
    Serial.println();
  }
}
*/

void printGlobalFrameStats() {
  Serial.println(F("\n📊 [GLOBAL FRAME STATS]"));
  for (const auto& kv : globalFrameStats) {
    const FrameStatKey& key = kv.first;
    int count = kv.second;

    // Convert direction to label using your existing helper
    const char* dirLabel = directionToStr((FrameDirection)key.direction);

    // Format frame type/subtype (e.g., "00/04")
    char combo[10];
    snprintf(combo, sizeof(combo), "%02X/%02X", key.type, key.subtype);

    Serial.printf("  • %s  %s  → %d\n", combo, dirLabel, count);
  }
}

/*
void printGlobalFrameStats() {
  Serial.println("\n[GLOBAL FRAME STATS]");
  for (const auto& kv : globalFrameStats) {
    const FrameStatKey& key = kv.first;
    int count = kv.second;

    // Format direction
    const char* dirSymbol = " ";
    switch (key.direction) {
      case 1: dirSymbol = "[→]"; break;
      case 2: dirSymbol = "[←]"; break;
      case 3: dirSymbol = "[↔︎]"; break;
      default: dirSymbol = "[ ]"; break;
    }

    char combo[10];
    snprintf(combo, sizeof(combo), "%02X/%02X", key.type, key.subtype);
    Serial.printf("  • %s %s → %d\n", combo, dirSymbol, count);
  }
}
*/
