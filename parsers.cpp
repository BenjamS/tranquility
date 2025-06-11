#include "parsers.h"
#include "esp_wifi.h"
#include <stdio.h>
#include <SD.h>
#include "nvs_flash.h"

#define SD_CS 5  // or your CS pin

std::map<String, MacStats> macStatsMap;
std::map<FrameStatKey, int> globalFrameStats;

const char* directionToStr(FrameDirection dir) {
  switch (dir) {
    case DIR_CLIENT_TO_AP: return "Cl→AP";
    case DIR_AP_TO_CLIENT: return "AP→Cl";
    case DIR_STA_STA:      return "STA↔STA";
    case DIR_WDS:          return "WDS";
    default:               return "Unknown";
  }
}

//=============================================================
// Helpers
//=============================================================
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

String hexDump(const uint8_t* data, int len) {
  char buf[4];  // enough for 2-digit hex + null + separator
  String out = "";
  for (int i = 0; i < len; ++i) {
    if (i > 0) out += ":";
    sprintf(buf, "%02X", data[i]);
    out += buf;
  }
  return out;
}

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
      case 0x32: tagName = "Extended Supported Rates"; break;
      case 0x30: tagName = "RSN"; break;
      case 0x2A: tagName = "Power Capability"; break;
      case 0x2B: tagName = "Supported Channels"; break;
      case 0x46: tagName = "QoS Capability"; break;
      case 0x36: tagName = "HT Capabilities"; break;
      case 0x3D: tagName = "HT Information"; break;
      case 0x2D: tagName = "HT Capabilities"; break;
      case 0x7F: tagName = "Extended Capabilities"; break;
      case 0xDD: tagName = "Vendor Specific"; break;
      case 0x4A: tagName = "Neighbor Report"; break;
      default:   tagName = "Unknown"; break;
    }

    Serial.printf("  Tag: 0x%02X (%3d) %-25s Len: %2d → ", tagNumber, tagNumber, tagName.c_str(), tagLength);

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
//---Mgmt frame parsing---------------------

void parseDataFrame(const uint8_t* frame, uint16_t len, const DeviceCapture& cap) {
  if (cap.frameType != 2) return;

  const String& macKey = cap.senderMac;
  MacStats& stats = macStatsMap[macKey];

  uint8_t macHeaderLen = 24;
  if (cap.directionCode == DIR_WDS) macHeaderLen += 6;
  bool isQoS = (cap.subtype == 0x0C || cap.subtype == 0x0D);
  if (isQoS) macHeaderLen += 2;

  if (len < macHeaderLen) return;

  if (isQoS) {
    const uint8_t* qosCtrl = frame + macHeaderLen - 2;
    uint8_t qos1 = qosCtrl[0];
    uint8_t tid = qos1 & 0x0F;
    bool eosp = qos1 & 0x10;
    bool amsdu = qos1 & 0x20;

    if (cap.directionCode == DIR_CLIENT_TO_AP) {
      stats.qosUpCount++;
      stats.tidUpSum += tid;
      stats.tidUpSqSum += tid * tid;
      stats.amsduUpSum += amsdu;
      stats.eospUpSum += eosp;
      stats.qosLenUpSum += cap.length;
      stats.qosLenUpSqSum += cap.length * cap.length;
      if (cap.isEncrypted) stats.encryptedUpCount++;
    } else if (cap.directionCode == DIR_AP_TO_CLIENT) {
      stats.qosDownCount++;
      stats.tidDownSum += tid;
      stats.tidDownSqSum += tid * tid;
      stats.amsduDownSum += amsdu;
      stats.eospDownSum += eosp;
      stats.qosLenDownSum += cap.length;
      stats.qosLenDownSqSum += cap.length * cap.length;
      if (cap.isEncrypted) stats.encryptedDownCount++;
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
  const uint8_t* payload = llc + 8;
  uint16_t payloadLen = len - (macHeaderLen + 8);

  stats.etherTypes.insert(etherType);
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
    stats.ipv4Addrs.insert(String(srcIp));
    stats.ipv4Addrs.insert(String(dstIp));
    Serial.printf("IPv4: %s → %s | Proto: 0x%02X\n", srcIp, dstIp, protocol);

    // ---------- UDP ----------
    if (protocol == 0x11 && payloadLen >= ihl + 8) {
      const uint8_t* udp = ip + ihl;
      uint16_t srcPort = (udp[0] << 8) | udp[1];
      uint16_t dstPort = (udp[2] << 8) | udp[3];
      stats.udpPorts.insert(srcPort);
      stats.udpPorts.insert(dstPort);
      Serial.printf("UDP: %u → %u\n", srcPort, dstPort);

      const uint8_t* dns = udp + 8;
      if (dstPort == 53 || srcPort == 53 || dstPort == 5353 || srcPort == 5353) {
        if (dstPort == 53 || srcPort == 53) stats.dnsCount++;
        else stats.mdnsCount++;

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
          Serial.printf("🔍 DNS Query: %s\n", hostname.c_str());
          stats.dnsHostnames.insert(hostname);
        }
      }
    }

    // ---------- TCP ----------
    else if (protocol == 0x06 && payloadLen >= ihl + 20) {
      const uint8_t* tcp = ip + ihl;
      uint16_t srcPort = (tcp[0] << 8) | tcp[1];
      uint16_t dstPort = (tcp[2] << 8) | tcp[3];
      uint8_t flags = tcp[13];
      stats.tcpPorts.insert(srcPort);
      stats.tcpPorts.insert(dstPort);

      Serial.printf("TCP: %u → %u | Flags:", srcPort, dstPort);
      if (flags & 0x02) Serial.print(" SYN");
      if (flags & 0x10) Serial.print(" ACK");
      if (flags & 0x01) Serial.print(" FIN");
      Serial.println();
    }

    extractAsciiPayloadFromDF(payload, payloadLen);
  }

  // ---------- IPv6 ----------
  else if (etherType == 0x86DD && payloadLen >= 40) {
    Serial.println("🌐 IPv6 Packet");
    const uint8_t* ip6 = payload;
    uint8_t nextHeader = ip6[6];
    uint8_t hopLimit = ip6[7];

    char srcIp[8], dstIp[8];
    snprintf(srcIp, sizeof(srcIp), "%02X:%02X", ip6[8], ip6[9]);
    snprintf(dstIp, sizeof(dstIp), "%02X:%02X", ip6[24], ip6[25]);

    stats.ipv6Addrs.insert(String(srcIp));
    stats.ipv6Addrs.insert(String(dstIp));

    Serial.printf("IPv6: %s → %s | NH: 0x%02X | HL: %d\n", srcIp, dstIp, nextHeader, hopLimit);

    if (nextHeader == 58 && payloadLen >= 40 + 4) {
      const uint8_t* icmp6 = ip6 + 40;
      uint8_t type = icmp6[0];
      String label;

      switch (type) {
        case 133: label = "Router Solicitation"; break;
        case 134: label = "Router Advertisement"; break;
        case 135: label = "Neighbor Solicitation"; break;
        case 136: label = "Neighbor Advertisement"; break;
        default: label = "Other ICMPv6"; break;
      }

      Serial.printf("📢 ICMPv6 Type: %d — %s\n", type, label.c_str());
      stats.icmpv6Types.insert(label);
    }

    extractAsciiPayloadFromDF(payload, payloadLen);
  }

  // ---------- Raw / Vendor Multicast ----------
  else if (etherType < 0x0600) {
    Serial.printf("📎 Possibly Length: %d — Vendor tag or raw payload?\n", etherType);
    extractAsciiPayloadFromDF(payload, payloadLen);
  }

  // ---------- Save ASCII from QoS frames ----------
  if (isQoS) {
    String ascii = extractAsciiPayloadFromDF(payload, payloadLen);
    if (ascii.length()) stats.asciiStrings.insert(ascii);
  }
}
//---Mgmt frame parsing---------------------
void parseMgmtFrame(const uint8_t* frame, uint16_t len, DeviceCapture& cap) {
  if (len < 36) return;  // sanity check (24 + 12)
  const uint8_t* ieData = frame + 36;  // 24 header + 12 fixed mgmt
  uint16_t ieLen = len - 36;

  // Parse all IEs including WPS
  parseMgmtIEs(ieData, ieLen, cap);
}

void parseMgmtIEs(const uint8_t* data, uint16_t len, DeviceCapture& cap) {
  int offset = 0;
  while (offset + 2 <= len) {
    uint8_t id = data[offset];
    uint8_t tagLen = data[offset + 1];
    if (offset + 2 + tagLen > len) break;

    const uint8_t* tagData = data + offset + 2;

    if (id == 0 && tagLen <= 32) {
      String ssid = "";
      for (int i = 0; i < tagLen; ++i) {
        char c = tagData[i];
        if (c >= 32 && c <= 126) ssid += c;
      }
      if (ssid.length()) {
        cap.mgmtInfo.ssid = ssid;
        Serial.println("📶 [SSID] Extracted: \"" + ssid + "\"");
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
  Serial.println(F("MAC(ven)                     Combos            Pkts   LenAvg/Std   Chs    RSSImin/max  First/Last (s)"));
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

    // Set aside ephemeral probers to declutter table
    comboStr.trim();
    if (vendor == "Unknwn" &&
      stats.packetCount <= 3 &&
      (comboStr == "00411" || comboStr == "00412") &&
      (last - first <= 2) &&
      stats.rxMacSummaries.count("FF:FF:FF(BC)") &&
      stats.bssidSummaries.count("FF:FF:FF(Unknwn)")) {
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

    // Print row
    Serial.printf("%-10s %-20s   %3u  %5.1f/%-5.1f   %s  %3d/%-3d     %5lus/%5lus\n",
                  (macShort + "(" + vendor + ")").c_str(),
                  //rxSummaryStr.c_str(),
                  //bssidSummaryStr.c_str(),
                  comboStr.c_str(),
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

if (stats.mgmt.ssid.length())
  Serial.println("    → SSID: " + stats.mgmt.ssid);

if (stats.mgmt.asciiHints.length())
  Serial.println("    → ASCII: " + stats.mgmt.asciiHints);

if (stats.mgmt.wps.wpsSumFxd.length())
  Serial.println("    → WPS Fxd: " + stats.mgmt.wps.wpsSumFxd);

  } // End for loop

  Serial.println("-----------------------------------------------------------------------------------------------------\n");
  if (ephemeralProberCount > 0) {
  Serial.printf("📉 %d ephemeral probers (1–2 probe requests, short lifespan, unknown vendor)\n", ephemeralProberCount);
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