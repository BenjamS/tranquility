#include "parsers.h"
#include "esp_wifi.h"
#include <stdio.h>

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

// === YOUR FULL parseGlobalItems AND parseDataFrame GO HERE ===
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

void debugPrintGlobalDebugInfo(const DeviceCapture& cap) {
  Serial.println(F("🔍 Global Frame Metadata:"));
  Serial.printf("  • Type/Subtype   : %u / 0x%02X\n", cap.frameType, cap.subtype);
  Serial.printf("  • Direction      : %s\n", cap.direction.c_str());
  Serial.printf("  • Length         : %u bytes\n", cap.length);

  Serial.printf("  • Sender MAC     : %s\n", cap.senderMac.c_str());
  Serial.printf("  • Dest MAC       : %s\n", cap.receiverMac.c_str());
  Serial.printf("  • BSSID MAC      : %s\n", cap.bssidMac.c_str());

  Serial.printf("  • Sender Vendor  : %s\n", cap.srcVendor.c_str());
  Serial.printf("  • Dest Purp/Vend : %s\n", cap.dstMacPurpose.c_str());
  Serial.printf("  • BSSID Vendor   : %s\n", cap.bssidVendor.c_str());

  Serial.printf("  • RSSI Min/Max   : %d dBm\n", cap.rssi);
  Serial.printf("  • Time seen      : %s\n", cap.timeSeen);
  Serial.printf("  • Channels Seen  : %s\n", formatChannelList(cap.channelMask).c_str());
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


void parseDataFrame(const uint8_t* frame, uint16_t len, const DeviceCapture& cap) {
  if (cap.frameType != 2) return;

  const String& macKey = cap.senderMac;
  MacStats& stats = macStatsMap[macKey];

  String comboKey = String(cap.frameType, HEX) + String(cap.subtype, HEX) + " " + cap.directionText;
  stats.otherCombos[comboKey]++;
  stats.destMacs.insert(cap.receiverMac);
  stats.totalDataFrames++;
  stats.lenSum += cap.length;
  stats.lenSqSum += cap.length * cap.length;

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



void updateMacStatsFromGlobalItems(const DeviceCapture& cap, int rssi, uint8_t channel) {
  MacStats& stats = macStatsMap[cap.senderMac];

  // First seen
  if (stats.packetCount == 0) {
    stats.firstSeen = cap.timeSeen;
  }

  // Last seen always updated
  stats.lastSeen = cap.timeSeen;

  // Packet count
  stats.packetCount++;

  // RSSI
  if (cap.rssi < stats.rssiMin) stats.rssiMin = cap.rssi;
  if (cap.rssi > stats.rssiMax) stats.rssiMax = cap.rssi;

  // Channel tracking
  if (channel >= 1 && channel <= 13) {
    stats.channelMask |= (1 << (cap.channel - 1));
  }

  // Frame combo key (e.g. "020C(Cl→AP)")
  char comboKey[32];
  snprintf(comboKey, sizeof(comboKey), "%01X%02X(%s)", cap.frameType, cap.subtype, cap.direction.c_str());
  stats.frameCombos[String(comboKey)]++;
}

void debugPrintMacStats(const String& macKey) {
  if (macStatsMap.find(macKey) == macStatsMap.end()) {
    Serial.printf("[DEBUG] No stats found for MAC: %s\n", macKey.c_str());
    return;
  }

  const MacStats& s = macStatsMap[macKey];
  Serial.printf("\n[DEBUG] Stats for MAC: %s\n", macKey.c_str());

  // Basic
  Serial.printf("  Total Data Frames: %lu\n", s.totalDataFrames);
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

