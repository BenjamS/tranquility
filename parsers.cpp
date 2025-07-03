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

const size_t MAX_SSID_TRACK = 10;

//=============================================================
// Helpers
//=============================================================
void parseSsdpPayload(const uint8_t* payload, size_t len, const char* srcIp, const char* dstIp,
                      const char* flowKey, datFrameInfo& df) {
  const char* data = (const char*)payload;
  const char* end = data + len;

  // Quick check: SSDP should look like HTTP/1.1 NOTIFY or M-SEARCH
  if (len < 10 || (!strstr(data, "HTTP") && !strstr(data, "NOTIFY") && !strstr(data, "M-SEARCH"))) return;

  String server, location, st, usn;
  const char* line = data;

  while (line < end) {
    const char* next = strchr(line, '\n');
    if (!next) break;

    String l = String(line, next - line);
    l.trim();

    String lUpper = l;
    lUpper.toUpperCase();

    if (lUpper.startsWith("SERVER:")) {
      String temp = l.substring(7);
      temp.trim();
      server = temp;
    }
    else if (lUpper.startsWith("LOCATION:")) {
      String temp = l.substring(9);
      temp.trim();
      location = temp;
    }
    else if (lUpper.startsWith("ST:")) {
      String temp = l.substring(3);
      temp.trim();
      st = temp;
    }
    else if (lUpper.startsWith("NT:")) {  // NT is sometimes used in NOTIFY
      String temp = l.substring(3);
      temp.trim();
      if (st.length() == 0) st = temp;
    }
    else if (lUpper.startsWith("USN:")) {
      String temp = l.substring(4);
      temp.trim();
      usn = temp;
    }

    line = next + 1;
  }

  if (usn.length() == 0 && st.length() == 0) return;

  // Deduplicate
  String key = usn + "|" + location;
  if (df.seenSsdpKeys.count(key)) return;
  df.seenSsdpKeys.insert(key);

  // 🔍 Heuristic device naming
  String deviceName;
  String stLower = st;
  stLower.toLowerCase();

  if (stLower.indexOf("roku") >= 0) deviceName = "Roku Device";
  else if (stLower.indexOf("sonos") >= 0) deviceName = "Sonos Speaker";
  else if (stLower.indexOf("mediarenderer") >= 0) deviceName = "Media Renderer";
  else if (stLower.indexOf("printer") >= 0) deviceName = "Network Printer";
  else if (server.indexOf("LG") >= 0) deviceName = "LG Smart Device";
  else if (server.indexOf("Linux") >= 0) deviceName = "Generic Linux UPnP";
  else if (st.length()) deviceName = st;
  else deviceName = usn;

  // 📦 Store result
  SsdpDevice dev;
  dev.ip = srcIp;
  dev.deviceName = deviceName;
  dev.server = server;
  dev.location = location;
  dev.st = st;
  dev.usn = usn;

  df.ssdpDevices.insert(dev);

  // Optional Debug Output
  Serial.printf("📣 SSDP Detected: %-20s | USN: %-30s | Location: %s\n",
                deviceName.c_str(), usn.c_str(), location.c_str());
}

/*
void parseSsdpPayload(const uint8_t* payload, size_t len, const char* srcIp, const char* dstIp,
                      const char* flowKey, datFrameInfo& df) {
  const char* data = (const char*)payload;
  const char* end = data + len;

  // Defensive check: look for something that begins like HTTP
  if (len < 10 || !strstr(data, "HTTP")) return;

  String server, location, st, usn;
  const char* line = data;

  while (line < end) {
    const char* next = strchr(line, '\n');
    if (!next) break;

    String l = String(line, next - line);
    l.trim();

    if (l.startsWith("SERVER:")) {
      String temp = l.substring(7);
      temp.trim();
      server = temp;
    }
    else if (l.startsWith("LOCATION:")) {
      String temp = l.substring(9);
      temp.trim();
      location = temp;
    }
    else if (l.startsWith("ST:")) {
      String temp = l.substring(3);
      temp.trim();
      server = temp;
    }
    else if (l.startsWith("UN:")) {
      String temp = l.substring(4);
      temp.trim();
      location = temp;
    }

//    if (l.startsWith("SERVER:"))     server   = l.substring(7).trim();
//    else if (l.startsWith("LOCATION:")) location = l.substring(9).trim();
//    else if (l.startsWith("ST:"))     st      = l.substring(3).trim();
//    else if (l.startsWith("USN:"))    usn     = l.substring(4).trim();

    line = next + 1;
  }

  if (usn.length() == 0 && st.length() == 0) return; // not a valid SSDP ad

  String key = usn + "|" + location;
  if (df.seenSsdpKeys.count(key)) return;  // deduplicate
  df.seenSsdpKeys.insert(key);

  // Device name logic (prefer friendly info)
  String deviceName;
  if (st.indexOf("roku") >= 0)         deviceName = "Roku Device";
  else if (st.indexOf("Sonos") >= 0)   deviceName = "Sonos Speaker";
  else if (st.length() > 0)            deviceName = st;
  else                                 deviceName = usn;

  SsdpDevice dev;
  dev.ip = srcIp;
  dev.deviceName = deviceName;
  dev.server = server;
  dev.location = location;
  dev.st = st;
  dev.usn = usn;

  df.ssdpDevices.insert(dev);
}
*/

Dhcpv6Info parseDhcpv6(const uint8_t* udpPayload, size_t udpLen, const uint8_t* end) {
  Dhcpv6Info info;
  info.msgType = "UNKNOWN";
  info.hostname = "-";
  info.mac = "-";
  info.timestamp = "-";
  info.vendor = "-";

  if (udpLen < 4) return info;

  uint8_t msgType = udpPayload[0];
  switch (msgType) {
    case 1: info.msgType = "SOLICIT"; break;
    case 3: info.msgType = "REQUEST"; break;
    case 4: info.msgType = "CONFIRM"; break;
    case 5: info.msgType = "RENEW"; break;
    case 6: info.msgType = "REBIND"; break;
    case 7: info.msgType = "REPLY"; break;
    case 8: info.msgType = "RELEASE"; break;
    case 9: info.msgType = "INFO-REQ"; break;
  }

  const uint8_t* optPtr = udpPayload + 4;
  const uint8_t* endPtr = udpPayload + udpLen;

  while (optPtr + 4 <= endPtr) {
    uint16_t optCode = (optPtr[0] << 8) | optPtr[1];
    uint16_t optLen  = (optPtr[2] << 8) | optPtr[3];
    const uint8_t* optData = optPtr + 4;

    if (optData + optLen > endPtr) break;

    if (optCode == 1 && optLen >= 4) {
      uint16_t duidType = (optData[0] << 8) | optData[1];
      if (duidType == 1 && optLen >= 10) {
        const uint8_t* mac = optData + optLen - 6;
        char macStr[18];
        snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        info.mac = String(macStr);

        uint32_t ts = (optData[4] << 24) | (optData[5] << 16) | (optData[6] << 8) | optData[7];
        time_t realTime = 946684800 + ts;
        struct tm* t = gmtime(&realTime);
        char buf[32];
        strftime(buf, sizeof(buf), "%Y-%m-%d", t);
        info.timestamp = String(buf);
      }
      else if (duidType == 3 && optLen >= 8) {
        const uint8_t* mac = optData + 4;
        char macStr[18];
        snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        info.mac = String(macStr);
      }
    }

    else if (optCode == 39 && optLen >= 1) {
      char name[128] = {0};
      size_t pos = 0;
      const uint8_t* ptr = optData + 1;
      while (ptr < optData + optLen && *ptr && pos < sizeof(name) - 2) {
        uint8_t len = *ptr++;
        if (ptr + len > optData + optLen) break;
        for (int i = 0; i < len && pos < sizeof(name) - 2; ++i)
          name[pos++] = isprint(*ptr) ? *ptr++ : '.';
        name[pos++] = '.';
      }
      name[pos] = '\0';
      info.hostname = String(name);
    }

    else if (optCode == 16 && optLen >= 4) {
      uint32_t entNum = (optData[0] << 24) | (optData[1] << 16) |
                        (optData[2] << 8) | optData[3];
      char label[64];
      snprintf(label, sizeof(label), "Enterprise %u", entNum);
      info.vendor = label;
      if (optLen > 4) {
        char extra[64] = {0};
        memcpy(extra, optData + 4, min(63, (int)optLen - 4));
        info.vendor += ": " + String(extra);
      }
    }

    optPtr += 4 + optLen;
  }
  return info;
}


const char* dnsTypeToString(uint16_t type) {
  switch (type) {
    case 1:   return "A";         // IPv4 address
    case 2:   return "NS";        // Name server
    case 5:   return "CNAME";     // Canonical name
    case 6:   return "SOA";       // Start of authority
    case 12:  return "PTR";       // Domain pointer
    case 15:  return "MX";        // Mail exchange
    case 16:  return "TXT";       // Text record
    case 28:  return "AAAA";      // IPv6 address
    case 33:  return "SRV";       // Service locator
    case 41:  return "OPT";       // EDNS0 (not typically shown)
    case 255: return "ANY";
    default:  return "UNKNOWN";
  }
}

String ipv6ArrayToString(const std::array<uint8_t, 16>& addr) {
  char ipStr[40];
  snprintf(ipStr, sizeof(ipStr),
           "%02X%02X:%02X%02X:%02X%02X:%02X%02X:"
           "%02X%02X:%02X%02X:%02X%02X:%02X%02X",
           addr[0], addr[1], addr[2], addr[3],
           addr[4], addr[5], addr[6], addr[7],
           addr[8], addr[9], addr[10], addr[11],
           addr[12], addr[13], addr[14], addr[15]);
  return String(ipStr);
}

bool isSolicitedNode(const uint8_t* ipv6) {
  // Check for FF02::1:FFXX:XXXX pattern
  return ipv6[0] == 0xFF &&     // Multicast
         ipv6[1] == 0x02 &&
         ipv6[2] == 0x00 && ipv6[3] == 0x00 &&
         ipv6[4] == 0x00 && ipv6[5] == 0x00 &&
         ipv6[6] == 0x00 && ipv6[7] == 0x00 &&
         ipv6[8] == 0x00 && ipv6[9] == 0x00 &&
         ipv6[10] == 0x00 && ipv6[11] == 0x01 &&
         ipv6[12] == 0xFF;  // FFXX:XXXX
}

String matchTargetMacSuffix(const uint8_t* dstAddr, const std::map<uint32_t, String>& macSuffixMap) {
  if (!isSolicitedNode(dstAddr)) return "";

  // Extract last 3 bytes
  uint8_t b1 = dstAddr[13];
  uint8_t b2 = dstAddr[14];
  uint8_t b3 = dstAddr[15];
  uint32_t suffix = (b1 << 16) | (b2 << 8) | b3;

  auto it = macSuffixMap.find(suffix);
  if (it != macSuffixMap.end()) {
    return " 🎯 Target=" + it->second;
  } else {
    char unknownMac[16];
    snprintf(unknownMac, sizeof(unknownMac), "?? ?? ?? %02X:%02X:%02X", b1, b2, b3);
    return " 🎯 Target=" + String(unknownMac);
  }
}

const char* annotateIPv6(const char* ip) {
  if (strncmp(ip, "fe80", 4) == 0) return "🔗 link-local";
  if (strncmp(ip, "ff02::fb", 8) == 0) return "📣 mDNS multicast";
  if (strcmp(ip, "::1") == 0) return "🖥️ localhost";
  if (strncmp(ip, "fc", 2) == 0 || strncmp(ip, "fd", 2) == 0) return "🏠 ULA";
  if (strncmp(ip, "ff02::1:ff", 10) == 0) return "🎯 solicited-node";
  if (strncmp(ip, "ff", 2) == 0) return "📡 multicast";
  if (strncmp(ip, "::", 2) == 0) return "🚫 unspecified";
  if (strncmp(ip, "2001:4860:4860::8888", 21) == 0 ||
      strncmp(ip, "2001:4860:4860::8844", 21) == 0) return "🌐 Google DNS";
  if (strncmp(ip, "2606:4700:4700::1111", 21) == 0 ||
      strncmp(ip, "2606:4700:4700::1001", 21) == 0) return "☁️ Cloudflare DNS";
  if (strncmp(ip, "2620:fe::fe", 11) == 0 ||
      strncmp(ip, "2620:fe::9", 10) == 0) return "🛡️ Quad9 DNS";
  if (strncmp(ip, "2001:db8", 8) == 0) return "📘 documentation";
  if (strstr(ip, "::ffff:") != nullptr) return "🔁 IPv4-mapped";
  if (strncmp(ip, "2", 1) == 0) return "🚀 global";  // catch-all for public
  return "";
}

/*
const char* annotateIPv6(const char* ip) {
  if (strncmp(ip, "FE80", 4) == 0) return " 🔗 link-local";
  if (strncmp(ip, "FF02::FB", 8) == 0) return " 📣 mDNS multicast";
  if (strcmp(ip, "::1") == 0) return " 🖥️ localhost";
  if (strncmp(ip, "FC", 2) == 0 || strncmp(ip, "FD", 2) == 0) return " 🏠 ULA";
  if (strncmp(ip, "FF02::1:FF", 10) == 0) return " 🎯 solicited-node";
  if (strncmp(ip, "FF", 2) == 0) return " 📡 multicast";
  if (strncmp(ip, "::", 2) == 0) return " 🚫 unspecified";
  if (strncmp(ip, "2001:4860:4860::8888", 21) == 0) return " 🌐 Google DNS";
  if (strncmp(ip, "2606:4700:4700::1111", 21) == 0) return " ☁️ Cloudflare DNS";
  if (strncmp(ip, "2620:fe::fe", 11) == 0) return " 🛡️ Quad9 DNS";
  return "";  // No tag
}
*/

void compressIPv6RFC5952(const uint8_t* addr, char* out, size_t outLen) {
  uint16_t segs[8];
  for (int i = 0; i < 8; ++i) {
    segs[i] = (addr[2 * i] << 8) | addr[2 * i + 1];
  }

  // Find longest run of zeros
  int bestStart = -1, bestLen = 0;
  for (int i = 0; i < 8;) {
    if (segs[i] == 0) {
      int j = i;
      while (j < 8 && segs[j] == 0) ++j;
      int len = j - i;
      if (len > bestLen) {
        bestStart = i;
        bestLen = len;
      }
      i = j;
    } else {
      ++i;
    }
  }
  if (bestLen < 2) bestStart = -1;

  char* ptr = out;
  size_t remaining = outLen;

  for (int i = 0; i < 8;) {
    if (i == bestStart) {
      if (remaining > 1) { *ptr++ = ':'; --remaining; }
      if (remaining > 1) { *ptr++ = ':'; --remaining; }
      i += bestLen;
      continue;
    }

    if (i > 0 && ptr > out && ptr[-1] != ':') {
      if (remaining > 1) { *ptr++ = ':'; --remaining; }
    }

    int written = snprintf(ptr, remaining, "%x", segs[i]);
    if (written <= 0 || (size_t)written >= remaining) break;

    ptr += written;
    remaining -= written;
    ++i;
  }

  *ptr = '\0';  // Null-terminate
}

const char* getIpv6Label(uint8_t nextHeader, uint16_t srcPort, uint16_t dstPort) {
  if (nextHeader == 17) {  // UDP
    if (srcPort == 5353 || dstPort == 5353) return "IPv6/UDP/mDNS";
    return "IPv6/UDP";
  }
  if (nextHeader == 6) return "IPv6/TCP";
  if (nextHeader == 58) return "IPv6/ICMPv6";  // could add subtypes if needed
  return "IPv6/Other";
}

const char* getIpv4Label(uint8_t protocol, uint16_t srcPort, uint16_t dstPort) {
  if (protocol == 0x11) { // UDP
    if (dstPort == 5353 || srcPort == 5353) return "IPv4/UDP/mDNS";
    if (dstPort == 53 || srcPort == 53)     return "IPv4/UDP/DNS";
    if (dstPort == 5355 || srcPort == 5355) return "IPv4/UDP/LLMNR";
    if (dstPort == 137 || srcPort == 137)   return "IPv4/UDP/NetBIOS";
    if (dstPort == 67 || srcPort == 67 || dstPort == 68 || srcPort == 68) return "IPv4/UDP/DHCP";
    return "IPv4/UDP";
  }
  if (protocol == 0x06) return "IPv4/TCP";     // TCP
  if (protocol == 0x01) return "IPv4/ICMP";    // ICMP
  return "IPv4/Other";                         // default fallback
}


String decodeNetbiosName(const char* encoded, size_t len = 32) { 
  if (!encoded || len != 32) return "";

  char decoded[17] = {0};  // 16-byte name + null terminator

  for (size_t i = 0; i < 16; ++i) {
    char c1 = encoded[2 * i];
    char c2 = encoded[2 * i + 1];

    if (c1 < 'A' || c1 > 'P' || c2 < 'A' || c2 > 'P') {
      decoded[i] = '?';
      continue;
    }

    uint8_t high = c1 - 'A';
    uint8_t low  = c2 - 'A';
    decoded[i] = (high << 4) | low;
  }

  // Optionally extract suffix byte
  char suffixStr[6];
  snprintf(suffixStr, sizeof(suffixStr), " (%02X)", (uint8_t)decoded[15]);

  // Trim trailing nulls and spaces
  decoded[15] = '\0';  // Remove suffix from visible part
  String result = String(decoded);
  result.trim();
  return result + String(suffixStr);  // e.g. "LAPTOP123 (00)"
}

/*
String decodeNetbiosName(const char* encoded, size_t len = 32) { //Not working
  if (!encoded || len != 32) return "";

  char decoded[17] = {0};  // 16-byte name + null terminator

  for (size_t i = 0; i < 16; ++i) {
    char c1 = encoded[2 * i];
    char c2 = encoded[2 * i + 1];

    if (c1 < 'A' || c1 > 'P' || c2 < 'A' || c2 > 'P') {
      // Bail out on invalid character — safer than guessing
      return "";
    }

    uint8_t high = c1 - 'A';
    uint8_t low  = c2 - 'A';
    decoded[i] = (high << 4) | low;
  }

  // Trim trailing spaces (0x20) from the actual name, but preserve suffix byte
  int trimLen = 15;
  while (trimLen > 0 && decoded[trimLen - 1] == ' ') {
    --trimLen;
  }

  String name(decoded, trimLen);
  char suffixStr[5];
  snprintf(suffixStr, sizeof(suffixStr), " (%02X)", (uint8_t)decoded[15]);

  return name + String(suffixStr);  // e.g. "LAPTOP123 (00)"
}

String decodeNetbiosName(const char* encoded, size_t len = 32) {
  if (!encoded || len != 32) return "";

  char decoded[17] = {0};  // 16-byte name + null terminator

  for (size_t i = 0; i < 16; ++i) {
    char c1 = encoded[2 * i];
    char c2 = encoded[2 * i + 1];

    if (c1 < 'A' || c1 > 'P' || c2 < 'A' || c2 > 'P') {
      decoded[i] = '?';
      continue;
    }

    uint8_t high = c1 - 'A';
    uint8_t low  = c2 - 'A';
    decoded[i] = (high << 4) | low;
  }

  // Strip padding spaces or nulls
  String result = String(decoded);
  result.trim();
  return result;
}
*/

bool isCompleteHandshake(const EapolHandshakeDetail& hs) {
  return hs.anonceSeen && hs.snonceSeen;
}

void printHexLine(const uint8_t* data, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    Serial.printf("%02X", data[i]);
  }
}

void macToString(const uint8_t* mac, char* out) {
  sprintf(out, "%02X:%02X:%02X:%02X:%02X:%02X",
          mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
void formatIPv6Short(const uint8_t* addr, char* buf, size_t bufLen) {
  snprintf(buf, bufLen,
    "%x:%x:%x:%x:%x:%x:%x:%x",
    (addr[0] << 8) | addr[1], (addr[2] << 8) | addr[3],
    (addr[4] << 8) | addr[5], (addr[6] << 8) | addr[7],
    (addr[8] << 8) | addr[9], (addr[10] << 8) | addr[11],
    (addr[12] << 8) | addr[13], (addr[14] << 8) | addr[15]);
}

void formatIPv6Compact(const uint8_t* ip, char* out, size_t outSize = 48) {
  snprintf(out, outSize,
           "%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X",
           ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
           ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]);
}

void ipToString(const uint8_t* ip, char* buf, size_t bufLen) {
  snprintf(buf, bufLen, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

bool decodeDnsName(const uint8_t* base, const uint8_t*& ptr, const uint8_t* end, char* out, size_t outLen) {
  size_t pos = 0;
  int depth = 0;
  const uint8_t* origPtr = ptr;

  while (ptr < end && depth++ < 10) {
    if (ptr >= end) return false;
    uint8_t len = *ptr++;

    // End of name
    if (len == 0) break;

    // Compression pointer (11xxxxxx)
    if ((len & 0xC0) == 0xC0) {
      if (ptr >= end) return false;

      uint8_t next = *ptr++;
      uint16_t offset = ((len & 0x3F) << 8) | next;

      // Bounds check
      if (offset >= (end - base)) return false;

      const uint8_t* newPtr = base + offset;
      // Recurse but don't update original ptr (compression terminates the name)
      return decodeDnsName(base, newPtr, end, out + pos, outLen - pos);
    }

    // Sanity check: label too long or buffer overflow
    if (len > 63 || ptr + len > end || pos + len + 1 >= outLen) return false;

    memcpy(out + pos, ptr, len);
    ptr += len;
    pos += len;
    out[pos++] = '.';
  }

  // Trim trailing dot
  if (pos > 0) out[pos - 1] = '\0';
  else if (outLen > 0) out[0] = '\0';

  return true;
}

/*
bool decodeDnsName(const uint8_t* base, const uint8_t* &ptr, const uint8_t* end, char* out, size_t outLen) {
  size_t pos = 0;
  int depth = 0;

  while (ptr < end && depth++ < 5) {
    uint8_t len = *ptr++;
    if (len == 0) break;

    // Compression pointer
    if ((len & 0xC0) == 0xC0) {
      if (ptr >= end) return false;
      uint16_t offset = ((len & 0x3F) << 8) | *ptr++;
      const uint8_t* newPtr = base + offset;
      return decodeDnsName(base, newPtr, end, out + pos, outLen - pos);
    }

    if (ptr + len > end || pos + len + 1 >= outLen) return false;

    memcpy(out + pos, ptr, len);
    pos += len;
    ptr += len;
    out[pos++] = '.';
  }

  if (pos > 0) out[pos - 1] = '\0'; // remove trailing dot
  else out[0] = '\0';

  return true;
}
*/
bool isLikelyEui64(const uint8_t* addr) {
  // Check for FF:FE at positions 11 and 12 (bytes 8 and 9 of the IID)
  return (addr[11] == 0xFF && addr[12] == 0xFE);
}

String extractMacFromEUI64(const uint8_t* ip6InterfaceId) {
  uint8_t mac[6];

  mac[0] = ip6InterfaceId[0] ^ 0x02;  // Invert U/L bit
  mac[1] = ip6InterfaceId[1];
  mac[2] = ip6InterfaceId[2];
  mac[3] = ip6InterfaceId[5];
  mac[4] = ip6InterfaceId[6];
  mac[5] = ip6InterfaceId[7];

  char macStr[18];
  snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  String vendor = lookupVendor(mac);

  return String(macStr) + "(" + vendor + ")";
}

/*
String extractMacFromEUI64(const uint8_t* ipv6) {
  char mac[18];
  snprintf(mac, sizeof(mac),
           "%02X:%02X:%02X:%02X:%02X:%02X",
           ipv6[8] ^ 0x02,  // Flip U/L bit
           ipv6[9],
           ipv6[10],
           ipv6[13],
           ipv6[14],
           ipv6[15]);
  return String(mac);
}
*/
/*
String extractMacFromEUI64(const uint8_t* addr) {
  // Extracts MAC from IPv6 EUI-64: |prefix|FFFE|suffix|
  // Reverses the U/L bit flip in the first byte

  char mac[18];
  snprintf(mac, sizeof(mac),
           "%02X:%02X:%02X:%02X:%02X:%02X",
           addr[8] ^ 0x02,  // Flip U/L bit
           addr[9],
           addr[10],
           addr[13],
           addr[14],
           addr[15]);

  return String(mac);
}
*/
/*
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
*/
void printFlowSummary(
  const std::map<String, uint32_t>& flowCounts,
  const std::map<String, uint64_t>& flowBytes,
  const std::map<String, uint64_t>& flowBytesSq,
  const std::map<String, std::set<String>>& dnsHostnamesByFlow,
  const std::set<String>& knownMacs,
  const std::map<String, std::array<uint8_t, 16>> fullIp6SrcMap,
  const std::map<String, std::array<uint8_t, 16>> fullIp6DstMap,
  //const std::map<String, String>& fullIp6SrcMap,
  //const std::map<String, String>& fullIp6DstMap,
  const char* label,
  size_t maxToShow
) {
  if (flowCounts.empty()) {
    Serial.printf("[DEBUG] No flows for: %s\n", label);
    return;
  }

  Serial.printf("📶 %s:\n", label);

  // --- Build MAC suffix → full MAC map ---
  std::map<uint32_t, String> macSuffixMap;
  for (const String& mac : knownMacs) {
    int lastColon = mac.lastIndexOf(':');
    int midColon = mac.lastIndexOf(':', lastColon - 1);
    int preColon = mac.lastIndexOf(':', midColon - 1);
    if (preColon >= 0 && midColon > preColon && lastColon > midColon) {
      uint8_t b1 = strtoul(mac.substring(preColon + 1, midColon).c_str(), nullptr, 16);
      uint8_t b2 = strtoul(mac.substring(midColon + 1, lastColon).c_str(), nullptr, 16);
      uint8_t b3 = strtoul(mac.substring(lastColon + 1).c_str(), nullptr, 16);
      uint32_t suffix = (b1 << 16) | (b2 << 8) | b3;
      macSuffixMap[suffix] = mac;
    }
  }

  std::vector<std::pair<String, uint32_t>> sorted(flowCounts.begin(), flowCounts.end());
  std::sort(sorted.begin(), sorted.end(), [](const std::pair<String, uint32_t>& a, const std::pair<String, uint32_t>& b) {
    return a.second > b.second;
  });

  size_t shown = 0;

  for (const auto& pair : sorted) {
    const String& flow = pair.first;
    uint32_t count = pair.second;
    uint64_t totalBytes = flowBytes.count(flow) ? flowBytes.at(flow) : 0;
    uint64_t totalSq    = flowBytesSq.count(flow) ? flowBytesSq.at(flow) : 0;

    float mean = count > 0 ? (float)totalBytes / count : 0.0;
    float stddev = 0.0;
    if (count > 1) {
      double avg = (double)totalBytes / count;
      double avgSq = (double)totalSq / count;
      float variance = static_cast<float>(avgSq - avg * avg);
      if (variance > 0) stddev = sqrtf(variance);
    }

    String extraInfo;

    bool hasHostname = dnsHostnamesByFlow.count(flow) && !dnsHostnamesByFlow.at(flow).empty();
    bool isImportant = hasHostname;

    // Extend to IPv6-only annotations
    // 🧬 Post-scan EUI-64 extraction
    bool hasEui64Tag = false;
    auto fullSrcIt = fullIp6SrcMap.find(flow);
    if (fullSrcIt != fullIp6SrcMap.end()) {
      const std::array<uint8_t, 16>& ip = fullSrcIt->second;
      // Check if it's a valid EUI-64 address
      if (isLikelyEui64(ip.data())) {
        hasEui64Tag = true;
        String mac = extractMacFromEUI64(ip.data() + 8);
        extraInfo += " 🧬 EUI64=" + mac;
      }
    }

    // 🎯 Post-scan solicited-node target MAC match
    auto fullDstIt = fullIp6DstMap.find(flow);
    if (fullDstIt != fullIp6DstMap.end()) {
      const std::array<uint8_t, 16>& ip = fullDstIt->second;

      // Check for solicited-node multicast pattern: FF02::1:FFXX:XXXX
      if (ip[0] == 0xFF && ip[1] == 0x02 &&
         ip[11] == 0x01 && ip[12] == 0xFF) {

       // Extract suffix from last 3 bytes
        uint32_t suffix = (uint32_t(ip[13]) << 16) |
                      (uint32_t(ip[14]) << 8) |
                      uint32_t(ip[15]);

        auto it = macSuffixMap.find(suffix);
        if (it != macSuffixMap.end()) {
          extraInfo += " 🎯 Target=" + it->second;
        } else {
          char fallback[16];
          snprintf(fallback, sizeof(fallback), "%02X:%02X:%02X",
                   ip[13], ip[14], ip[15]);
          extraInfo += " 🎯 Target=??:??:??:" + String(fallback);
        }
      }
    }


if (shown < maxToShow || isImportant) {
  // Print flow summary on main line
  Serial.printf("  %s : %u pkts, Bytes: %.1f ± %.1f\n",
                flow.c_str(), count, mean, stddev);

  // Print hostnames (if any) on the next indented line
  auto hostIt = dnsHostnamesByFlow.find(flow);
  if (hostIt != dnsHostnamesByFlow.end() && !hostIt->second.empty()) {
    // Group TXT fields by base name
    std::map<String, std::vector<String>> txtGroups;
    std::vector<String> otherTags;

    for (const auto& h : hostIt->second) {
     if (h.startsWith("mDNS TXT: ")) {
        int arrow = h.indexOf(" → ");
        if (arrow > 0) {
          String key = h.substring(10, arrow);     // extract base
          String value = h.substring(arrow + 3);   // extract value
          txtGroups[key].push_back(value);
        }
      } else {
        otherTags.push_back(h);
      }
    }

    // Print grouped TXT lines
    for (const auto& group : txtGroups) {
     Serial.printf("     🔎 TXT %s:\n", group.first.c_str());
     for (const auto& field : group.second) {
       Serial.printf("        • %s\n", field.c_str());
     }
    }

    // Print non-TXT hostnames (SRV, PTR, mDNS tags)
    for (const auto& h : otherTags) {
      Serial.printf("     🔍 %s\n", h.c_str());
    }
  }

//  auto hostIt = dnsHostnamesByFlow.find(flow);
//  if (hostIt != dnsHostnamesByFlow.end() && !hostIt->second.empty()) {
//    Serial.print("     🔍 ");
//    bool first = true;
//    for (const auto& h : hostIt->second) {
//      if (!first) Serial.print(", ");
//      Serial.print(h);
//      first = false;
//    }
//    Serial.println();
//  }

  // Print EUI-64 or Target info (optional annotations)
  if (!extraInfo.isEmpty()) {
    Serial.printf("     %s\n", extraInfo.c_str());
  }

  if (!isImportant) shown++;
}

    //if (shown < maxToShow || isImportant) {
    //    Serial.printf("  %s : %u pkts, Bytes: %.1f ± %.1f%s\n",
    //                 flow.c_str(), count, mean, stddev, extraInfo.c_str());
    //      if (!isImportant) shown++;
    //}
  }
      if (sorted.size() > shown) {
       Serial.printf("  + %zu more flows not shown\n", sorted.size() - shown);
    }

}
/*
void printFlowSummary(
  const std::map<String, uint32_t>& flowCounts,
  const std::map<String, uint64_t>& flowBytes,
  const std::map<String, uint64_t>& flowBytesSq,
  const std::map<String, std::set<String>>& dnsHostnamesByFlow,
  const std::set<String>& knownMacs,
  const std::set<String>& eui64Macs,
  const char* label,
  size_t maxToShow
) {
  if (flowCounts.empty()) {
    Serial.printf("[DEBUG] No flows for: %s\n", label);
    return;
  }

  Serial.printf("📶 %s:\n", label);

  // Build MAC suffix → full MAC map
  std::map<uint32_t, String> macSuffixMap;
  for (const String& mac : knownMacs) {
    int lastColon = mac.lastIndexOf(':');
    int midColon = mac.lastIndexOf(':', lastColon - 1);
    int preColon = mac.lastIndexOf(':', midColon - 1);
    if (preColon >= 0 && midColon > preColon && lastColon > midColon) {
      uint8_t b1 = strtoul(mac.substring(preColon + 1, midColon).c_str(), nullptr, 16);
      uint8_t b2 = strtoul(mac.substring(midColon + 1, lastColon).c_str(), nullptr, 16);
      uint8_t b3 = strtoul(mac.substring(lastColon + 1).c_str(), nullptr, 16);
      uint32_t suffix = (b1 << 16) | (b2 << 8) | b3;
      macSuffixMap[suffix] = mac;
    }
  }

  // Sort flows by packet count
  std::vector<std::pair<String, uint32_t>> sorted(flowCounts.begin(), flowCounts.end());
  std::sort(sorted.begin(), sorted.end(), [](const std::pair<String, uint32_t>& a, const std::pair<String, uint32_t>& b) {
  return a.second > b.second;
  });

  size_t shown = 0;
  for (auto& pair : sorted) {
    String flow = pair.first;
    uint32_t count = pair.second;
    uint64_t totalBytes = flowBytes.count(flow) ? flowBytes.at(flow) : 0;
    uint64_t totalSq    = flowBytesSq.count(flow) ? flowBytesSq.at(flow) : 0;

    float mean = count > 0 ? (float)totalBytes / count : 0.0;
    float variance = 0.0;
    if (count > 1) {
      double avg = static_cast<double>(totalBytes) / count;
      double avgSq = static_cast<double>(totalSq) / count;
      variance = static_cast<float>(avgSq - avg * avg);
      if (variance < 0) variance = 0;
    }
    float stddev = sqrt(variance);

    // Inline hostname if present
    String extraInfo;
    auto hostIt = dnsHostnamesByFlow.find(flow);
    if (hostIt != dnsHostnamesByFlow.end() && !hostIt->second.empty()) {
      for (const auto& h : hostIt->second) {
        extraInfo += " 🔍 " + h;
      }
    }

    // 🧬 EUI-64 Source Match
    for (const String& euiMac : eui64Macs) {
      if (flow.indexOf(euiMac) != -1) {
        extraInfo += " 🧬 EUI64=" + euiMac;
        break;
      }
    }

    // 🎯 Solicited-node target MAC suffix match
    if (flow.startsWith("FE80") || flow.startsWith("FF02") || flow.startsWith("2001")) {
      int arrow = flow.indexOf(" → ");
      int paren = flow.indexOf(" (", arrow);
      if (arrow > 0 && paren > arrow) {
        String dst = flow.substring(arrow + 3, paren);
        if (dst.startsWith("FF02::1:FF")) {
          int lastColon = dst.lastIndexOf(':');
          int midColon = dst.lastIndexOf(':', lastColon - 1);
          int preColon = dst.lastIndexOf(':', midColon - 1);
          if (preColon >= 0 && midColon > preColon && lastColon > midColon) {
            uint8_t b1 = strtoul(dst.substring(preColon + 1, midColon).c_str(), nullptr, 16);
            uint8_t b2 = strtoul(dst.substring(midColon + 1, lastColon).c_str(), nullptr, 16);
            uint8_t b3 = strtoul(dst.substring(lastColon + 1).c_str(), nullptr, 16);
            uint32_t suffix = (b1 << 16) | (b2 << 8) | b3;

            auto it = macSuffixMap.find(suffix);
            String targetTag;
            if (it != macSuffixMap.end()) {
              targetTag = " 🎯 Target=" + it->second;
            } else {
              char unknownMac[16];
              snprintf(unknownMac, sizeof(unknownMac), "?? ?? ?? %02X:%02X:%02X", b1, b2, b3);
              targetTag = " 🎯 Target=" + String(unknownMac);
            }
            extraInfo += targetTag;
          }
        }
      }
    }

    bool hasHostname = dnsHostnamesByFlow.count(flow) && !dnsHostnamesByFlow.at(flow).empty();
    bool hasEui64Tag = false;
    for (const String& euiMac : eui64Macs) {
      if (flow.indexOf(euiMac) != -1) {
        hasEui64Tag = true;
        break;
      }
    }

    bool isImportant = hasHostname || hasEui64Tag;

    if (shown < maxToShow || isImportant) {
      Serial.printf("  %s : %u pkts, Bytes: %.1f ± %.1f%s\n",
                flow.c_str(), count, mean, stddev, extraInfo.c_str());
      if (!isImportant) shown++;
    }

  }

  if (sorted.size() > maxToShow) {
    Serial.printf("  + %zu more flows not shown\n", sorted.size() - maxToShow);
  }
}
*/
/*
void printFlowSummary(
  const std::map<String, uint32_t>& flowCounts,
  const std::map<String, uint64_t>& flowBytes,
  const std::map<String, uint64_t>& flowBytesSq,
  const std::map<String, std::set<String>>& dnsHostnamesByFlow,
  const std::set<String>& knownMacs,
  const char* label,
  size_t maxToShow
) {
  if (flowCounts.empty()) return;

  Serial.printf("📶 %s:\n", label);

  // Build MAC suffix → full MAC map
  std::map<uint32_t, String> macSuffixMap;
  auto insertSuffixes = [&](const std::set<String>& macSet) {
    for (const String& mac : macSet) {
      int lastColon = mac.lastIndexOf(':');
      int midColon = mac.lastIndexOf(':', lastColon - 1);
      int preColon = mac.lastIndexOf(':', midColon - 1);
      if (preColon >= 0 && midColon > preColon && lastColon > midColon) {
        uint8_t b1 = strtoul(mac.substring(preColon + 1, midColon).c_str(), nullptr, 16);
        uint8_t b2 = strtoul(mac.substring(midColon + 1, lastColon).c_str(), nullptr, 16);
        uint8_t b3 = strtoul(mac.substring(lastColon + 1).c_str(), nullptr, 16);
        uint32_t suffix = (b1 << 16) | (b2 << 8) | b3;
        macSuffixMap[suffix] = mac;
      }
    }
  };
  insertSuffixes(knownMacs);

  // Sort flow entries by count descending
  std::vector<std::pair<String, uint32_t>> sorted(flowCounts.begin(), flowCounts.end());
  std::sort(sorted.begin(), sorted.end(),
            [](const std::pair<String, uint32_t>& a, const std::pair<String, uint32_t>& b) {
              return a.second > b.second;
            });

  size_t shown = 0;

  for (const auto& pair : sorted) {
    String flow = pair.first;
    uint32_t count = pair.second;
    uint64_t totalBytes = flowBytes.count(flow) ? flowBytes.at(flow) : 0;
    uint64_t totalSq = flowBytesSq.count(flow) ? flowBytesSq.at(flow) : 0;

    float mean = (count > 0) ? ((float)totalBytes / count) : 0.0;
    float variance = 0.0;
    if (count > 1) {
      double avg = static_cast<double>(totalBytes) / count;
      double avgSq = static_cast<double>(totalSq) / count;
      variance = static_cast<float>(avgSq - avg * avg);
      if (variance < 0.0) variance = 0.0;
    }
    float stddev = sqrt(variance);

    // IPv6 zero compression (basic)
    flow.replace(":0000", "::");
    flow.replace("0000:", "::");
    while (flow.indexOf(":::") != -1) flow.replace(":::", "::");

    // Attempt to match multicast suffix with known MAC
    if (flow.startsWith("FE80") || flow.startsWith("FF02") || flow.startsWith("2001")) {
      int arrow = flow.indexOf(" → ");
      int paren = flow.indexOf(" (", arrow);
      if (arrow > 0 && paren > arrow) {
        String dst = flow.substring(arrow + 3, paren);
        if (dst.startsWith("FF02::1:FF")) {
          int lastColon = dst.lastIndexOf(':');
          int midColon = dst.lastIndexOf(':', lastColon - 1);
          int preColon = dst.lastIndexOf(':', midColon - 1);
          if (preColon >= 0 && midColon > preColon && lastColon > midColon) {
            uint8_t b1 = strtoul(dst.substring(preColon + 1, midColon).c_str(), nullptr, 16);
            uint8_t b2 = strtoul(dst.substring(midColon + 1, lastColon).c_str(), nullptr, 16);
            uint8_t b3 = strtoul(dst.substring(lastColon + 1).c_str(), nullptr, 16);
            uint32_t suffix = (b1 << 16) | (b2 << 8) | b3;

            auto it = macSuffixMap.find(suffix);
            String targetTag;
            if (it != macSuffixMap.end()) {
              targetTag = " 🎯 Target MAC: " + it->second;
            } else {
              char unknownMac[16];
              snprintf(unknownMac, sizeof(unknownMac), "%02X:%02X:%02X", b1, b2, b3);
              targetTag = " 🎯 Target MAC suffix: " + String(unknownMac);
            }

            flow = flow.substring(0, paren) + targetTag + flow.substring(paren);
          }
        }
      }
    }

    if (shown++ < maxToShow) {
      String extraInfo;
      auto hostIt = dnsHostnamesByFlow.find(flow);
      if (hostIt != dnsHostnamesByFlow.end() && !hostIt->second.empty()) {
        // Show up to 3 hostnames, grouped by source tag
        std::map<String, std::vector<String>> tagGroups;
        for (const String& h : hostIt->second) {
          int split = h.indexOf(": ");
          String tag = (split > 0) ? h.substring(0, split) : "";
          String name = (split > 0) ? h.substring(split + 2) : h;
          tagGroups[tag].push_back(name);
        }

        for (const auto& tg : tagGroups) {
          const String& tag = tg.first;
          const std::vector<String>& items = tg.second;
          extraInfo += " 🔍 " + tag + ": ";
          for (size_t i = 0; i < items.size() && i < 3; ++i) {
            if (i > 0) extraInfo += ", ";
            extraInfo += items[i];
          }
        }
      }

      Serial.printf("  %s : %u pkts, Bytes: %.1f ± %.1f%s\n",
                    flow.c_str(), count, mean, stddev, extraInfo.c_str());
    }
  }

  if (flowCounts.size() > maxToShow) {
    Serial.printf("  + %zu more flows not shown\n", flowCounts.size() - maxToShow);
  }
}
*/
/*
void printFlowSummary(
  const std::map<String, uint32_t>& flowCounts,
  const std::map<String, uint64_t>& flowBytes,
  const std::map<String, uint64_t>& flowBytesSq,
  const std::map<String, std::set<String>>& dnsHostnamesByFlow,
  const std::set<String>& knownMacs,
  const char* label,
  size_t maxToShow
) {
  if (flowCounts.empty()) return;

  Serial.printf("📶 %s:\n", label);

  // Build MAC suffix → full MAC map
  std::map<uint32_t, String> macSuffixMap;
  auto insertSuffixes = [&](const std::set<String>& macSet) {
    for (const String& mac : macSet) {
      int lastColon = mac.lastIndexOf(':');
      int midColon = mac.lastIndexOf(':', lastColon - 1);
      int preColon = mac.lastIndexOf(':', midColon - 1);
      if (preColon >= 0 && midColon > preColon && lastColon > midColon) {
        uint8_t b1 = strtoul(mac.substring(preColon + 1, midColon).c_str(), nullptr, 16);
        uint8_t b2 = strtoul(mac.substring(midColon + 1, lastColon).c_str(), nullptr, 16);
        uint8_t b3 = strtoul(mac.substring(lastColon + 1).c_str(), nullptr, 16);
        uint32_t suffix = (b1 << 16) | (b2 << 8) | b3;
        macSuffixMap[suffix] = mac;
      }
    }
  };
  insertSuffixes(knownMacs);

  // Sort flow entries by count descending
  std::vector<std::pair<String, uint32_t>> sorted(flowCounts.begin(), flowCounts.end());
  std::sort(sorted.begin(), sorted.end(),
          [](const std::pair<String, uint32_t>& a, const std::pair<String, uint32_t>& b) {
            return a.second > b.second;
          });

  size_t shown = 0;

  for (const auto& pair : sorted) {
    String flow = pair.first;
    uint32_t count = pair.second;
    uint64_t totalBytes = flowBytes.count(flow) ? flowBytes.at(flow) : 0;
    uint64_t totalSq = flowBytesSq.count(flow) ? flowBytesSq.at(flow) : 0;

    float mean = (count > 0) ? ((float)totalBytes / count) : 0.0;
    float variance = 0.0;
    if (count > 1) {
      double avg = static_cast<double>(totalBytes) / count;
      double avgSq = static_cast<double>(totalSq) / count;
      variance = static_cast<float>(avgSq - avg * avg);
      if (variance < 0.0) variance = 0.0; // Prevent sqrt(-0.0)
    }
    float stddev = sqrt(variance);

    // ✅ IPv6 compression
    flow.replace("0000:", ":");
    flow.replace(":0000", ":");
    while (flow.indexOf(":::" ) != -1) flow.replace(":::", "::");
    while (flow.indexOf("::0:" ) != -1) flow.replace("::0:", "::");
    while (flow.indexOf(":0:"  ) != -1) flow.replace(":0:", "::");

    // ✅ Try target MAC suffix match for solicited-node multicast
    if (flow.startsWith("FE80") || flow.startsWith("FF02") || flow.startsWith("2001")) {
      int arrow = flow.indexOf(" → ");
      int paren = flow.indexOf(" (", arrow);
      if (arrow > 0 && paren > arrow) {
        String dst = flow.substring(arrow + 3, paren);
        if (dst.startsWith("FF02::1:FF")) {
          int lastColon = dst.lastIndexOf(':');
          int midColon = dst.lastIndexOf(':', lastColon - 1);
          int preColon = dst.lastIndexOf(':', midColon - 1);
          if (preColon >= 0 && midColon > preColon && lastColon > midColon) {
            uint8_t b1 = strtoul(dst.substring(preColon + 1, midColon).c_str(), nullptr, 16);
            uint8_t b2 = strtoul(dst.substring(midColon + 1, lastColon).c_str(), nullptr, 16);
            uint8_t b3 = strtoul(dst.substring(lastColon + 1).c_str(), nullptr, 16);
            uint32_t suffix = (b1 << 16) | (b2 << 8) | b3;

            auto it = macSuffixMap.find(suffix);
            String targetTag;
            if (it != macSuffixMap.end()) {
              targetTag = " 🎯 Target MAC: " + it->second;
            } else {
              char unknownMac[16];
              snprintf(unknownMac, sizeof(unknownMac), "?? ?? ?? %02X:%02X:%02X", b1, b2, b3);
              targetTag = " 🎯 Target MAC: " + String(unknownMac);
            }

            // Insert tag into flow before the parentheses
            int paren = flow.indexOf(" (", arrow);
            if (paren != -1)
              flow = flow.substring(0, paren) + targetTag + flow.substring(paren);
          }
        }
      }
    }

    if (shown++ < maxToShow) {
      // 🔍 Inline DNS hostnames if available
      String extraInfo;
      auto hostIt = dnsHostnamesByFlow.find(flow);
      if (hostIt != dnsHostnamesByFlow.end() && !hostIt->second.empty()) {
        extraInfo = " 🔍 " + *hostIt->second.begin();
      }

      Serial.printf("  %s : %u pkts, Bytes: %.1f/%.1f%s\n",
                    flow.c_str(), count, mean, stddev, extraInfo.c_str());
    }
  }

  if (flowCounts.size() > maxToShow) {
    Serial.printf("  + %zu more flows not shown\n", flowCounts.size() - maxToShow);
  }
}

void printFlowSummary(const std::map<String, uint32_t>& flowCounts,
                      const std::map<String, uint64_t>& flowBytes,
                      const std::map<String, uint64_t>& flowBytesSq,
                      const std::map<String, std::set<String>>& dnsHostnamesByFlow = {},
                      const char* label = "Flows",
                      size_t maxToShow = 7) {
  if (flowCounts.empty()) return;
    std::map<uint32_t, String> macSuffixMap;

  auto insertSuffixes = [&](const std::set<String>& macSet) {
  for (const String& mac : macSet) {
    int lastColon = mac.lastIndexOf(':');
    int midColon = mac.lastIndexOf(':', lastColon - 1);
    int preColon = mac.lastIndexOf(':', midColon - 1);
    if (preColon >= 0 && midColon > preColon && lastColon > midColon) {
      uint8_t b1 = strtoul(mac.substring(preColon + 1, midColon).c_str(), nullptr, 16);
      uint8_t b2 = strtoul(mac.substring(midColon + 1, lastColon).c_str(), nullptr, 16);
      uint8_t b3 = strtoul(mac.substring(lastColon + 1).c_str(), nullptr, 16);
      uint32_t suffix = (b1 << 16) | (b2 << 8) | b3;
      macSuffixMap[suffix] = mac;
    }
  }
};


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
    String flow = pair.first;
    uint32_t count = pair.second;

    // ✅ Optional IPv6 abbreviation (flow compression)
    flow.replace("0000:", ":");
    flow.replace(":0000", ":");
    flow.replace(":::", "::"); // Clean up double replacement
    while (flow.indexOf(":0000") >= 0)
      flow.replace(":0000", ":");
    flow.replace("FE80:0:0:0", "FE80::");
    flow.replace("FF02:0:0:0:0:1", "FF02::1");
    flow.replace(":::", "::");

    if (shown++ < maxToShow) {
      uint64_t totalBytes = flowBytes.count(flow) ? flowBytes.at(flow) : 0;
      float mean = (count > 0) ? ((float)totalBytes / count) : 0.0;

      Serial.printf("  %s : %u pkts, %.1f B/pkt\n", flow.c_str(), count, mean);

      // ✅ Append hostnames if any exist for this flow
      auto it = dnsHostnamesByFlow.find(flow);
      if (it != dnsHostnamesByFlow.end()) {
        for (const String& hostname : it->second) {
          Serial.printf("    🔍 Hostname: %s\n", hostname.c_str());
        }
      }

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
*/

String extractIPv6Prefix(const uint8_t* addr) {
  char prefix[40];
  snprintf(prefix, sizeof(prefix), "%02x%02x:%02x%02x:%02x%02x:%02x%02x::/64",
           addr[0], addr[1], addr[2], addr[3],
           addr[4], addr[5], addr[6], addr[7]);
  return String(prefix);
}

String formatIPv6(const uint8_t* addr, bool annotate = true, std::set<uint32_t>* targetSuffixes = nullptr) {
  char ipStr[40];  // Max IPv6 string = 39 + null
  snprintf(ipStr, sizeof(ipStr),
           "%02X%02X:%02X%02X:%02X%02X:%02X%02X:"
           "%02X%02X:%02X%02X:%02X%02X:%02X%02X",
           addr[0], addr[1], addr[2], addr[3],
           addr[4], addr[5], addr[6], addr[7],
           addr[8], addr[9], addr[10], addr[11],
           addr[12], addr[13], addr[14], addr[15]);

  String result(ipStr);

  if (!annotate) return result;

  // 📛 Label special address types
  if (result.startsWith("FE80")) result += " 🔗 link-local";
  else if (result.startsWith("FF02::1")) result += " 🔉 all-nodes";
  else if (result.startsWith("FF02::2")) result += " 📣 all-routers";
  else if (result.startsWith("2001:4860:4860::8888")) result += " 🌐 Google DNS";

  // 🧬 Extract EUI-64 MAC (usually from src IP)
  if (isLikelyEui64(addr)) {
    String mac = extractMacFromEUI64(addr);
    result += " 🧬 EUI-64 MAC: " + mac;
  }

  // 🎯 Target MAC suffix (from solicited-node multicast)
  if (targetSuffixes &&
      addr[0] == 0xFF && addr[1] == 0x02 &&
      addr[11] == 0x01 && addr[12] == 0xFF) {
    uint32_t suffix =
      (uint32_t(addr[13]) << 16) |
      (uint32_t(addr[14]) << 8) |
      addr[15];

    targetSuffixes->insert(suffix);

    char suffixStr[12];
    snprintf(suffixStr, sizeof(suffixStr), "%02X:%02X:%02X", addr[13], addr[14], addr[15]);
    result += " 🎯 target suffix: " + String(suffixStr);
  }

  return result;
}

/*
String formatIPv6(const uint8_t* addr, bool annotate = true, std::set<uint32_t>* targetSuffixes = nullptr) {
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

  // Standard IPv6 annotations
  if (ip.startsWith("FE80")) ip += " 🔗 link-local";
  else if (ip.startsWith("FF02::1")) ip += " 🔉 all-nodes";
  else if (ip.startsWith("FF02::2")) ip += " 📣 all-routers";
  else if (ip.startsWith("2001:4860:4860::8888")) ip += " 🌐 Google DNS";

  // 🧬 Reconstruct source MAC if EUI-64
  if (isLikelyEui64(addr)) {
    String mac = extractMacFromEUI64(addr);
    ip += " 🧬 EUI-64 MAC: " + mac;
  }

  // 🎯 Attempt to extract target MAC suffix if FF02::1:FFXX:XXXX
  if (targetSuffixes &&
      addr[0] == 0xFF && addr[1] == 0x02 &&
      addr[11] == 0x01 && addr[12] == 0xFF) {
    uint32_t suffix =
      (static_cast<uint32_t>(addr[13]) << 16) |
      (static_cast<uint32_t>(addr[14]) << 8) |
      static_cast<uint32_t>(addr[15]);

    targetSuffixes->insert(suffix);
    char suffixStr[9];
    snprintf(suffixStr, sizeof(suffixStr), "%02X:%02X:%02X", addr[13], addr[14], addr[15]);
    ip += " 🎯 target suffix: " + String(suffixStr);
  }

  return ip;
}
*/
/*
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
*/

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

  auto& ssids = stats.mgmt.seenSsids;

  // Already seen
  if (ssids.count(ssid)) return;

  // Still under limit
  if (ssids.size() < MAX_SSID_TRACK) {
    ssids.insert(ssid);
    Serial.println("[📡] New SSID for MAC: \"" + ssid + "\"");
    return;
  }

  // Overflow: bump hidden count
  stats.mgmt.hiddenSsidCount++;

  // Insert or update the (+x more) entry
  String marker = "(+" + String(stats.mgmt.hiddenSsidCount) + " more)";
  
  // Erase previous marker if exists
  for (auto it = ssids.begin(); it != ssids.end(); ++it) {
    if (it->startsWith("(+")) {
      ssids.erase(it);
      break;
    }
  }

  ssids.insert(marker);
}

/*
void addSsidToStats(MacStats& stats, const String& ssid) {
  if (ssid.length() == 0) return;

  if (stats.mgmt.seenSsids.insert(ssid).second) {
    Serial.println("[📡] New SSID discovered for MAC (addSsidToStats): \"" + ssid + "\"");
  }
}
*/

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


void extractSsid(const uint8_t* payload, int len, String& out) {
  out = "";

  int offset = 0;
  while (offset + 2 <= len) {
    uint8_t id = payload[offset];
    uint8_t tagLen = payload[offset + 1];

    // Validate tag length
    if (offset + 2 + tagLen > len) break;

    // Stop if we hit vendor-specific IEs (WPS etc.)
    if (id == 0xDD) break;

    // Handle SSID tag (ID 0)
    if (id == 0 && tagLen <= 32) {
      if (tagLen == 0) return;

      out.reserve(tagLen);
      for (int i = 0; i < tagLen; ++i) {
        char c = payload[offset + 2 + i];
        if (c >= 32 && c <= 126) {
          out += c;
        }
      }
      return;
    }

    offset += 2 + tagLen;
  }
}
/*
void extractSsid(const uint8_t* payload, int len, String& out) {
  out = "";
  int offset = 0;
  while (offset + 2 <= len) {
    uint8_t id = payload[offset];
    uint8_t tagLen = payload[offset + 1];

    if (offset + 2 + tagLen > len) break;
    if (id == 0 && tagLen <= 32) {
      if (tagLen == 0) return;
      out.reserve(tagLen);  // Optional: prevent reallocs

      for (int i = 0; i < tagLen; ++i) {
        char c = payload[offset + 2 + i];
        if (c >= 32 && c <= 126) {
          out += c;
        }
      }
      return;
    }
    offset += 2 + tagLen;
  }
}
*/
/*
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
*/
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
  bool isEncrypted = frame[1] & 0x40;
  const String& macKey = cap.senderMac;
  MacStats& stats = macStatsMap[macKey];

  uint8_t macHeaderLen = 24;
  if (cap.directionCode == DIR_WDS) macHeaderLen += 6;
  bool isQoS = cap.subtype >= 0x08 && cap.subtype <= 0x0F;
  if (isQoS) macHeaderLen += 2;
  if (len < macHeaderLen + 8) return;

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
      if (isEncrypted) stats.df.encryptedUpCount++;
    } else if (cap.directionCode == DIR_AP_TO_CLIENT) {
      stats.df.qosDownCount++;
      stats.df.tidDownSum += tid;
      stats.df.tidDownSqSum += tid * tid;
      stats.df.amsduDownSum += amsdu;
      stats.df.eospDownSum += eosp;
      stats.df.qosLenDownSum += cap.length;
      stats.df.qosLenDownSqSum += cap.length * cap.length;
      if (isEncrypted) stats.df.encryptedDownCount++;
    }

    Serial.printf("🎯 QoS Control: TID = %u | A-MSDU = %s | EOSP = %s%s\n",
      tid, amsdu ? "Yes" : "No", eosp ? "Yes" : "No",
      isEncrypted ? " | 🔐 Encrypted" : "");

    if (tid >= 4 && tid < 6) Serial.println("🟡 Possibly video (TID 4-5)");
    else if (tid >= 6 && tid < 8) Serial.println("🚨 High-priority traffic (TID 6-7)");
  }

  if (isEncrypted) return;

  const uint8_t* llc = frame + macHeaderLen;
  if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03) return;

  uint32_t oui = (llc[3] << 16) | (llc[4] << 8) | llc[5];
  uint16_t etherType = (llc[6] << 8) | llc[7];
  const uint8_t* payload = llc + 8;
  uint16_t payloadLen = len - (macHeaderLen + 8);

  stats.df.etherTypes.insert(etherType);

  // -------- EtherType Summary --------
  switch (etherType) {
    case 0x0806: stats.df.etherTypeSummaryCounts["ARP"]++; break;
    case 0x888E: stats.df.etherTypeSummaryCounts["EAPOL"]++; break;
    case 0x8100: stats.df.etherTypeSummaryCounts["802.1Q VLAN"]++; break;
    case 0x8847: stats.df.etherTypeSummaryCounts["MPLS"]++; break;
    case 0x8864: stats.df.etherTypeSummaryCounts["PPP-over-E"]++; break;
    case 0x88CC: stats.df.etherTypeSummaryCounts["LLDP"]++; break;
    default:
      if (etherType != 0x0800 && etherType != 0x86DD) {
        char label[16];
        snprintf(label, sizeof(label), "0x%04X", etherType);
        stats.df.etherTypeSummaryCounts[label]++;
      }
      break;
  }

  // --------------------- EAPOL ---------------------
  if (etherType == 0x888E && payloadLen >= 60) {
    uint8_t type = payload[1];
    if (type == 3) {

      uint16_t keyInfo = (payload[4] << 8) | payload[5];
      bool mic      = keyInfo & 0x0200;
      bool ack      = keyInfo & 0x0080;
      bool install  = keyInfo & 0x0040;
      bool pairwise = keyInfo & 0x0001;

      //bool mic = keyInfo & (1 << 8);
      //bool ack = keyInfo & (1 << 7);
      //bool install = keyInfo & (1 << 6);
      //bool pairwise = keyInfo & (1 << 3);

      Serial.printf("[DEBUG] keyInfo: 0x%04X | Binary: ", keyInfo);
      for (int i = 15; i >= 0; --i)
        Serial.print((keyInfo >> i) & 1);
      Serial.println();
      Serial.printf("🔐 EAPOL Key Frame | MIC:%d | ACK:%d | Install:%d | Pairwise:%d\n", mic, ack, install, pairwise);
      if (mic && install && !pairwise) {
        Serial.println("🔁 Group Key Handshake (1/2) — GTK Install");
      } else if (mic && !install && !ack && !pairwise) {
        Serial.println("✅ Group Key Handshake (2/2) — Client ACK");
      }

EapolMsgType msgType = EAPOL_MSG_UNKNOWN;

if (!mic && ack) {
  msgType = EAPOL_MSG_1_4;
}
else if (mic && ack && !install && pairwise) {
  msgType = EAPOL_MSG_2_4;
}
else if (mic && install && !ack && pairwise) {
  msgType = EAPOL_MSG_3_4;
}
else if (mic && !install && !ack && pairwise) {
  msgType = EAPOL_MSG_4_4;
}
else if (mic && install && !ack && !pairwise) {
  Serial.println("🔁 Group Key Handshake (1/2) — GTK Install");
  msgType = EAPOL_GROUP_MSG_1_2;
}
else if (mic && !install && !ack && !pairwise) {
  Serial.println("✅ Group Key Handshake (2/2) — Client ACK");
  msgType = EAPOL_GROUP_MSG_2_2;
}
     
      const char* msgLabel[] = {"Unknown", "1/4", "2/4", "3/4", "4/4", "G-1/2", "G-2/2"};
      Serial.printf("📡 WPA Handshake Detected: Msg %s\n", msgLabel[msgType]);

      stats.df.eapolHandshakeCounts[msgType]++;
      EapolHandshakeDetail& hs = stats.df.handshake;

      if (msgType == EAPOL_MSG_1_4 && !hs.anonceSeen) {
        memcpy(hs.anonce, payload + 17, 32);
        memcpy(hs.apMac, cap.senderMac.c_str(), 6);
        hs.anonceSeen = true;
        Serial.println("🧬 ANonce saved");
      } else if (msgType == EAPOL_MSG_2_4 && !hs.snonceSeen) {
        memcpy(hs.snonce, payload + 17, 32);
        memcpy(hs.clientMac, cap.senderMac.c_str(), 6);
        hs.replayCounter = ((uint64_t)payload[9] << 56) | ((uint64_t)payload[10] << 48) |
                           ((uint64_t)payload[11] << 40) | ((uint64_t)payload[12] << 32) |
                           ((uint64_t)payload[13] << 24) | ((uint64_t)payload[14] << 16) |
                           ((uint64_t)payload[15] << 8)  | ((uint64_t)payload[16]);
        hs.snonceSeen = true;
        Serial.println("🧬 SNonce + replay counter saved");
      }

      if (stats.mgmt.ssid.length() && hs.ssid.length() == 0) {
        hs.ssid = stats.mgmt.ssid;
        Serial.println("🔖 SSID saved: " + hs.ssid);
      }

      if (hs.anonceSeen && hs.snonceSeen) {
        Serial.println("🎉 4-Way Handshake Complete!");

        Serial.print("ANonce: ");
        printHexLine(hs.anonce, 32);
        Serial.println();

        Serial.print("SNonce: ");
        printHexLine(hs.snonce, 32);
        Serial.println();
      }
    }
    return;
  }

  // --------------------- IPv4 ---------------------
if (etherType == 0x0800 && payloadLen >= 20) {
  const uint8_t* ip = payload;
  Serial.printf("[DEBUG] Src IP raw bytes: %02X %02X %02X %02X\n",
            ip[12], ip[13], ip[14], ip[15]);
  uint8_t ihl = (ip[0] & 0x0F) * 4;
  uint8_t protocol = ip[9];

  char srcIp[16], dstIp[16], flowKey[64];
  ipToString(ip + 12, srcIp, sizeof(srcIp));
  Serial.printf("[DEBUG] ipToString(): %s\n", srcIp);
  ipToString(ip + 16, dstIp, sizeof(dstIp));
  const uint8_t* end = payload + payloadLen;
  const char* label = "IPv4/Other";

  // ---------- UDP ----------
  if (protocol == 0x11 && payloadLen >= ihl + 8) {
    const uint8_t* udp = ip + ihl;
    uint16_t srcPort = (udp[0] << 8) | udp[1];
    uint16_t dstPort = (udp[2] << 8) | udp[3];
    const uint8_t* dns = udp + 8;
    const uint8_t* end = payload + payloadLen;

    // 🔍 SSDP detection (port 1900)
    if (srcPort == 1900 || dstPort == 1900) {
      parseSsdpPayload(dns, end - dns, srcIp, dstIp, "", stats.df);
    }

    // Get label right away here at the top
    label = getIpv4Label(protocol, srcPort, dstPort);
    // Construct flow key with final label
    snprintf(flowKey, sizeof(flowKey), "%s → %s (%s)", srcIp, dstIp, label);
    // Count this flow
    stats.df.ipv4Flows[flowKey]++;
    stats.df.ipv4FlowBytes[flowKey] += payloadLen;
    stats.df.ipv4FlowBytesSqSum[flowKey] += static_cast<uint64_t>(payloadLen) * payloadLen;
    stats.df.etherTypeSummaryCounts[label]++;
    Serial.printf("🧭 IPv4 Flow: %s | +%u bytes\n", flowKey, payloadLen);
    //---Now do hostname parsing/logging---
    // DHCP Hostname
    if ((srcPort == 68 && dstPort == 67) && dns + 240 < end) {
      const uint8_t* options = dns + 240;
      while (options + 1 < end && options[0] != 255) {
        uint8_t code = options[0], len = options[1];
        if (options + 2 + len > end) break;

        if (code == 12 && len < 64) {
          char host[65] = {0};
          memcpy(host, options + 2, len);
          String taggedHost = "DHCP:" + String(host);
          stats.df.dnsHostnames.insert(taggedHost);
          snprintf(flowKey, sizeof(flowKey), "%s → %s (%s)", srcIp, dstIp, label);
          stats.df.dnsHostnamesByFlow[flowKey].insert(taggedHost);
          Serial.printf("📛 DHCP Hostname: %s\n", host);
          break;
        }
        options += 2 + len;
      }
    }

    // LLMNR Hostname
    if (srcPort == 5355 || dstPort == 5355) {
      const uint8_t* ptr = dns + 12;
      char host[128] = {0};
      size_t pos = 0;
      while (ptr < end && *ptr && pos < sizeof(host) - 2) {
        uint8_t len = *ptr++;
        if (ptr + len > end) break;
        for (uint8_t i = 0; i < len && pos < sizeof(host) - 2; ++i)
          host[pos++] = (*ptr >= 32 && *ptr <= 126) ? *ptr++ : '.';
        host[pos++] = '.';
      }
      host[pos] = '\0';
      if (pos > 1) {
        String taggedHost = "LLMR:" + String(host);
        stats.df.dnsHostnames.insert(taggedHost);
        snprintf(flowKey, sizeof(flowKey), "%s → %s (%s)", srcIp, dstIp, label);
        stats.df.dnsHostnamesByFlow[flowKey].insert(taggedHost);
        Serial.printf("🌐 LLMNR Hostname: %s\n", host);
      }
    }

    // NetBIOS Name
    if (dstPort == 137 || srcPort == 137) {
      const uint8_t* ptr = dns + 12;
      if (ptr + 1 < end && *ptr < 64) {
        char name[32] = {0};
        uint8_t len = *ptr++;
        for (uint8_t i = 0; i < len && ptr < end && i < sizeof(name) - 1; ++i)
          name[i] = (*ptr >= 32 && *ptr <= 126) ? *ptr++ : '.';
        //String taggedHost = "SOURCE: " + String(name);
        String decodedName = decodeNetbiosName(name);
        String taggedHost = "NetBIOS: " + decodedName + " [" + String(name) + "]";
        //String taggedHost = "NetBIOS: " + decodedName;
        stats.df.dnsHostnames.insert(taggedHost);
        snprintf(flowKey, sizeof(flowKey), "%s → %s (%s)", srcIp, dstIp, label);
        stats.df.dnsHostnamesByFlow[flowKey].insert(taggedHost);
        Serial.printf("📡 NetBIOS Host: %s\n", decodedName);
      }
    }

    // DNS / mDNS Hostnames
    if (dstPort == 53 || dstPort == 5353 || srcPort == 53 || srcPort == 5353) {
      bool isMdns = (dstPort == 5353 || srcPort == 5353);
      label = isMdns ? "IPv4/UDP/mDNS" : "IPv4/UDP/DNS";
      const uint8_t* base = dns;
      uint16_t qdCount = (dns[4] << 8) | dns[5];
      uint16_t anCount = (dns[6] << 8) | dns[7];
      const uint8_t* ptr = dns + 12;

      // Skip Questions
      for (int i = 0; i < qdCount && ptr < end; ++i) {
        char temp[128];
        decodeDnsName(base, ptr, end, temp, sizeof(temp));
        while (*ptr && ptr < end) ++ptr;
        ptr += 4;
      }

// Parse Answers
for (int i = 0; i < anCount && ptr + 10 < end; ++i) {
  char name[128];
  if (!decodeDnsName(base, ptr, end, name, sizeof(name))) {
    Serial.println("--------------[WARN] Failed to decode DNS name");
    break;
  }

  if (ptr + 10 > end) {
    Serial.println("-------------[WARN] DNS record too short");
    break;
  }

  uint16_t type        = (ptr[0] << 8) | ptr[1];
  uint16_t classField  = (ptr[2] << 8) | ptr[3];
  bool cacheFlush      = classField & 0x8000;
  uint16_t dnsClass    = classField & 0x7FFF;
  uint32_t ttl         = (ptr[4] << 24) | (ptr[5] << 16) | (ptr[6] << 8) | ptr[7];
  uint16_t dataLen     = (ptr[8] << 8) | ptr[9];
  ptr += 10;

  if (ptr + dataLen > end) break;

  const uint8_t* rdata = ptr;  // Safe reference to RDATA
  ptr += dataLen;              // Advance once at the bottom

  Serial.printf("---------------------[DNS] Record type = %u (%s), class = 0x%04X%s, name: %s\n",
                type, dnsTypeToString(type), classField,
                cacheFlush ? " [flush]" : "", name);

  if (type > 50 || dnsTypeToString(type) == "UNKNOWN") {
    Serial.printf("-----------------⚠️  Unknown DNS record type: %u (0x%04X), name: %s\n", type, type, name);
    hexDump(rdata, dataLen);
  }

  // 🌐 Handle known types
  if (type == 1 && dataLen == 4) {  // A Record
    char ipStr[16];
    ipToString(rdata, ipStr, sizeof(ipStr));
    Serial.printf("📥 A Record: %s → %s\n", name, ipStr);
    stats.df.ipv4Addrs.insert(ipStr);
  }
  else if (type == 12) {  // PTR Record
    char ptrName[128];
    decodeDnsName(base, rdata, end, ptrName, sizeof(ptrName));
    Serial.printf("🔁 PTR Record: %s → %s\n", name, ptrName);
    String tagged = (isMdns ? "mDNS: " : "DNS: ") + String(ptrName);
    stats.df.dnsHostnames.insert(tagged);
    snprintf(flowKey, sizeof(flowKey), "%s → %s (%s)", srcIp, dstIp, label);
    stats.df.dnsHostnamesByFlow[flowKey].insert(tagged);
  }
  else if (type == 16) {  // TXT Record
    Serial.printf("----------------📝 TXT Record: %s\n", name);
    String taggedBase = (isMdns ? "mDNS TXT: " : "DNS TXT: ") + String(name);

    const uint8_t* txt = rdata;
    const uint8_t* txtEnd = rdata + dataLen;
    if (txt == txtEnd) Serial.println("[TXT] No fields found");

    while (txt < txtEnd) {
      uint8_t len = *txt++;
      if (txt + len > txtEnd || len == 0) break;

      char field[128] = {0};
      memcpy(field, txt, len);
      field[len] = '\0';

      String taggedField = taggedBase + " → " + String(field);
      String txtKey = taggedBase + "|" + String(field);
      if (!stats.df.seenTxtKeys.count(txtKey)) {
        stats.df.seenTxtKeys.insert(txtKey);

        stats.df.dnsHostnames.insert(taggedField);
        snprintf(flowKey, sizeof(flowKey), "%s → %s (%s)", srcIp, dstIp, label);
        stats.df.dnsHostnamesByFlow[flowKey].insert(taggedField);

        Serial.printf("🔎 TXT Field: %s\n", field);
      }

      txt += len;
    }
  }
  else if (type == 28 && dataLen == 16) {  // AAAA Record
    char ip6Str[40];
    formatIPv6Short(rdata, ip6Str, sizeof(ip6Str));
    Serial.printf("🌐 AAAA Record: %s → %s\n", name, ip6Str);
    stats.df.dnsHostnames.insert((isMdns ? "mDNS AAAA: " : "DNS AAAA: ") + String(name));
    stats.df.ipv6Flows["AAAA: " + String(name) + " → " + ip6Str]++;
  }
  else if (type == 33 && dataLen >= 6) {  // SRV Record
    uint16_t priority = (rdata[0] << 8) | rdata[1];
    uint16_t weight   = (rdata[2] << 8) | rdata[3];
    uint16_t port     = (rdata[4] << 8) | rdata[5];
    const uint8_t* target = rdata + 6;

    char targetName[128];
    decodeDnsName(base, target, end, targetName, sizeof(targetName));
    Serial.printf("🛰️ SRV Record: %s → %s:%u (prio=%u w=%u)\n",
                  name, targetName, port, priority, weight);

    String hostLabel = String(isMdns ? "mDNS SRV: " : "DNS SRV: ") +
                       String(name) + " → " + String(targetName) + ":" + port;
    stats.df.dnsHostnames.insert(hostLabel);
    snprintf(flowKey, sizeof(flowKey), "%s → %s (%s)", srcIp, dstIp, label);
    stats.df.dnsHostnamesByFlow[flowKey].insert(hostLabel);
  }
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


    const char* label = getIpv4Label(protocol, srcPort, dstPort);

    snprintf(flowKey, sizeof(flowKey), "%s → %s (%s)", srcIp, dstIp, label);
    stats.df.ipv4Flows[flowKey]++;
    stats.df.ipv4FlowBytes[flowKey] += payloadLen;
    stats.df.ipv4FlowBytesSqSum[flowKey] += static_cast<uint64_t>(payloadLen) * payloadLen;
    stats.df.etherTypeSummaryCounts[label]++;
    Serial.printf("🧭 IPv4 Flow: %s | +%u bytes\n", flowKey, payloadLen);
    Serial.printf("TCP: %u → %u | Flags:", srcPort, dstPort);
    if (flags & 0x02) Serial.print(" SYN");
    if (flags & 0x10) Serial.print(" ACK");
    if (flags & 0x01) Serial.print(" FIN");
    if (flags & 0x04) Serial.print(" RST");
    if (flags & 0x08) Serial.print(" PSH");
    if (flags & 0x20) Serial.print(" URG");
    Serial.println();
  }

}

  // --------------------- IPv6 (Optimized) ---------------------
else if (etherType == 0x86DD && payloadLen >= 40) {
  const uint8_t* ip6 = payload;
  uint8_t nextHeader = ip6[6];
  uint16_t offset = 40;

  // Prepare reusable variables
  char srcIp[64], dstIp[64], flowKey[128];
  const char* label = "IPv6/Other";

  // Skip extension headers
  while ((nextHeader == 0 || nextHeader == 43 || nextHeader == 60 || nextHeader == 51 || nextHeader == 50) &&
         offset + 8 < payloadLen) {
    nextHeader = payload[offset];
    uint8_t extLen = payload[offset + 1];
    offset += 8 + extLen * 8;
  }

  // Compress IPv6 addresses
  compressIPv6RFC5952(ip6 + 8, srcIp, sizeof(srcIp));
  compressIPv6RFC5952(ip6 + 24, dstIp, sizeof(dstIp));
  bool isUDP = 0;

  // ---------------- ICMPv6 ----------------
  if (nextHeader == 58 && payloadLen >= offset + 4) {
    const uint8_t* icmp6 = payload + offset;
    uint8_t type = icmp6[0];

    if      (type == 133) label = "IPv6/ICMPv6/RS";
    else if (type == 134) label = "IPv6/ICMPv6/RA";
    else if (type == 135) label = "IPv6/ICMPv6/NS";
    else if (type == 136) label = "IPv6/ICMPv6/NA";
    else                  label = "IPv6/ICMPv6/Other";

    stats.df.icmpv6Types.insert(label);
  }

  // ---------------- TCP ----------------
  else if (nextHeader == 6 && payloadLen >= offset + 20) {
    const uint8_t* tcp = payload + offset;
    uint16_t srcPort = (tcp[0] << 8) | tcp[1];
    uint16_t dstPort = (tcp[2] << 8) | tcp[3];
    uint8_t flags = tcp[13];

    stats.df.tcpPorts.insert(srcPort);
    stats.df.tcpPorts.insert(dstPort);
    label = "IPv6/TCP";

    Serial.printf("TCP: %u → %u | Flags:", srcPort, dstPort);
    if (flags & 0x02) Serial.print(" SYN");
    if (flags & 0x10) Serial.print(" ACK");
    if (flags & 0x01) Serial.print(" FIN");
    Serial.println();
  }

  // ---------------- UDP ----------------
  else if (nextHeader == 17 && payloadLen >= offset + 8) {
    isUDP = 1;
    const uint8_t* udp = payload + offset;
    uint16_t srcPort = (udp[0] << 8) | udp[1];
    uint16_t dstPort = (udp[2] << 8) | udp[3];
    const uint8_t* dns = udp + 8;
    const uint8_t* end = payload + payloadLen;

    stats.df.udpPorts.insert(srcPort);
    stats.df.udpPorts.insert(dstPort);
    label = "IPv6/UDP";

    Serial.printf("UDP: %u → %u\n", srcPort, dstPort);

// --- DHCPv6 check ---
if ((srcPort == 546 || dstPort == 547) && dns + 4 < end) {
  Dhcpv6Info dhcpInfo = parseDhcpv6(dns, end - dns, end);
String key = dhcpInfo.msgType + "|" + dhcpInfo.mac + "|" + dhcpInfo.hostname + "|" +
             dhcpInfo.timestamp + "|" + dhcpInfo.vendor;

if (!stats.df.seenDhcpv6Keys.count(key)) {
  stats.df.seenDhcpv6Keys.insert(key);                // ✅ Mark as seen
  stats.df.dhcpv6Entries.push_back(dhcpInfo);         // ✅ Store only unique
    // Debug print
  Serial.printf("📡 DHCPv6 (parsed): %-9s | MAC: %-17s | Host: %-17s | Date: %-10s | Vendor: %s\n",
              dhcpInfo.msgType.c_str(),
              dhcpInfo.mac.c_str(),
              dhcpInfo.hostname.c_str(),
              dhcpInfo.timestamp.c_str(),
              dhcpInfo.vendor.c_str());
}



}

// -------- DNS/mDNS hostname extraction --------
if (dstPort == 5353 || srcPort == 5353) {
  label = "IPv6/UDP/mDNS";
  stats.df.etherTypeSummaryCounts[label]++;

  const uint8_t* ptr = dns + 12;
  char host[128] = {0};
  size_t hostPos = 0;

  while (ptr < end && *ptr && hostPos < sizeof(host) - 2) {
    uint8_t len = *ptr++;
    if (ptr + len > end) break;
    for (uint8_t i = 0; i < len && hostPos < sizeof(host) - 2; ++i) {
      char c = *ptr++;
      host[hostPos++] = (c >= 32 && c <= 126) ? c : '.';
    }
    host[hostPos++] = '.';
  }
  host[hostPos] = '\0';

  // 🌐 Apply placeholder for reverse lookups
  String hostname;
  if (strstr(host, ".ip6.arpa")) {
    hostname = "[flowSrc].ip6.arpa.";
    Serial.printf("🔍 Reverse mDNS abbreviated as: %s\n", hostname.c_str());
  } else {
    hostname = String(host);
    Serial.printf("🔍 mDNS Query (IPv6): %s\n", hostname.c_str());
  }

  // 🔖 Annotate flowSrc and flowDst (srcPlain / dstPlain)
  const char* srcTag = annotateIPv6(srcIp);
  const char* dstTag = annotateIPv6(dstIp);

  // Optional: add annotation directly into the flow key
  char flowKey[128];
  snprintf(flowKey, sizeof(flowKey), "%s%s → %s%s (%s)", 
         srcIp, srcTag, dstIp, dstTag, label);

  stats.df.dnsHostnames.insert(hostname);
  stats.df.dnsHostnamesByFlow[flowKey].insert(hostname);
  Serial.printf("[DEBUG] Host stored (annotated): %s → %s\n", flowKey, hostname.c_str());
}
  //if(dstPort != 5353 && srcPort != 5353){
  if(flowKey[0] == '\0'){
    snprintf(flowKey, sizeof(flowKey), "%s → %s (%s)", srcIp, dstIp, label);
  }

  }
  
  // ---------------- Flow Tracking ----------------
  //if(isUDP == 0){
  if(flowKey[0] == '\0'){
    snprintf(flowKey, sizeof(flowKey), "%s → %s (%s)", srcIp, dstIp, label);
  }
  stats.df.ipv6Flows[flowKey]++;
  stats.df.ipv6FlowBytes[flowKey] += payloadLen;
  stats.df.ipv6FlowBytesSqSum[flowKey] += static_cast<uint64_t>(payloadLen) * payloadLen;
  stats.df.etherTypeSummaryCounts[label]++;
  Serial.printf("🧭 IPv6 Flow: %s | +%u bytes\n", flowKey, payloadLen);
  // For eui-64 mac and target mac suffix parsing at end of scan in printFlowSummary
  std::array<uint8_t, 16> srcAddr;
  std::array<uint8_t, 16> dstAddr;
  memcpy(srcAddr.data(), ip6 + 8, 16);
  memcpy(dstAddr.data(), ip6 + 24, 16);
  stats.df.fullIp6SrcMap[flowKey] = srcAddr;
  stats.df.fullIp6DstMap[flowKey] = dstAddr;

}


}


/*
void parseDataFrame(const uint8_t* frame, uint16_t len, const DeviceCapture& cap) {
  if (cap.frameType != 2) return;
  bool isEncrypted = frame[1] & 0x40; // Bit 6 of byte 1 = "Protected Frame"
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
      if (isEncrypted) stats.df.encryptedUpCount++;
    } else if (cap.directionCode == DIR_AP_TO_CLIENT) {
      stats.df.qosDownCount++;
      stats.df.tidDownSum += tid;
      stats.df.tidDownSqSum += tid * tid;
      stats.df.amsduDownSum += amsdu;
      stats.df.eospDownSum += eosp;
      stats.df.qosLenDownSum += cap.length;
      stats.df.qosLenDownSqSum += cap.length * cap.length;
      if (isEncrypted) stats.df.encryptedDownCount++;
    }

    Serial.printf("🎯 QoS Control: TID = %u | A-MSDU = %s | EOSP = %s%s\n",
      tid, amsdu ? "Yes" : "No", eosp ? "Yes" : "No",
      isEncrypted ? " | 🔐 Encrypted" : "");

    if (tid >= 4 && tid < 6) Serial.println("🟡 Possibly video (TID 4-5)");
    else if (tid >= 6 && tid < 8) Serial.println("🚨 High-priority traffic (TID 6-7)");
  }

  if (isEncrypted) return;
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
  std::set<uint32_t>& suffixSet = stats.df.targetMacSuffixes;
  String srcPlain = formatIPv6(ip6 + 8, true);              // source
  String dstPlain = formatIPv6(ip6 + 24, true, &suffixSet); // destination
  //String srcPlain = formatIPv6(ip6 + 8, true);
  //String dstPlain = formatIPv6(ip6 + 24, true);
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

*/
/*
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
*/

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

//Deauth frame parsing
void parseDeauthFrame(const uint8_t* frame, uint16_t len, unsigned long now) {
  if (len < 26) return;

  uint8_t subtype = (frame[0] >> 4) & 0x0F;
  uint8_t type = (frame[0] >> 2) & 0x03;
  if (!(type == 0 && subtype == 0x0C)) return;

  const uint8_t* srcMac = frame + 10;
  const uint8_t* dstMac = frame + 4;
  const uint8_t* bssid  = frame + 16;

  bool isBroadcast = memcmp(dstMac, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) == 0;
  bool fromClient = memcmp(srcMac, bssid, 6) != 0;
  uint16_t reason = frame[24] | (frame[25] << 8);

  // Skip clean client disconnects
  if (fromClient && reason == 8) return;

  // Use a static MAC hash key (fast and compact)
  uint32_t macHash = (srcMac[2] << 24) | (srcMac[3] << 16) | (srcMac[4] << 8) | srcMac[5];

  static std::map<uint32_t, uint16_t> deauthCountBySender;
  static unsigned long lastCheck = 0;
  const uint32_t INTERVAL = 5000;
  const uint16_t THRESH = 10;

  deauthCountBySender[macHash]++;

  if (now - lastCheck > INTERVAL) {
    for (const auto& kv : deauthCountBySender) {
      if (kv.second >= THRESH) {
        uint8_t fakeMac[6] = {
          0x00, 0x00,
          (uint8_t)(kv.first >> 24),
          (uint8_t)(kv.first >> 16),
          (uint8_t)(kv.first >> 8),
          (uint8_t)(kv.first)
        };
        char mac[18];
        macToString(fakeMac, mac);
        Serial.printf("🚨 Deauth Attack Suspected: %s | Count: %u\n", mac, kv.second);  
      }
    }
    deauthCountBySender.clear();
    lastCheck = now;
  }

  // Optional: Print only summary, not every frame
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

void printMacStats() {

  Serial.println(F("\n📊 Device Summary After Scan"));
  Serial.println(F("MAC(ven)                     Combos              Cty   Pkts   LenAvg/Std   Chs    RSSImin/max  First/Last (s)"));
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
      size_t total = stats.rxMacSummaries.size();
      for (const String& entry : stats.rxMacSummaries) {
        if (count > 0) Serial.print("|");
        Serial.print(entry);
        if (++count >= 7) break;
      }
      if (total > 7) {
        Serial.printf(" | + %zu more", total - 7);
      }
      Serial.println();
    }

    if (!stats.bssidSummaries.empty()) {
      Serial.print(" → BSSID MACs: ");
      int count = 0;
      size_t total = stats.bssidSummaries.size();
      for (const String& entry : stats.bssidSummaries) {
        if (count > 0) Serial.print("|");
        Serial.print(entry);
        if (++count >= 7) break;
      }
      if (total > 7) {
        Serial.printf(" | + %zu more", total - 7);
      }
      Serial.println();
    }

    //if (!stats.rxMacSummaries.empty()) {
    //  Serial.print("    → Rx MACs: ");
    //  int count = 0;
    //  for (const String& entry : stats.rxMacSummaries) {
    //    if (count++ > 0) Serial.print("|");
    //    Serial.print(entry);
    //  }
    //  Serial.println();
    //}

    //if (!stats.bssidSummaries.empty()) {
    //  Serial.print(" → BSSID MACs: ");
    //  int count = 0;
    //  for (const String& entry : stats.bssidSummaries) {
    //    if (count++ > 0) Serial.print("|");
    //    Serial.print(entry);
    //  }
    //  Serial.println();
    //}

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

  std::vector<std::pair<String, uint32_t>> sorted(stats.df.etherTypeSummaryCounts.begin(), stats.df.etherTypeSummaryCounts.end());
  std::sort(sorted.begin(), sorted.end(),
      [](const std::pair<String, uint32_t>& a, const std::pair<String, uint32_t>& b) {
        return a.second < b.second;
      });

  int total = 0;
  for (auto& pair : sorted) total += pair.second;

  int shown = 0;
  for (auto& pair : sorted) {
    if (shown < 3 || pair.second > 1) {
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

  Serial.println();
}

// 🟢 Always attempt to print flows if they exist
if (!stats.df.ipv4Flows.empty() || !stats.df.ipv6Flows.empty()) {
  std::set<String> knownMacs = stats.rxMacSummaries;
  knownMacs.insert(stats.bssidSummaries.begin(), stats.bssidSummaries.end());

  // 📶 IPv4 Flow Summary
  if (!stats.df.ipv4Flows.empty()) {
    printFlowSummary(
      stats.df.ipv4Flows,
      stats.df.ipv4FlowBytes,
      stats.df.ipv4FlowBytesSqSum,
      stats.df.dnsHostnamesByFlow,
      knownMacs,
      {},             // No fullSrc needed for IPv4
      {},             // No fullDst needed for IPv4
      "IPv4 Flows",
      10
    );

    if (!stats.df.ssdpDevices.empty()) {
      Serial.println("📡 SSDP Devices (Port 1900):");
      for (const auto& d : stats.df.ssdpDevices) {
        Serial.printf("     📟 %s\n", d.deviceName.c_str());
        Serial.printf("        • IP       : %s\n", d.ip.c_str());
        Serial.printf("        • Server   : %s\n", d.server.c_str());
        Serial.printf("        • Location : %s\n", d.location.c_str());
        Serial.printf("        • ST       : %s\n", d.st.c_str());
        Serial.printf("        • USN      : %s\n", d.usn.c_str());
      }
    }

  }

  // 📶 IPv6 Flow Summary
  if (!stats.df.ipv6Flows.empty()) {
    printFlowSummary(
      stats.df.ipv6Flows,
      stats.df.ipv6FlowBytes,
      stats.df.ipv6FlowBytesSqSum,
      stats.df.dnsHostnamesByFlow,
      knownMacs,
      stats.df.fullIp6SrcMap,
      stats.df.fullIp6DstMap,
      "IPv6 Flows",
      10
    );
    if (!stats.df.dhcpv6Entries.empty()) {
      Serial.println("📡 DHCPv6 Messages:");
      for (const auto& d : stats.df.dhcpv6Entries) {
        Serial.printf("     %-9s | MAC: %-17s | Host: %-20s | Date: %-10s | Vendor: %s\n",
        d.msgType.c_str(), d.mac.c_str(), d.hostname.c_str(), d.timestamp.c_str(), d.vendor.c_str());
      }
    }
  }

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


/*
else if (etherType == 0x86DD && payloadLen >= 40) {
  const uint8_t* ip6 = payload;
  uint8_t nextHeader = ip6[6];
  uint16_t offset = 40;

// Optional MAC extraction from EUI-64 IPv6 address
if (isLikelyEui64(ip6 + 8)) {
  String recoveredMac = extractMacFromEUI64(ip6 + 8);
  Serial.println("🔍 EUI-64 detected. MAC reconstructed: " + recoveredMac);
  stats.df.dnsHostnames.insert("EUI64:" + recoveredMac);  // optional tagging
  // You could also save in a dedicated set like:
  // stats.df.eui64Macs.insert(recoveredMac);
}

  // Handle IPv6 extension headers
  while ((nextHeader == 0 || nextHeader == 43 || nextHeader == 60 || nextHeader == 51 || nextHeader == 50) &&
         offset + 8 < payloadLen) {
    nextHeader = payload[offset];
    uint8_t extLen = payload[offset + 1];
    offset += 8 + extLen * 8;
  }

  char srcIp[48], dstIp[48], flowKey[128], label[32] = "IPv6/Other";
  formatIPv6Compact(ip6 + 8, srcIp);
  formatIPv6Compact(ip6 + 24, dstIp);

  // --- ICMPv6 ---
  if (nextHeader == 58 && payloadLen >= offset + 4) {
    const uint8_t* icmp6 = payload + offset;
    uint8_t type = icmp6[0];

    if (type == 133) strcpy(label, "IPv6/ICMPv6/RS");
    else if (type == 134) strcpy(label, "IPv6/ICMPv6/RA");
    else if (type == 135) strcpy(label, "IPv6/ICMPv6/NS");
    else if (type == 136) strcpy(label, "IPv6/ICMPv6/NA");
    else strcpy(label, "IPv6/ICMPv6/Other");

    stats.df.icmpv6Types.insert(label);
  }

  // --- TCP ---
  else if (nextHeader == 6 && payloadLen >= offset + 20) {
    const uint8_t* tcp = payload + offset;
    uint16_t srcPort = (tcp[0] << 8) | tcp[1];
    uint16_t dstPort = (tcp[2] << 8) | tcp[3];
    uint8_t flags = tcp[13];

    stats.df.tcpPorts.insert(srcPort);
    stats.df.tcpPorts.insert(dstPort);
    strcpy(label, "IPv6/TCP");

    Serial.printf("TCP: %u → %u | Flags:", srcPort, dstPort);
    if (flags & 0x02) Serial.print(" SYN");
    if (flags & 0x10) Serial.print(" ACK");
    if (flags & 0x01) Serial.print(" FIN");
    Serial.println();
  }

  // --- UDP ---
else if (nextHeader == 17 && payloadLen >= offset + 8) {
  const uint8_t* udp = payload + offset;
  uint16_t srcPort = (udp[0] << 8) | udp[1];
  uint16_t dstPort = (udp[2] << 8) | udp[3];

  stats.df.udpPorts.insert(srcPort);
  stats.df.udpPorts.insert(dstPort);
  strcpy(label, "IPv6/UDP");

  Serial.printf("UDP: %u → %u\n", srcPort, dstPort);

  // -------- DNS/mDNS Hostname Extraction --------
  const uint8_t* dns = udp + 8;
  const uint8_t* end = payload + payloadLen;

  if (dstPort == 5353 || srcPort == 5353) {
    stats.df.etherTypeSummaryCounts["IPv6/UDP/mDNS"]++;

    const uint8_t* ptr = dns + 12;
    char host[128] = {0};
    size_t hostPos = 0;

    while (ptr < end && *ptr && hostPos < sizeof(host) - 2) {
      uint8_t len = *ptr++;
      if (ptr + len > end) break;
      for (uint8_t i = 0; i < len && hostPos < sizeof(host) - 2; ++i) {
        char c = *ptr++;
        host[hostPos++] = (c >= 32 && c <= 126) ? c : '.';
      }
      host[hostPos++] = '.';
    }
    host[hostPos] = '\0';

    if (hostPos > 1) {
      stats.df.dnsHostnames.insert(host);
      snprintf(flowKey, sizeof(flowKey), "%s → %s (%s)", srcIp, dstIp, label);
      String compressedKey = String(flowKey);
compressedKey.replace("0000:", ":");
compressedKey.replace(":0000", ":");
while (compressedKey.indexOf(":::" ) != -1) compressedKey.replace(":::", "::");
while (compressedKey.indexOf("::0:" ) != -1) compressedKey.replace("::0:", "::");
while (compressedKey.indexOf(":0:"  ) != -1) compressedKey.replace(":0:", "::");
stats.df.dnsHostnamesByFlow[compressedKey].insert(host);
      //stats.df.dnsHostnamesByFlow[flowKey].insert(host);
      Serial.printf("🔍 mDNS Query (IPv6): %s\n", host);
      Serial.printf("[DEBUG] Host stored: %s → %s\n", compressedKey, host);
    }
  }
}
  snprintf(flowKey, sizeof(flowKey), "%s → %s (%s)", srcIp, dstIp, label);
  stats.df.ipv6Flows[flowKey]++;
  stats.df.ipv6FlowBytes[flowKey] += payloadLen;
  stats.df.ipv6FlowBytesSqSum[flowKey] += static_cast<uint64_t>(payloadLen) * payloadLen;
  stats.df.etherTypeSummaryCounts[label]++;
  Serial.printf("🧭 IPv6 Flow: %s | +%u bytes\n", flowKey, payloadLen);
}

*/