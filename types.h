#pragma once

#include <Arduino.h>
#include <set>
#include <map>
#include <vector>

// ---------------- ENUM ----------------
enum FrameDirection : uint8_t {
  DIR_UNKNOWN = 0,
  DIR_STA_STA,
  DIR_CLIENT_TO_AP,
  DIR_AP_TO_CLIENT,
  DIR_WDS
};

enum EapolMsgType {
  EAPOL_MSG_UNKNOWN = 0,
  EAPOL_MSG_1_4,
  EAPOL_MSG_2_4,
  EAPOL_MSG_3_4,
  EAPOL_MSG_4_4,
  EAPOL_GROUP_MSG_1_2,
  EAPOL_GROUP_MSG_2_2  
};

const char* directionToStr(FrameDirection dir);

// ---------------- STRUCTS ----------------

struct Dhcpv6Info {
  String msgType;   // e.g. "SOLICIT"
  String mac;       // Parsed from DUID
  String hostname;  // FQDN if present
  String timestamp; // Parsed DUID-LLT time
  String vendor;    // Vendor Class option
};

struct FrameStatKey {
  uint8_t type;
  uint8_t subtype;
  uint8_t direction;

  bool operator<(const FrameStatKey& other) const {
    if (type != other.type) return type < other.type;
    if (subtype != other.subtype) return subtype < other.subtype;
    return direction < other.direction;
  }
};

struct wpsFingerprint {
  String deviceName;
  String modelName;
  String modNumDetail;
  String serialNumber;
  String uuid;
  String primaryDeviceType;
  String authInfo;
  String rfBand;
  uint16_t devicePasswordId = 0;
  uint16_t configMethods = 0;
  String vendorExt;
  String wpsSumFxd = "";  // generated inside parseWpsIE
  String wpsSumVar = "";  // generated inside parseWpsIE
  String shortWpsFP;
};

struct MgmtInfo {
  String ssid;
  String countryCode;
  String asciiHints;  // from unknown ASCII-looking IEs
  std::set<String> seenSsids;
  int hiddenSsidCount = 0;
  wpsFingerprint wps;
  
};

struct EapolHandshakeDetail {
  bool anonceSeen = false;
  bool snonceSeen = false;

  uint8_t anonce[32];
  uint8_t snonce[32];

  uint8_t apMac[6];
  uint8_t clientMac[6];

  String ssid;               // Optional: for WPA2-PSK decryption
  uint64_t replayCounter = 0;
};

struct SsdpDevice {
  String ip;
  String deviceName;  // parsed from ST or USN
  String server;
  String location;
  String st;
  String usn;

  // For deduplication
  bool operator<(const SsdpDevice& other) const {
    return usn < other.usn;  // or combine with IP if needed
  }
};

struct datFrameInfo {

  uint32_t qosUpCount = 0, qosDownCount = 0;
  uint64_t qosLenUpSum = 0, qosLenUpSqSum = 0;
  uint64_t qosLenDownSum = 0, qosLenDownSqSum = 0;
  uint32_t tidUpSum = 0, tidUpSqSum = 0;
  uint32_t tidDownSum = 0, tidDownSqSum = 0;
  uint32_t amsduUpSum = 0, amsduDownSum = 0;
  uint32_t eospUpSum = 0, eospDownSum = 0;
  uint32_t encryptedUpCount = 0, encryptedDownCount = 0;

  std::set<String> dnsHostnames;
  std::set<uint16_t> udpPorts;
  std::set<uint16_t> tcpPorts;
  std::set<String> ipv4Addrs;
  std::set<String> icmpv6Types;
  std::set<uint16_t> etherTypes;
  std::map<String, uint32_t> etherTypeSummaryCounts;
  std::map<String, uint32_t> ipv6Flows;  // key = "src → dst", value = count
  std::map<String, uint64_t> ipv6FlowBytes;
  std::map<String, uint32_t> ipv4Flows;
  std::map<String, uint64_t> ipv4FlowBytes;             // flow key → byte count
  std::map<String, uint64_t> ipv6FlowBytesSqSum;
  std::map<String, uint64_t> ipv4FlowBytesSqSum;
  
  std::map<String, std::set<String>> dnsHostnamesByFlow;
  std::map<String, std::array<uint8_t, 16>> fullIp6SrcMap;
  std::map<String, std::array<uint8_t, 16>> fullIp6DstMap;
  //std::map<String, String> fullIp6SrcMap;
  //std::map<String, String> fullIp6DstMap;
  // Key: "192.168.0.2 → 8.8.8.8"
  // Value: { "example.com", "google.com" }
  //std::set<uint32_t> targetMacSuffixes;  // Lower 24-bit MAC suffixes seen as targets (EUI-64 deduction)
  //std::set<String> eui64Macs;
  //std::map<String, String> eui64FlowMap;  // Map from compressed IPv6 src IP → reconstructed EUI64 MAC
  // EAPOL
  EapolHandshakeDetail handshake;
  uint16_t eapolHandshakeCounts[5] = {0};

  std::vector<Dhcpv6Info> dhcpv6Entries;
  std::set<String> seenDhcpv6Keys;
  std::set<String> seenTxtKeys;

  std::set<SsdpDevice> ssdpDevices;           // for summary
  std::set<String> seenSsdpKeys;              // for deduplication

};

struct DeviceCapture {
  uint8_t frameType;
  uint8_t subtype;
  uint16_t length;
  int8_t rssi;
  uint32_t timeSeen;
  uint16_t channelMask = 0;

  String senderMac;
  String receiverMac;
  String bssidMac;

  String srcVendor;
  String dstMacPurpose;
  String bssidVendor;

  FrameDirection directionCode = DIR_UNKNOWN;
  String directionText = "Unknown";

  //bool isEncrypted = false;

  MgmtInfo mgmtInfo;

};

struct MacStats {
  String vendor;
  uint32_t packetCount = 0;
  uint32_t firstSeen = 0, lastSeen = 0;
  int8_t rssiMin = 127, rssiMax = -128;
  uint16_t channelsSeen = 0;
  uint64_t lenSum = 0;
  uint64_t lenSqSum = 0;
  std::set<String> destMacs;
  std::map<FrameStatKey, uint32_t> frameCombos;
  std::set<String> rxMacSummaries;  // E.g., "44:65:0D(Unicast)", "33:33:00(IPv6)"
  std::set<String> bssidSummaries;
  std::set<String> asciiStrings;
  
  //Mgmt frame parsing
  //wpsFingerprint wps;
  MgmtInfo mgmt;
  //Data frame parsing
  datFrameInfo df;
};

extern std::map<String, MacStats> macStatsMap;
extern std::map<FrameStatKey, int> globalFrameStats;

struct VendorOUI {
  uint8_t prefix[3];
  const char* name;
};

const VendorOUI vendorTable[] = {
  {{0x33, 0x33, 0x00}, "mDNS6"}, //IPv6 mDNS
  {{0x01, 0x00, 0x5E}, "MC4"}, //IPv4 Multicast
  {{0xFF, 0xFF, 0xFF}, "BC"}, //Broadcast
  {{0x01, 0x80, 0xC2}, "SpanTr"}, // 01:80:C2 (Spanning Tree)
  {{0xFC, 0xFC, 0x48}, "Apple"},
  {{0x00, 0x17, 0xF2}, "Apple"},
  {{0x30, 0xE0, 0x4F}, "Apple"},
  {{0x50, 0xB1, 0x27}, "Apple"},
  {{0xD8, 0xBB, 0x2C}, "Apple"},
  {{0x90, 0x72, 0x40}, "Apple"},
  {{0x00, 0x03, 0x93}, "Apple"},
  {{0xF8, 0x42, 0x88}, "Apple"},
  {{0xA8, 0x81, 0x7E}, "Apple"}, //A8:81:7E Apple, Inc.
  {{0xC4, 0x14, 0x11}, "Apple"}, //C4:14:11 Apple, Inc.
  {{0x60, 0x0F, 0x6B}, "Apple"}, //60:0F:6B Apple, Inc.
  {{0xA4, 0xC3, 0x37}, "Apple"}, //A4:C3:37 Apple, Inc.
  {{0x30, 0x10, 0xE4}, "Apple"}, //30:10:E4 Apple, Inc.
  {{0x50, 0xDE, 0x06}, "Apple"}, //50:DE:06 Apple, Inc.
  {{0xD0, 0x6B, 0x78}, "Apple"}, //D0:6B:78 Apple, Inc.
  {{0xDC, 0xA6, 0x32}, "RaspPi"},
  {{0x00, 0x1A, 0x11}, "Google"},
  {{0x88, 0x32, 0x9B}, "SmsgTh"},
  {{0xBC, 0x8C, 0xCD}, "SmsgTh"}, // BC:8C:CD Samsung Electro-Mechanics(Thailand)
  {{0xA0, 0xD0, 0x5B}, "Smsung"},
  {{0x64, 0x1C, 0xAE}, "Smsung"},
  {{0xCC, 0x6E, 0xA4}, "Smsung"}, //Samsung Electronics Co.,Ltd
  {{0xD4, 0x11, 0xA3}, "Smsung"}, //Samsung Electronics Co.,Ltd
  {{0x1C, 0xAF, 0x4A}, "Samsng"}, //1C:AF:4A Samsung Electronics Co.,Ltd
  {{0x9C, 0x8C, 0x6E}, "Samsng"}, // 9C:8C:6E Samsung Electronics Co.,Ltd
  {{0xD8, 0x0D, 0x17}, "TpLink"},
  {{0xEC, 0x75, 0x0C}, "TpLink"},
  {{0x00, 0x1D, 0x0F}, "TpLink"},
  {{0x00, 0x31, 0x92}, "TpLink"},
  {{0x14, 0xEB, 0xB6}, "TpLink"},
  {{0x48, 0x22, 0x54}, "TpLink"},
  {{0xA8, 0x6E, 0x84}, "TPLink"}, //TP-Link Systems Inc
  {{0xA8, 0x6E, 0x84}, "TPLink"}, //TP-Link Systems Inc
  {{0xB0, 0x95, 0x75}, "TpLink"}, //Tp-Link Technologies Co.,Ltd.
  {{0x10, 0x27, 0xF5}, "TPLink"}, //TP-Link Systems Inc
  {{0x50, 0x91, 0xE3}, "TPLink"}, // 50:91:E3 TP-Link Systems Inc
  {{0xA4, 0x77, 0x33}, "Google"},
  {{0x00, 0x11, 0x22}, "CIMSYS"},
  {{0xF0, 0x9F, 0xC2}, "Ubiqui"},
  {{0x00, 0x15, 0x6D}, "Ubiqui"},
  {{0xD0, 0x21, 0xF9}, "Ubiqui"}, //D0:21:F9 Ubiquiti Inc
  {{0xFC, 0xEC, 0xDA}, "Ubiqui"}, //FC:EC:DA Ubiquiti Inc
  {{0x3C, 0x5A, 0xB4}, "Google"},
  {{0x00, 0x50, 0xF2}, "Micsft"},
  {{0x00, 0x15, 0x5D}, "Micsft"},
  {{0x00, 0x1D, 0xD8}, "Micsft"},
  {{0xAC, 0x18, 0x26}, "Cisco"},
  {{0xE4, 0x55, 0xA8}, "CiscoM"}, //E4:55:A8 Cisco Meraki
  {{0x98, 0xFC, 0x11}, "CiscoL"}, //98:FC:11 Cisco-Linksys, LLC
  {{0x70, 0xDF, 0x2F}, "Cisco"}, //70:DF:2F Cisco Systems, Inc
  {{0x00, 0xE0, 0x4C}, "Realtk"},
  {{0x00, 0x16, 0x3E}, "Xensrc"},
  {{0x00, 0x50, 0x56}, "VMware"},
  {{0x78, 0x7D, 0x53}, "ExtNet"},
  {{0x00, 0x19, 0x77}, "ExtNet"},
  {{0x4C, 0x23, 0x1A}, "ExtNet"},
  {{0x00, 0x00, 0x78}, "Labtam"},
  {{0xB0, 0x99, 0xD7}, "Samsng"},
  {{0x00, 0x37, 0x2A}, "WiFiAl"},
  {{0x50, 0x6F, 0x9A}, "WiFiAl"},
  {{0x00, 0x24, 0xE2}, "Hasgwa"},
  {{0x44, 0x3B, 0x14}, "MitStr"}, //MitraStar Technology Corp.
  {{0xCC, 0xED, 0xDC}, "MitStr"},
  {{0x44, 0x48, 0xB9}, "MitStr"},
  {{0xCC, 0xD4, 0xA1}, "MitStr"},
  {{0x2C, 0x96, 0x82}, "MitStr"},
  {{0xE4, 0xAB, 0x89}, "MtrStr"}, //E4:AB:89 MitraStar Technology Corp.
  {{0xF4, 0x6F, 0xED}, "Fibhom"},
  {{0xF8, 0x55, 0xCD}, "Viston"},
  {{0xF4, 0x95, 0x1B}, "HefeiR"},
  {{0x58, 0x9B, 0xF7}, "HefeiR"},
  {{0x14, 0x82, 0x5B}, "HefeiR"}, // 14:82:5B Hefei Radio Communication Technology Co., Ltd
  {{0x00, 0x00, 0x0F}, "Next"},
  {{0x00, 0x00, 0xDD}, "TclInc"},
  {{0x00, 0x01, 0x01}, "Privat"},
  {{0x00, 0x01, 0x02}, "3Com"},
  {{0x00, 0x01, 0x10}, "Gotham"},
  {{0x00, 0x04, 0x05}, "ACNTec"},
  {{0x00, 0x06, 0x30}, "AdtrSW"},
  {{0x00, 0x0B, 0x4A}, "VisiUK"},
  {{0x00, 0x0F, 0xAC}, "Iee802"},
  {{0x00, 0x10, 0xBC}, "Aastra"},
  {{0x00, 0x00, 0x03}, "Xerox"},
  {{0x00, 0x00, 0x27}, "JpnRad"},
  {{0x00, 0x00, 0x42}, "Metier"},
  {{0x00, 0x00, 0x7F}, "Lintyp"},
  {{0x00, 0x03, 0xA4}, "Imatin"},
  {{0x00, 0x08, 0x00}, "Multec"},
  {{0x00, 0x0C, 0x43}, "MedTek"},
  {{0x00, 0x0C, 0xE7}, "MedTek"},
  {{0x00, 0xDD, 0x07}, "UngBas"},
  {{0x00, 0x90, 0x4C}, "Epigrm"},
  {{0x00, 0x09, 0x86}, "MetaLk"},
  {{0x8C, 0xFD, 0xF0}, "Qualcm"},
  {{0x00, 0x03, 0x7F}, "Athros"},
  {{0x34, 0x21, 0x09}, "Jensen"},
  {{0xEC, 0x6C, 0x9A}, "Arcady"},
  {{0x18, 0x82, 0x8C}, "Arcady"}, //Arcadyan Corporation
  {{0xA8, 0xA2, 0x37}, "Arcady"}, //A8:A2:37 Arcadyan Corporation
  {{0x5C, 0x7B, 0x5C}, "Shenzn"},
  {{0x2C, 0xEC, 0xF7}, "Shenzn"},
  {{0xC4, 0x3C, 0xB0}, "ShenZn"}, //Shenzhen Bilian Electronic Co.，Ltd
  {{0x08, 0xAA, 0x55}, "Motrla"},
  {{0x54, 0x27, 0x58}, "Motrla"},
  {{0x00, 0xBD, 0x3E}, "Vizio"},
  {{0x8C, 0x3B, 0x4A}, "UGSICo"}, //Universal Global Scientific Industrial Co., Ltd.
  {{0x80, 0x78, 0x71}, "Askey"}, //Askey Computer Corp
  {{0xF4, 0x52, 0x46}, "Askey"}, //Askey Computer Corp
  {{0xE8, 0xD1, 0x1B}, "Askey"}, //E8:D1:1B Askey Computer Corp
  {{0x08, 0x33, 0xED}, "Askey"}, // 08:33:ED Askey Computer Corp
  {{0xC8, 0xB4, 0x22}, "Askey"}, // C8:B4:22 Askey Computer Corp
  {{0xFC, 0x12, 0x63}, "Askey"}, // FC:12:63 Askey Computer Corp
  {{0x78, 0x29, 0xED}, "Askey"}, // 78:29:ED Askey Computer Corp
  {{0xB4, 0x8C, 0x9D}, "AzureW"}, //AzureWave Tech Inc.
  {{0x90, 0xE8, 0x68}, "AzureW"}, //AzureWave Technology Inc.
  {{0xE8, 0xFB, 0x1C}, "AzureW"}, //E8:FB:1C AzureWave Technology Inc.
  {{0xF0, 0x03, 0x8C}, "AzureW"}, //F0:03:8C AzureWave Technology Inc.
  {{0x74, 0xC6, 0x3B}, "AzureW"}, // 74:C6:3B AzureWave Technology Inc.
  {{0x94, 0xBB, 0x43}, "AzureW"}, // 94:BB:43 AzureWave Technology Inc.
  {{0x90, 0xE4, 0x68}, "Guangz"}, //Guangzhou Shiyuan Electronic Technology Company Limited
  {{0xCC, 0x5E, 0xF8}, "CNeTec"}, //Cloud Network Technology Singapore Pte. Ltd.
  {{0x30, 0x03, 0xC8}, "CNeTec"}, //Cloud Network Technology Singapore Pte. Ltd.
  {{0xB4, 0xE6, 0x2A}, "LGInno"}, //LG Innotek
  {{0xA4, 0x36, 0xC7}, "LGInno"}, //LG Innotek
  {{0xD4, 0x8D, 0x26}, "LGInno"}, //LG Innotek
  {{0x40, 0x2F, 0x86}, "LGInno"},  // 40:2F:86 LG Innotek
  {{0xC8, 0x08, 0xE9}, "LGElec"}, // C8:08:E9 LG Electronics
  {{0xFC, 0x15, 0xB4}, "HP"}, //Hewlett Packard
  {{0xE4, 0x7D, 0xEB}, "ShanIT"}, //Shanghai Notion Information Technology CO.,LTD.
  {{0xAC, 0xC3, 0x58}, "CzAuto"}, //Continental Automotive Czech Republic s.r.o.
  {{0xEC, 0x6C, 0x9A}, "Arcady"}, //EC:6C:9A Arcadyan Corporation
  {{0x4C, 0x23, 0x1A}, "ExtNet"}, //Extreme Networks Headquarters
  {{0x00, 0x09, 0x0F}, "FrtNet"}, //Fortinet, Inc.
  {{0xF0, 0xD4, 0xE2}, "Dell"}, //Dell Inc.
  {{0x04, 0x79, 0x70}, "Huawei"}, //Huawei Technologies Co.,Ltd
  {{0x14, 0x77, 0x40}, "Huawei"}, // 14:77:40 Huawei Device Co., Ltd.
  {{0xA8, 0x31, 0x62}, "HHNTec"}, //Hangzhou Huacheng Network Technology Co.,Ltd
  {{0x28, 0x56, 0x3A}, "Fibhom"}, //Fiberhome Telecommunication Technologies Co.,LTD
  {{0xB4, 0x60, 0x8C}, "Fibhom"}, //B4:60:8C Fiberhome Telecommunication Technologies Co.,LTD
  {{0x70, 0xF1, 0x1C}, "ShzOge"}, //Shenzhen Ogemray Technology Co.,Ltd
  {{0xB8, 0x94, 0xE7}, "Xiaomi"}, //Xiaomi Communications Co Ltd
  {{0xDC, 0x46, 0x28}, "Intel"},
  {{0xF4, 0xA4, 0x75}, "Intel"},
  {{0xF4, 0x7B, 0x09}, "Intel"}, //Intel Corporate
  {{0x98, 0x5F, 0x41}, "Intel"}, //Intel Corporate
  {{0x04, 0xCF, 0x4B}, "Intel"}, //Intel Corporate
  {{0xF0, 0xB6, 0x1E}, "Intel"}, //F0:B6:1E Intel Corporate
  {{0xC8, 0x58, 0xC0}, "Intel"}, //C8:58:C0 Intel Corporate
  {{0x14, 0xF6, 0xD8}, "Intel"}, //14:F6:D8 Intel Corporate
  {{0x14, 0x75, 0x5B}, "Intel"}, //14:75:5B Intel Corporate
  {{0x70, 0xCD, 0x0D}, "Intel"}, //70:CD:0D Intel Corporate
  {{0x5C, 0x80, 0xB6}, "Intel"}, //5C:80:B6 Intel Corporate
  {{0xC8, 0x58, 0xC0}, "Intel"}, //C8:58:C0 Intel Corporate
  {{0xB0, 0x52, 0x16}, "HonHai"}, //Hon Hai Precision Ind. Co.,Ltd.
  {{0xB4, 0x4C, 0x3B}, "ZDahua"}, //Zhejiang Dahua Technology Co., Ltd.
  {{0xE4, 0x24, 0x6C}, "ZDahua"}, //E4:24:6C Zhejiang Dahua Technology Co., Ltd.
  {{0xC4, 0xAA, 0xC4}, "ZDahua"}, //C4:AA:C4 Zhejiang Dahua Technology Co., Ltd.
  {{0x6C, 0x22, 0x1A}, "AltoBm"}, //AltoBeam Inc.
  {{0x4C, 0x60, 0xBA}, "AltoBm"}, //4C:60:BA AltoBeam Inc.
  {{0x20, 0xF4, 0x78}, "Xiaomi"}, //20:F4:78 Xiaomi Communications Co Ltd
  {{0x7C, 0xB3, 0x7B}, "Qngdao"}, //7C:B3:7B Qingdao Intelligent&Precise Electronics Co.,Ltd.
  {{0x80, 0xCB, 0xBC}, "Qngdao"}, // 80:CB:BC Qingdao Intelligent&Precise Electronics Co.,Ltd.
  {{0x10, 0x59, 0x32}, "Roku"}, //Roku, Inc
  {{0x34, 0x21, 0x09}, "Jensen"}, //34:21:09 Jensen Scandinavia AS
  {{0xF0, 0xC8, 0x14}, "ShzBil"}, //F0:C8:14 Shenzhen Bilian Electronic Co.，Ltd
  {{0x00, 0x08, 0x22}, "InPro"}, //00:08:22 InPro Comm
  {{0x54, 0xBA, 0xD6}, "Huawei"}, //54:BA:D6 Huawei Technologies Co.,Ltd
  {{0x60, 0x23, 0xA4}, "SchnAI"}, //60:23:A4 Sichuan AI-Link Technology Co., Ltd.
  {{0x7C, 0xFC, 0x3C}, "Viston"}, //7C:FC:3C Visteon Corporation
  {{0x24, 0x46, 0xC8}, "Motrla"}, //24:46:C8 Motorola Mobility LLC, a Lenovo Company
  {{0x38, 0xF9, 0xF5}, "Garmin"}, //38:F9:F5 Garmin International
  {{0x60, 0xAB, 0x67}, "Xiaomi"}, //60:AB:67 Xiaomi Communications Co Ltd
  {{0x94, 0xEC, 0x13}, "HEzviz"}, //94:EC:13 Hangzhou Ezviz Software Co.,Ltd.
  {{0xE8, 0xA0, 0xCD}, "Nintnd"}, //E8:A0:CD Nintendo Co.,Ltd
  {{0x6C, 0x56, 0x97}, "Amazon"}, //6C:56:97 Amazon Technologies Inc.
  {{0xFC, 0xD7, 0x49}, "Amazon"}, //FC:D7:49 Amazon Technologies Inc.
  {{0x48, 0x5F, 0x2D}, "Amazon"}, //48:5F:2D Amazon Technologies Inc.
  {{0x4C, 0x53, 0xFD}, "Amazon"}, //4C:53:FD Amazon Technologies Inc.
  {{0xAC, 0x41, 0x6A}, "Amazon"}, // AC:41:6A Amazon Technologies Inc.
  {{0xD0, 0xA4, 0x6F}, "Dragon"}, //D0:A4:6F China Dragon Technology Limited
  {{0xBC, 0xFF, 0x4D}, "Esprsf"}, //BC:FF:4D Espressif Inc.
  {{0xBC, 0xDD, 0xC2}, "EspMe"}, //BC:DD:C2:CC:B5:70 Espressif Inc. (probably me)
  {{0x94, 0x04, 0xE3}, "Vantiv"}, //94:04:E3 Vantiva USA LLC
  {{0xE0, 0x37, 0x17}, "Vantiv"}, // E0:37:17 Vantiva USA LLC
  {{0x20, 0x28, 0xBC}, "Vision"}, //20:28:BC Visionscape Co,. Ltd.
  {{0x88, 0xEF, 0x16}, "Comscp"}, // 88:EF:16 Commscope
  {{0x6C, 0x63, 0x9C}, "Comscp"}, // 6C:63:9C Commscope
  {{0x80, 0x5D, 0xD4}, "Comscp"}, // B0:5D:D4 Commscope
  {{0x24, 0x18, 0xC6}, "FnLink"}, // 24:18:C6 Hunan Fn-Link Technology Limited
  {{0x30, 0x1F, 0x48}, "ZTE"},    // 30:1F:48 zte corporation
  {{0x9C, 0x95, 0x61}, "Gaoshn"}, // 9C:95:61 Hui Zhou Gaoshengda Technology Co.,LTD
  {{0xB8, 0xAB, 0x62}, "Gaoshn"}, // B8:AB:62 Hui Zhou Gaoshengda Technology Co.,LTD
  {{0x7C, 0x27, 0xBC}, "Gaoshn"}, // 7C:27:BC Hui Zhou Gaoshengda Technology Co.,LTD
  {{0x54, 0x47, 0xCC}, "Sgecom"}, // 54:47:CC Sagemcom Broadband SAS
  {{0xA8, 0x80, 0x55}, "TuyaSt"}, // A8:80:55 Tuya Smart Inc.

//  04:68:65 Apple, Inc.
//04:D6:AA Samsung Electro-Mechanics(Thailand)
//0C:6A:C4 Apple, Inc.
//30:CD:A7 Samsung Electronics Co.,Ltd
//30:F6:EF Intel Corporate
//50:8E:49 Xiaomi Communications Co Ltd
//00:05:32 Cisco Systems, Inc
//00:C3:0A Xiaomi Communications Co Ltd
//0C:6A:C4 Apple, Inc.
//0C:80:63 Tp-Link Technologies Co.,Ltd.
//98:FC:11 Cisco-Linksys, LLC
//BC:32:5F Zhejiang Dahua Technology Co., Ltd.
//FC:5F:49 Zhejiang Dahua Technology Co., Ltd.

};

const size_t vendorCount = sizeof(vendorTable) / sizeof(vendorTable[0]);