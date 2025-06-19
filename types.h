#pragma once

#include <Arduino.h>
#include <set>
#include <map>

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
  EAPOL_MSG_4_4
};

const char* directionToStr(FrameDirection dir);

// ---------------- STRUCTS ----------------

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
  // Key: "192.168.0.2 → 8.8.8.8"
  // Value: { "example.com", "google.com" }
  std::set<uint32_t> targetMacSuffixes;  // Lower 24-bit MAC suffixes seen as targets (EUI-64 deduction)
  // EAPOL
  EapolHandshakeDetail handshake;
  uint16_t eapolHandshakeCounts[5] = {0};
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
  {{0xFC, 0xFC, 0x48}, "Apple"},
  {{0x00, 0x17, 0xF2}, "Apple"},
  {{0x30, 0xE0, 0x4F}, "Apple"},
  {{0x50, 0xB1, 0x27}, "Apple"},
  {{0xD8, 0xBB, 0x2C}, "Apple"},
  {{0x90, 0x72, 0x40}, "Apple"},
  {{0x00, 0x03, 0x93}, "Apple"},
  {{0xF8, 0x42, 0x88}, "Apple"},
  {{0xDC, 0xA6, 0x32}, "RaspPi"},
  {{0x00, 0x1A, 0x11}, "Google"},
  {{0x88, 0x32, 0x9B}, "SmsgTh"},
  {{0xA0, 0xD0, 0x5B}, "Smsung"},
  {{0x64, 0x1C, 0xAE}, "Smsung"},
  {{0xD8, 0x0D, 0x17}, "TpLink"},
  {{0xEC, 0x75, 0x0C}, "TpLink"},
  {{0x00, 0x1D, 0x0F}, "TpLink"},
  {{0x00, 0x31, 0x92}, "TpLink"},
  {{0x14, 0xEB, 0xB6}, "TpLink"},
  {{0x48, 0x22, 0x54}, "TpLink"},
  {{0xA4, 0x77, 0x33}, "Google"},
  {{0x00, 0x11, 0x22}, "CIMSYS"},
  {{0xF0, 0x9F, 0xC2}, "Ubiqui"},
  {{0x00, 0x15, 0x6D}, "Ubiqui"},
  {{0x3C, 0x5A, 0xB4}, "Google"},
  {{0x00, 0x50, 0xF2}, "Micsft"},
  {{0x00, 0x15, 0x5D}, "Micsft"},
  {{0x00, 0x1D, 0xD8}, "Micsft"},
  {{0xAC, 0x18, 0x26}, "Cisco"},
  {{0x00, 0xE0, 0x4C}, "Realtk"},
  {{0x00, 0x16, 0x3E}, "Xensrc"},
  {{0x00, 0x50, 0x56}, "VMware"},
  {{0x78, 0x7D, 0x53}, "ExtNet"},
  {{0x00, 0x19, 0x77}, "ExtNet"},
  {{0x4C, 0x23, 0x1A}, "ExtNet"},
  {{0x00, 0x00, 0x78}, "Labtam"},
  {{0xB0, 0x99, 0xD7}, "Samsng"},
  {{0xDC, 0x46, 0x28}, "Intel"},
  {{0xF4, 0xA4, 0x75}, "Intel"},
  {{0x00, 0x37, 0x2A}, "WiFiAl"},
  {{0x50, 0x6F, 0x9A}, "WiFiAl"},
  {{0x00, 0x24, 0xE2}, "Hasgwa"},
  {{0x44, 0x3B, 0x14}, "MitStr"}, //MitraStar Technology Corp.
  {{0xCC, 0xED, 0xDC}, "MitStr"},
  {{0x44, 0x48, 0xB9}, "MitStr"},
  {{0xCC, 0xD4, 0xA1}, "MitStr"},
  {{0x2C, 0x96, 0x82}, "MitStr"},
  {{0xF4, 0x6F, 0xED}, "Fibhom"},
  {{0xF8, 0x55, 0xCD}, "Viston"},
  {{0xF4, 0x95, 0x1B}, "HefeiR"},
  {{0x58, 0x9B, 0xF7}, "HefeiR"},
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
  {{0x5C, 0x7B, 0x5C}, "Shenzn"},
  {{0x2C, 0xEC, 0xF7}, "Shenzn"},
  {{0x08, 0xAA, 0x55}, "Motrla"},
  {{0x54, 0x27, 0x58}, "Motrla"},
  {{0x00, 0xBD, 0x3E}, "Vizio"},
  {{0x8C, 0x3B, 0x4A}, "UGSICo"}, //Universal Global Scientific Industrial Co., Ltd.
  {{0x80, 0x78, 0x71}, "Askey"}, //Askey Computer Corp
  {{0xF4, 0x52, 0x46}, "Askey"}, //Askey Computer Corp
  {{0xB4, 0x8C, 0x9D}, "Azure"}, //AzureWave Tech Inc.
  {{0x90, 0xE4, 0x68}, "Guangz"}, //Guangzhou Shiyuan Electronic Technology Company Limited
  {{0xCC, 0x5E, 0xF8}, "CNeTec"}, //Cloud Network Technology Singapore Pte. Ltd.
  {{0x30, 0x03, 0xC8}, "CNeTec"}, //Cloud Network Technology Singapore Pte. Ltd.
  {{0xB4, 0xE6, 0x2A}, "LGInno"}, //LG Innotek
  {{0xFC, 0x15, 0xB4}, "LGInno"}, //Hewlett Packard
  {{0xE4, 0x7D, 0xEB}, "ShanIT"}, //Shanghai Notion Information Technology CO.,LTD.
  {{0xAC, 0xC3, 0x58}, "CzAuto"}, //Continental Automotive Czech Republic s.r.o.
  {{0xEC, 0x6C, 0x9A}, "Arcady"}, //EC:6C:9A Arcadyan Corporation
  {{0x4C, 0x23, 0x1A}, "ExtNet"}, //Extreme Networks Headquarters
  {{0x00, 0x09, 0x0F}, "FrtNet"}, //Fortinet, Inc.
  {{0xF0, 0xD4, 0xE2}, "Dell"}, //Dell Inc.
  {{0x04, 0x79, 0x70}, "Huawei"}, //Huawei Technologies Co.,Ltd
  {{0xA8, 0x31, 0x62}, "HHNTec"}, //Hangzhou Huacheng Network Technology Co.,Ltd
  {{0x28, 0x56, 0x3A}, "Fibhom"}, //Fiberhome Telecommunication Technologies Co.,LTD
  {{0x10, 0x27, 0xF5}, "TPLink"}, //TP-Link Systems Inc
  {{0x70, 0xF1, 0x1C}, "ShenOg"}, //Shenzhen Ogemray Technology Co.,Ltd
  {{0xB8, 0x94, 0xE7}, "Xiaomi"}, //Xiaomi Communications Co Ltd

};

const size_t vendorCount = sizeof(vendorTable) / sizeof(vendorTable[0]);