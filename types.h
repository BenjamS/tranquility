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

const char* directionToStr(FrameDirection dir);

// ---------------- STRUCTS ----------------
struct DeviceCapture {
  uint8_t frameType;
  uint8_t subtype;
  uint16_t length;
  int8_t rssi;
  uint32_t timeSeen;
  uint8_t channelMask = 0;

  String senderMac;
  String receiverMac;
  String bssidMac;

  String srcVendor;
  String dstMacPurpose;
  String bssidVendor;

  FrameDirection directionCode = DIR_UNKNOWN;
  String directionText = "Unknown";

  bool isEncrypted = false;
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

struct MacStats {
  uint32_t totalDataFrames = 0;
  uint64_t lenSum = 0;
  uint64_t lenSqSum = 0;
  std::set<String> destMacs;
  std::map<String, uint32_t> otherCombos;
  std::set<uint16_t> etherTypes;

  uint32_t qosUpCount = 0, qosDownCount = 0;
  uint64_t qosLenUpSum = 0, qosLenUpSqSum = 0;
  uint64_t qosLenDownSum = 0, qosLenDownSqSum = 0;
  uint32_t tidUpSum = 0, tidUpSqSum = 0;
  uint32_t tidDownSum = 0, tidDownSqSum = 0;
  uint32_t amsduUpSum = 0, amsduDownSum = 0;
  uint32_t eospUpSum = 0, eospDownSum = 0;
  uint32_t encryptedUpCount = 0, encryptedDownCount = 0;

  uint32_t dnsCount = 0;
  uint32_t mdnsCount = 0;
  std::set<String> dnsHostnames;

  std::set<uint16_t> udpPorts;
  std::set<uint16_t> tcpPorts;
  std::set<String> ipv4Addrs;
  std::set<String> ipv6Addrs;
  std::set<String> icmpv6Types;

  std::set<String> asciiStrings;
};

extern std::map<String, MacStats> macStatsMap;
extern std::map<FrameStatKey, int> globalFrameStats;

