#pragma once

#include "types.h"
#include "esp_wifi.h"
//=============================================
// Helpers
//=============================================
const char* directionToStr(FrameDirection dir);
void addSsidToStats(MacStats& stats, const String& ssid);
void parseUnknownAsciiIe(uint8_t tagId, const uint8_t* tagData, uint8_t tagLen, String& output);
//void parseUnknownAsciiIe(uint8_t tagNumber, const uint8_t* tagData, uint8_t tagLength, String& asciiStorage);
String extractSsid(const uint8_t* payload, int len);
String abbreviateMacPurpose(const String& purpose);
void initSD();
String getScanTimestamp();
//String formatTimestamp(unsigned long ms);
String lookupVendor(const uint8_t* mac);
String classifyDestMacPurpose(const uint8_t* mac);
String extractAsciiPayloadFromDF(const uint8_t* data, uint16_t len);
String formatChannelList(uint16_t mask);
//=============================================
// Main parsers
//=============================================
void parseGlobalItems(const wifi_promiscuous_pkt_t* ppkt, DeviceCapture& cap);
void updateMacStatsFromGlobalItems(const DeviceCapture& cap);
void parseDataFrame(const uint8_t* frame, uint16_t len, const DeviceCapture& cap);
void parseMgmtIEs(const uint8_t* data, uint16_t len, DeviceCapture& cap);
void parseMgmtFrame(const uint8_t* frame, uint16_t len, DeviceCapture& cap);
wpsFingerprint parseWpsIE(const uint8_t* data, int len);
//=============================================
// Printers
//=============================================
void debugPrintGlobalInfo(const DeviceCapture& cap);
void printGlobalMacStats();
void printGlobalFrameStats();
void printIEsDebug(const uint8_t* ieData, int ieLen);
void hexDump(const uint8_t* data, int len);
