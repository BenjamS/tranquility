#pragma once

#include "types.h"
#include "esp_wifi.h"
//=============================================
// Helpers
//=============================================
String abbreviateMacPurpose(const String& purpose);
void initSD();
String getScanTimestamp();
//String formatTimestamp(unsigned long ms);
String lookupVendor(const uint8_t* mac);
String classifyDestMacPurpose(const uint8_t* mac);
String extractAsciiPayloadFromDF(const uint8_t* data, uint16_t len);
String formatChannelList(uint16_t mask);
//String hexDump(const uint8_t* data, int len);
//void parseUnknownAsciiIe(uint8_t tagNumber, const uint8_t* tagData, uint8_t tagLength, String& asciiStorage);
//void printIEsDebug(const uint8_t* ieData, int ieLen);
//=============================================
// Main parsers
//=============================================
void parseGlobalItems(const wifi_promiscuous_pkt_t* ppkt, DeviceCapture& cap);
void updateMacStatsFromGlobalItems(const DeviceCapture& cap);
void parseDataFrame(const uint8_t* frame, uint16_t len, const DeviceCapture& cap);
//=============================================
// Printers
//=============================================
void debugPrintGlobalInfo(const DeviceCapture& cap);
void printGlobalMacStats();
void printGlobalFrameStats();
