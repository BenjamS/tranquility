#pragma once

#include "types.h"
#include "esp_wifi.h"

void parseGlobalItems(const wifi_promiscuous_pkt_t* ppkt, DeviceCapture& cap);
void parseDataFrame(const uint8_t* frame, uint16_t len, const DeviceCapture& cap);
String lookupVendor(const uint8_t* mac);
String classifyDestMacPurpose(const uint8_t* mac);
String extractAsciiPayloadFromDF(const uint8_t* data, uint16_t len);
void parseIpv6Icmpv6(const uint8_t* data, uint16_t len);

