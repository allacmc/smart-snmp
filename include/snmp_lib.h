#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "cJSON.h"

int build_snmp_get(uint8_t *buffer, size_t max_len, const uint8_t *oid, size_t oid_len, uint8_t request_id, const char *community);
bool parse_snmp_integer_value(const uint8_t *buffer, int len, int *out_value);
const char *f_GetOperStatusString(int oper_status);
bool parse_oid_string(const char *oid_str, uint8_t *oid_out, size_t *oid_len_out);
char *print_oid_readable(const uint8_t *oid, size_t oid_len);
bool parse_snmp_uint32_value(const uint8_t *buffer, int len, uint32_t *out_value);
bool parse_snmp_counter32_value(const uint8_t *packet, int length, uint32_t *out_value);

void f_FormatTraffic(char *out, size_t len, float kbps);

typedef enum {
    MIB_IF_OPER_STATUS,  // .1.3.6.1.2.1.2.2.1.8
    MIB_IF_IN_OCTETS,    // .1.3.6.1.2.1.2.2.1.10
    MIB_IF_OUT_OCTETS,   // .1.3.6.1.2.1.2.2.1.16
    MIB_IF_SPEED,        // .1.3.6.1.2.1.2.2.1.5
    MIB_IF_DESCR,        // .1.3.6.1.2.1.2.2.1.2
    MIB_IF_PPPoE_List     
} MIBMetric;

const char *f_GetBaseOID(MIBMetric metric);

int build_snmp_getnext(uint8_t *buffer, size_t max_len, const uint8_t *oid, size_t oid_len, uint8_t request_id, const char *community);

bool parse_oid_from_packet(const uint8_t *packet, int len, uint8_t *out_oid, size_t *out_len);
char *print_oid_readable_from_packet(const uint8_t *packet, int len); 
void f_FormatUptime(uint32_t ticks, char *out_str, size_t out_len);
bool parse_snmp_timeticks_value(const uint8_t *packet, int length, uint32_t *out_value); 
void mergeJsonWithReindex(cJSON *destino, cJSON *origem);
uint8_t parse_snmp_value_type(const uint8_t *resp, size_t len);
