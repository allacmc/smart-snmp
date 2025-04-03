#pragma once

#include "esp_err.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"

esp_err_t f_ListInterfaces(const char *ip_address);
bool parse_snmp_string_value(const uint8_t *buffer, int len, char *out, size_t out_size);
esp_err_t f_GetIfOperStatusFromOID(const char *ip_address, const char *oid_str, char *out_status_str, size_t max_len);
esp_err_t f_QueryIfStatusMulti(int sock, struct sockaddr_in *dest, const char **oids, size_t count, char **out_status_array);
esp_err_t f_QueryTrafficMulti(int sock, struct sockaddr_in *dest, const char **oids, size_t count, uint32_t *out_values);


