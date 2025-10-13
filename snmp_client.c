#include <stdlib.h>  // pra strtol, strtof etc.
#include "snmp_client.h"
#include "snmp_lib.h"
#include "snmp_defs.h"
#include "esp_log.h"
#include "string.h"
#include "lwip/sockets.h"
#include <string.h>
#include <errno.h>
#include "../../enervision_manager/include/f_wifi.h"
#include "../../enervision_manager/include/f_configfile.h"
#include "../../enervision_manager/include/f_safefree.h"
#include "cJSON.h"
#include "snmp_sysname.h"

//#define SNMP_PORT 161
static const char *TAG = "SNMP_CLIENT";
static bool PrintDebug = false;
int InterfaceDiscovery = 0;

//#define TERMO_PPPOE "<pppoe-" // Testado com mikrotik ver como vai ser com outros.

esp_err_t f_ListInterfaces(const char *ip_address, long port, int timeout_val, int max_interfaces, const char *community) {
          in_addr_t addr = inet_addr(ip_address);
          if (addr == INADDR_NONE) {ESP_LOGE(TAG, "Invalid IP: %s", ip_address);return ESP_ERR_INVALID_ARG;}
          struct sockaddr_in dest_addr = {.sin_family = AF_INET,.sin_port = htons(port),.sin_addr.s_addr = addr};
          int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
          if (sock < 0) {ESP_LOGE(TAG, "Error creating socket: errno %d", errno);return ESP_FAIL;}
          struct timeval timeout = {.tv_sec = timeout_val,.tv_usec = 0};
          if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) { ESP_LOGE(TAG, "Erro ao configurar timeout no socket: errno %d", errno); close(sock); return ESP_FAIL; }
          ESP_LOGI(TAG, "Socket created successfully (fd=%d). Community(%s), searching for interfaces ifDescr.N until no response or reaching the maximum of %d interfaces...", sock, community, max_interfaces);
          cJSON *root = cJSON_CreateArray();
          InterfaceDiscovery = 0;

          char sysname[128] = {0};
          if (f_GetSysName(ip_address, port, timeout_val, community, sysname, sizeof(sysname))) {
                ESP_LOGI(TAG, "SNMP device: sysName = %s", sysname);
          } else {
                ESP_LOGW(TAG, "Could not obtain sysName");
          }
          for (int i = 1; i <= max_interfaces; i++) {
                    // ---------- Requisição do nome da interface ----------
                        uint8_t descr_oid[] = { 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02, (uint8_t)i };
                        uint8_t descr_req[64];
                        int descr_len = build_snmp_get(descr_req, sizeof(descr_req), descr_oid, sizeof(descr_oid), i, community);
                        if (descr_len < 0) {ESP_LOGW(TAG, "Error building SNMP packet for ifDescr.%d", i);continue;}
                        sendto(sock, descr_req, descr_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
                        uint8_t descr_resp[256];
                        socklen_t from_len = sizeof(dest_addr);
                        int len = recvfrom(sock, descr_resp, sizeof(descr_resp) - 1, 0, (struct sockaddr *)&dest_addr, &from_len);
                        if (len < 0) {
                            ESP_LOGW(TAG, "ifDescr.%d no response", i);
                            if (i == 1) { ESP_LOGE(TAG, "Device did not respond to the first interface. Ending scan."); InterfaceDiscovery = 0; break; }
                            continue;
                        }
                        char iface[128] = {0};
                        if (!parse_snmp_string_value(descr_resp, len, iface, sizeof(iface))) {continue;}

                    // ---------- Requisição do status da interface ----------
                        uint8_t status_oid[] = { 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x08, (uint8_t)i };
                        uint8_t status_req[64];
                        int status_len = build_snmp_get(status_req, sizeof(status_req), status_oid, sizeof(status_oid), 100 + i, community);
                        if (status_len < 0) {ESP_LOGW(TAG, "Error building SNMP packet for ifOperStatus.%d", i);continue;}
                        sendto(sock, status_req, status_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
                        uint8_t status_resp[256];
                        len = recvfrom(sock, status_resp, sizeof(status_resp) - 1, 0, (struct sockaddr *)&dest_addr, &from_len);
                        int oper_status = -1;
                        const char *status_str = "N/A";
                        if (len > 0 && parse_snmp_integer_value(status_resp, len, &oper_status)) {
                            status_str = f_GetOperStatusString(oper_status);
                        } else {
                            ESP_LOGW(TAG, "Failed to get status of ifDescr.%d", i);
                        }
                    // ---------- ifType ----------
                              uint8_t type_oid[] = { 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03, (uint8_t)i };
                              uint8_t type_req[64];
                              int type_len = build_snmp_get(type_req, sizeof(type_req), type_oid, sizeof(type_oid), 200 + i, community);
                              sendto(sock, type_req, type_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
                              uint8_t type_resp[256];
                              len = recvfrom(sock, type_resp, sizeof(type_resp) - 1, 0, (struct sockaddr *)&dest_addr, &from_len);
                              int if_type = -1;
                              parse_snmp_integer_value(type_resp, len, &if_type);
                    // ---------- ifSpeed ----------
                              uint8_t speed_oid[] = { 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x05, (uint8_t)i };
                              uint8_t speed_req[64];
                              int speed_len = build_snmp_get(speed_req, sizeof(speed_req), speed_oid, sizeof(speed_oid), 300 + i, community);
                              sendto(sock, speed_req, speed_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
                              uint8_t speed_resp[256];
                              len = recvfrom(sock, speed_resp, sizeof(speed_resp) - 1, 0, (struct sockaddr *)&dest_addr, &from_len);
                              //No futuro, talvez seja interessante pegar o speed
                              // uint32_t if_speed = 0;
                              // if (!parse_snmp_uint32_value(speed_resp, len, &if_speed)) {
                              //     if_speed = 0;
                              // }

                    // ---------- Exibir resultado ----------
                    char oid_readable[128] = {0};
                    strncpy(oid_readable, print_oid_readable(status_oid, sizeof(status_oid)), sizeof(oid_readable) - 1);
                    oid_readable[sizeof(oid_readable) - 1] = '\0';
                    
                    if(PrintDebug) {ESP_LOGI(TAG, "ifDescr.%d: %s (%s) - OID(%s) - Type(%d)", i, iface, status_str, oid_readable, if_type);}

                    cJSON *item = cJSON_CreateObject();
                    cJSON_AddStringToObject(item, "sysName", sysname);
                    cJSON_AddStringToObject(item, "IP", ip_address);
                    cJSON_AddNumberToObject(item, "Port", port);
                    cJSON_AddStringToObject(item, "Community", community);
                    cJSON_AddNumberToObject(item, "index", i);
                    cJSON_AddStringToObject(item, "name", iface);
                    cJSON_AddStringToObject(item, "status", status_str);
                    cJSON_AddNumberToObject(item, "type", if_type);
                    cJSON_AddItemToArray(root, item);
                    InterfaceDiscovery++;
          }
          if (InterfaceDiscovery == 0) {
                ESP_LOGW(TAG, "No interfaces found, saving basic info anyway...");
                cJSON *item = cJSON_CreateObject();
                cJSON_AddStringToObject(item, "IP", ip_address);
                cJSON_AddNumberToObject(item, "Port", port);
                cJSON_AddStringToObject(item, "Community", community);
                cJSON_AddStringToObject(item, "status", "SEM_RESPOSTA");
                cJSON_AddStringToObject(item, "name", "SNMP_EMPTY");
                cJSON_AddNumberToObject(item, "index", 0);
                cJSON_AddNumberToObject(item, "type", 0);
                cJSON_AddItemToArray(root, item);
          }
          saveJsonToFile("/config/ScanInterfaces.json", root);
          cJSON_Delete(root);
          close(sock);
          return ESP_OK;
}

int f_iDiscoveryCount() {return InterfaceDiscovery;}

esp_err_t f_GetIfOperStatusFromOID(const char *ip_address, long port, const char *oid_str, char *out_status_str, size_t max_len, const char *communit) {
          if (!ip_address || !oid_str || !out_status_str || max_len == 0) return ESP_ERR_INVALID_ARG;

          uint8_t oid[32];
          size_t oid_len = 0;
          if (!parse_oid_string(oid_str, oid, &oid_len)) {
              ESP_LOGE(TAG, "Invalid OID: %s", oid_str);
              return ESP_ERR_INVALID_ARG;
          }

          in_addr_t addr = inet_addr(ip_address);
          if (addr == INADDR_NONE) {ESP_LOGE(TAG, "Invalid IP: %s", ip_address);return ESP_ERR_INVALID_ARG;}

          struct sockaddr_in dest_addr = {
              .sin_family = AF_INET,
              .sin_port = htons(port),
              .sin_addr.s_addr = addr
          };

          int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
          if (sock < 0) {ESP_LOGE(TAG, "Error creating socket: errno %d", errno);return ESP_FAIL;}

          uint8_t request[64];
          int req_len = build_snmp_get(request, sizeof(request), oid, oid_len, 123, communit); // qualquer req_id

          sendto(sock, request, req_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

          uint8_t response[256];
          socklen_t from_len = sizeof(dest_addr);
          int len = recvfrom(sock, response, sizeof(response) - 1, 0, (struct sockaddr *)&dest_addr, &from_len);

          int oper_status = -1;
          if (len > 0 && parse_snmp_integer_value(response, len, &oper_status)) {
              const char *status = f_GetOperStatusString(oper_status);
              strncpy(out_status_str, status, max_len - 1);
              out_status_str[max_len - 1] = '\0';
              close(sock);
              return ESP_OK;
          }

          close(sock);
          return ESP_FAIL;
}

esp_err_t f_QueryIfStatusMulti(int sock, struct sockaddr_in *dest, const char **oids, size_t count, char **out_status_array, const char *community) {
    if (!sock || !dest || !oids || !out_status_array || count == 0) return ESP_ERR_INVALID_ARG;

    for (size_t i = 0; i < count; i++) {
        uint8_t oid[32];
        size_t oid_len = 0;

        if (!parse_oid_string(oids[i], oid, &oid_len)) {
            ESP_LOGW(TAG, "Invalid OID: %s", oids[i]);
            //out_status_array[i] = strdup("INVALID_OID");
            out_status_array[i] = safe_strdup("INVALID_OID");
            continue;
        }

        uint8_t req[64];
        int req_len = build_snmp_get(req, sizeof(req), oid, oid_len, 100 + i, community);

        if (req_len <= 0) {
            ESP_LOGW(TAG, "Failed to build SNMP packet for %s", oids[i]);
            //out_status_array[i] = strdup("BUILD_FAIL");
            out_status_array[i] = safe_strdup("BUILD_FAIL");
            continue;
        }

        sendto(sock, req, req_len, 0, (struct sockaddr *)dest, sizeof(*dest));

        uint8_t resp[256];
        socklen_t len = sizeof(*dest);
        int r = recvfrom(sock, resp, sizeof(resp) - 1, 0, (struct sockaddr *)dest, &len);

        int status = -1;
        if (r > 0 && parse_snmp_integer_value(resp, r, &status)) {
            const char *str = f_GetOperStatusString(status);
            //out_status_array[i] = strdup(str);
            //out_status_array[i] = strdup(str);
            out_status_array[i] = safe_strdup(str);
        } else {
            // Aqui tratamos timeout ou erro de rede
            //ESP_LOGW(TAG, "Falha ao receber resposta SNMP para OID %s (IP: %s)", oids[i], inet_ntoa(dest->sin_addr));
            //out_status_array[i] = strdup("DESCON");
            out_status_array[i] = safe_strdup("DESCON");

        }
    }

    return ESP_OK;
}

esp_err_t f_QueryTrafficMulti(int sock, struct sockaddr_in *dest, const char **oids, size_t count, uint32_t *out_values, const char *community) {
    if (!sock || !dest || !oids || !out_values || count == 0) return ESP_ERR_INVALID_ARG;

    for (size_t i = 0; i < count; i++) {
        uint8_t oid[32];
        size_t oid_len = 0;

        if (!parse_oid_string(oids[i], oid, &oid_len)) { ESP_LOGW(TAG, "Invalid OID: %s", oids[i]); out_values[i] = 0xFFFFFFFF; continue; }

        uint8_t req[64];
        int req_len = build_snmp_get(req, sizeof(req), oid, oid_len, 200 + i, community);  // ID 200+ pra evitar conflito

        if (req_len <= 0) { ESP_LOGW(TAG, "Failed to build SNMP packet for %s", oids[i]); out_values[i] = 0xFFFFFFFF; continue; }

        sendto(sock, req, req_len, 0, (struct sockaddr *)dest, sizeof(*dest));

        uint8_t resp[256];
        socklen_t len = sizeof(*dest);
        int r = recvfrom(sock, resp, sizeof(resp) - 1, 0, (struct sockaddr *)dest, &len);

        uint32_t counter = 0;
        if (r > 0 && parse_snmp_counter32_value(resp, r, &counter)) {
            out_values[i] = counter;
        } else {
            //ESP_LOGW(TAG, "Falha ao receber resposta SNMP para tráfego OID %s (IP: %s)", oids[i], inet_ntoa(dest->sin_addr));
            out_values[i] = 0xFFFFFFFF;  // Marca como erro
        }
    }

    return ESP_OK;
}
