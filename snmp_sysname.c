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


static const char *TAG = "SNMP_SYSNAME";


bool f_GetSysName(const char *ip_address, long port, int timeout_val, const char *community, char *out_sysname, size_t max_len) {
            in_addr_t addr = inet_addr(ip_address);
            if (addr == INADDR_NONE) {
                ESP_LOGE(TAG, "IP inválido em f_GetSysName: %s", ip_address);
                return false;
            }

            struct sockaddr_in dest_addr = {
                .sin_family = AF_INET,
                .sin_port = htons(port),
                .sin_addr.s_addr = addr
            };

            int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (sock < 0) {
                ESP_LOGE(TAG, "Erro ao criar socket em f_GetSysName: errno %d", errno);
                return false;
            }

            struct timeval timeout = { .tv_sec = timeout_val, .tv_usec = 0 };
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

            // OID do sysName: 1.3.6.1.2.1.1.5.0
            uint8_t sysname_oid[] = { 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00 };
            uint8_t req[64];
            int req_len = build_snmp_get(req, sizeof(req), sysname_oid, sizeof(sysname_oid), 9999, community);
            if (req_len < 0) {
                ESP_LOGE(TAG, "Falha ao montar pacote SNMP para sysName");
                close(sock);
                return false;
            }

            if (sendto(sock, req, req_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
                ESP_LOGW(TAG, "Falha ao enviar sysName para %s:%ld", ip_address, port);
                close(sock);
                return false;
            }

            uint8_t resp[256];
            socklen_t from_len = sizeof(dest_addr);
            int len = recvfrom(sock, resp, sizeof(resp) - 1, 0, (struct sockaddr *)&dest_addr, &from_len);
            close(sock);

            if (len < 0) {
                ESP_LOGW(TAG, "Sem resposta para sysName de %s", ip_address);
                return false;
            }

            if (!parse_snmp_string_value(resp, len, out_sysname, max_len)) {
                ESP_LOGW(TAG, "Falha ao parsear sysName");
                return false;
            }

            return true;
}
