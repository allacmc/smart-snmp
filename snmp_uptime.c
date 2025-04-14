#include "snmp_uptime.h"
#include "esp_log.h"
#include "snmp_client.h"
#include "snmp_defs.h"
#include "snmp_lib.h"
#include "../../main/include/f_devices.h"
#include <string.h>
#include <stdlib.h>

#define TAG "SNMP_UPTIME"

typedef struct {
    char *ip;
    int port;
    int display;
} UptimeTarget;

#define MAX_UPTIME_TARGETS 16
static UptimeTarget uptime_targets[MAX_UPTIME_TARGETS];
static int total_uptime_targets = 0;

static bool PrintDebug = false;

int f_GetTotalUptimeTargets(void) {
    return total_uptime_targets;
}

void f_RegisterUptimeTarget(const char *ip, int port, int display) {
    if (total_uptime_targets >= MAX_UPTIME_TARGETS) return;

    uptime_targets[total_uptime_targets].ip = strdup(ip);
    uptime_targets[total_uptime_targets].port = port;
    uptime_targets[total_uptime_targets].display = display;
    total_uptime_targets++;
}

int f_GetUptimeDisplay(const char *ip, int port) {
    for (int i = 0; i < total_uptime_targets; i++) {
        if (strcmp(uptime_targets[i].ip, ip) == 0 && uptime_targets[i].port == port) {
            return uptime_targets[i].display;
        }
    }
    return -1;
}

void f_LiberaUptimeTargets(void) {
    for (int i = 0; i < total_uptime_targets; i++) {
        free(uptime_targets[i].ip);
    }
    total_uptime_targets = 0;
}



esp_err_t f_GetDeviceUptime(int sock, const char *ip_address, long port, uint32_t *out_ticks, const char *community) {
        if (f_GetTotalUptimeTargets() == 0) return ESP_FAIL; // não tem nada pra processar
        if (!ip_address || !out_ticks || sock < 0) return ESP_ERR_INVALID_ARG;

        struct sockaddr_in dest = {
            .sin_family = AF_INET,
            .sin_port = htons(port),
            .sin_addr.s_addr = inet_addr(ip_address)
        };

        const char *OID_UPTIME = "1.3.6.1.2.1.1.3.0";
        uint8_t oid[32];
        size_t oid_len = 0;

        if (!parse_oid_string(OID_UPTIME, oid, &oid_len)) {
            ESP_LOGE(TAG, "OID de uptime inválido");
            return ESP_FAIL;
        }

        uint8_t req[64], resp[256];
        int req_len = build_snmp_get(req, sizeof(req), oid, oid_len, 0x11, community);
        sendto(sock, req, req_len, 0, (struct sockaddr *)&dest, sizeof(dest));

        socklen_t from_len = sizeof(dest);
        int r = recvfrom(sock, resp, sizeof(resp) - 1, 0, (struct sockaddr *)&dest, &from_len);
        if (r <= 0) {
            if(PrintDebug){ESP_LOGE(TAG, "Sem resposta SNMP para uptime");}
            return ESP_FAIL;
        }

        uint32_t ticks = 0;
        if (!parse_snmp_timeticks_value(resp, r, &ticks)) {
            ESP_LOGE(TAG, "Falha ao extrair uptime (TimeTicks)");
            //ESP_LOG_BUFFER_HEXDUMP("SNMP_UPTIME", resp, r, ESP_LOG_INFO);
            return ESP_FAIL;
        }

        *out_ticks = ticks;
        return ESP_OK;
}

void f_ProcessaUptimeSNMP(int sock, const char *ip, int port, struct sockaddr_in *dest, const char *community) {
    int display = f_GetUptimeDisplay(ip, port) - 1;
    if (display < 0) return;

    uint32_t ticks = 0;
    if (f_GetDeviceUptime(sock, ip, port, &ticks, community) != ESP_OK) {
        if(PrintDebug){ESP_LOGE(TAG, "Falha ao consultar uptime de %s:%d", ip, port);}
        uint32_t erro_uptime = 0xFFFFFFFF;
        if (Device[display].xQueue != NULL && f_DeviceServico(Device[display].Servico, SNMP_Uptime)) {
            xQueueOverwrite(Device[display].xQueue, &erro_uptime);
            xQueueOverwrite(Device[display].xQueueAlarme, &erro_uptime);
        }
        return;
    }

    char uptime_str[64];
    f_FormatUptime(ticks, uptime_str, sizeof(uptime_str));
    if(PrintDebug){ESP_LOGI(TAG, "[UPTIME_SEND] Enviado ticks %lu para display %d (%s)", ticks, display, uptime_str);}
    if (Device[display].xQueue != NULL && f_DeviceServico(Device[display].Servico, SNMP_Uptime)) {
        xQueueOverwrite(Device[display].xQueue, &ticks);
        xQueueOverwrite(Device[display].xQueueAlarme, &ticks);
    }
}
