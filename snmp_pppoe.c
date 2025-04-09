#include "snmp_pppoe.h"
#include "esp_log.h"
#include <string.h>
#include <stdlib.h>
#include "../../main/include/f_devices.h"
#include "snmp_client.h"
#include "snmp_lib.h"
#include "snmp_defs.h"

#define TAG "SNMP_PPPOE"

#define TERMO_PPPOE "<pppoe-" // Testado com mikrotik ver como vai ser com outros.

typedef struct {
    char *ip;
    int port;
    int display;
} PPPoETarget;

#define MAX_PPPOE_TARGETS 16
static PPPoETarget pppoe_targets[MAX_PPPOE_TARGETS];
static int total_pppoe_targets = 0;

void f_RegisterPPPoETarget(const char *ip, int port, int display) {
    if (total_pppoe_targets >= MAX_PPPOE_TARGETS) return;

    pppoe_targets[total_pppoe_targets].ip = strdup(ip);
    pppoe_targets[total_pppoe_targets].port = port;
    pppoe_targets[total_pppoe_targets].display = display;
    total_pppoe_targets++;
}

int f_GetPPPoEDisplay(const char *ip, int port) {
    for (int i = 0; i < total_pppoe_targets; i++) {
        if (strcmp(pppoe_targets[i].ip, ip) == 0 && pppoe_targets[i].port == port) {
            return pppoe_targets[i].display;
        }
    }
    return -1;
}

bool f_IsPPPoETarget(const char *ip, int port) {
    for (int i = 0; i < total_pppoe_targets; i++) {
        if (strcmp(pppoe_targets[i].ip, ip) == 0 && pppoe_targets[i].port == port) {
            return true;
        }
    }
    return false;
}

void f_LiberaPPPoETargets(void) {
    for (int i = 0; i < total_pppoe_targets; i++) {
        free(pppoe_targets[i].ip);
    }
    total_pppoe_targets = 0;
}

int16_t f_PPPoECount(int sock, struct sockaddr_in *dest) {
    int16_t total_pppoe = 0;
    uint8_t req[64], resp[256];
    socklen_t from_len = sizeof(*dest);

    uint8_t current_oid[32];
    size_t current_oid_len = 0;

    parse_oid_string("1.3.6.1.2.1.2.2.1.2", current_oid, &current_oid_len);

    uint8_t req_id = 0x20;
    int max_seguro = 8192;  // ← segurança contra loop infinito
    int iteracoes = 0;
    while (true) {
        if (iteracoes++ > max_seguro) { ESP_LOGW("SNMP_PPP", "Loop SNMP interrompido após %d iterações (proteção de segurança)", max_seguro); total_pppoe = -1; break; }
        int req_len = build_snmp_getnext(req, sizeof(req), current_oid, current_oid_len, req_id++);
        if (req_len <= 0) { ESP_LOGW("SNMP_PPP", "Falha ao montar GETNEXT"); total_pppoe = -1; break; }
        bool resposta_ok = false;
        int r = 0;
        for (int tentativa = 0; tentativa < 4 && !resposta_ok; tentativa++) {
                sendto(sock, req, req_len, 0, (struct sockaddr *)dest, sizeof(*dest));
                r = recvfrom(sock, resp, sizeof(resp) - 1, 0, (struct sockaddr *)dest, &from_len);
                if (r > 0) {
                    resposta_ok = true;
                    break;
                } else {
                    vTaskDelay(pdMS_TO_TICKS(10));
                }
        }
        if (!resposta_ok) { total_pppoe = -1; break; }
        char *oid_str = print_oid_readable_from_packet(resp, r);
        if (!oid_str) { ESP_LOGW("SNMP_PPP", "OID retornado é NULL, encerrando."); ESP_LOG_BUFFER_HEXDUMP("SNMP_RAW", resp, r, ESP_LOG_WARN); break; }
        if (strncmp(oid_str, "1.3.6.1.2.1.2.2.1.2", 19) != 0) break;
        char iface_name[128] = {0};
        if (parse_snmp_string_value(resp, r, iface_name, sizeof(iface_name))) {
            if (strcasestr(iface_name, TERMO_PPPOE)) {
                total_pppoe++;
            }
        } else {
            ESP_LOGW("SNMP_PPP", "Falha ao extrair ifDescr");
            ESP_LOG_BUFFER_HEXDUMP("SNMP_RAW", resp, r, ESP_LOG_WARN);
        }

        size_t next_oid_len = 0;
        if (!parse_oid_from_packet(resp, r, current_oid, &next_oid_len)) {
            ESP_LOGW("SNMP_PPP", "Falha ao extrair próximo OID");
            break;
        }
        current_oid_len = next_oid_len;
    }

    return total_pppoe;
}

void f_ProcessaPPPoECount(int sock, const char *ip, int port, struct sockaddr_in *dest) {
    int display = f_GetPPPoEDisplay(ip, port) - 1;
    if (display < 0) return;

    int16_t pppoe_total = f_PPPoECount(sock, dest);
    if (Device[display].xQueue != NULL && f_DeviceServico(Device[display].Servico, SNMP_PPPoE_Count)) {
        xQueueOverwrite(Device[display].xQueue, &pppoe_total);
        xQueueOverwrite(Device[display].xQueueAlarme, &pppoe_total);
        //ESP_LOGI(TAG, "PPPoE %s:%d → %d", ip, port, pppoe_total);
    } else {
        ESP_LOGW(TAG, "Dispositivo %s:%d (Display %d) não possui fila para PPPoE", ip, port, display + 1);
    }
}
