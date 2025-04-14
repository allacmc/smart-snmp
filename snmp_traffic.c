#include "snmp_traffic.h"
#include "snmp_defs.h"
#include "snmp_lib.h"
#include "snmp_client.h"
#include "../../main/include/f_devices.h"
#include <string.h>
#include "esp_log.h"
#include "esp_timer.h"

//static const char *TAG = "SNMP_TRAFIC";

static TrafficHistory history[MAX_TRAFFIC_HISTORY];
static int history_count = 0;

void init_traffic_history(void) {
    history_count = 0;
    memset(history, 0, sizeof(history));
}

static TrafficHistory* get_or_create_history(const char *ip, int display) {
    for (int i = 0; i < history_count; i++) {
        if (strcmp(history[i].ip, ip) == 0 && history[i].display == display) {
            return &history[i];
        }
    }

    if (history_count < MAX_TRAFFIC_HISTORY) {
        TrafficHistory *new_entry = &history[history_count++];
        strncpy(new_entry->ip, ip, sizeof(new_entry->ip) - 1);
        new_entry->ip[sizeof(new_entry->ip) - 1] = '\0';
        new_entry->display = display;
        new_entry->last_in = 0;
        new_entry->last_out = 0;
        new_entry->last_time_ms = esp_timer_get_time() / 1000;
        return new_entry;
    }

    return NULL;
}

bool calcular_taxa_trafego(const char *ip, int display, uint32_t in_atual, uint32_t out_atual, float *out_kbps_in, float *out_kbps_out) {
        TrafficHistory *h = get_or_create_history(ip, display);
        if (!h) return false;

        int64_t agora_ms = esp_timer_get_time() / 1000;
        int64_t delta_tempo = agora_ms - h->last_time_ms;

        if (delta_tempo < 200) return false;

        uint32_t delta_in = in_atual - h->last_in;
        uint32_t delta_out = out_atual - h->last_out;

        float kbps_in = (delta_in * 8.0f) / delta_tempo;
        float kbps_out = (delta_out * 8.0f) / delta_tempo;

        if (out_kbps_in) *out_kbps_in = kbps_in;
        if (out_kbps_out) *out_kbps_out = kbps_out;

        h->last_in = in_atual;
        h->last_out = out_atual;
        h->last_time_ms = agora_ms;

        return true;
}

bool f_RegistraOIDTrafego(IPInfo *device, const char *display, int index) {
    if (!device || device->total_oids > MAX_OIDS - 2) return false;

    const char *base_in = f_GetBaseOID(MIB_IF_IN_OCTETS);
    const char *base_out = f_GetBaseOID(MIB_IF_OUT_OCTETS);

    char oid_in[64], oid_out[64];
    snprintf(oid_in, sizeof(oid_in), "%s%d", base_in, index);
    snprintf(oid_out, sizeof(oid_out), "%s%d", base_out, index);

    int idx_in = device->total_oids++;
    device->oids[idx_in].oid = strdup(oid_in);
    device->oids[idx_in].display = strdup(display);
    device->oids[idx_in].tipo = TIPO_TRAFEGO;

    int idx_out = device->total_oids++;
    device->oids[idx_out].oid = strdup(oid_out);
    device->oids[idx_out].display = strdup(display);
    device->oids[idx_out].tipo = TIPO_TRAFEGO;

    return true;
}

void f_ProcessaTrafegoSNMP(int sock, IPInfo *device, struct sockaddr_in *dest) {
    const char *oids_trafego[MAX_OIDS] = {0};
    int trafego_count = 0;
    int index_map[MAX_OIDS] = {0};

    for (int j = 0; j < device->total_oids; j++) {
        if (device->oids[j].tipo == TIPO_TRAFEGO) {
            oids_trafego[trafego_count] = device->oids[j].oid;
            index_map[trafego_count + MAX_OIDS / 2] = j;
            trafego_count++;
        }
    }

    if (trafego_count % 2 != 0) {
        ESP_LOGW("SNMP", "Quantidade ímpar de OIDs de tráfego: %d", trafego_count);
        trafego_count--; // Ou: return;
    }

    if (trafego_count == 0) return;

    uint32_t trafego_result[MAX_OIDS] = {0};
    f_QueryTrafficMulti(sock, dest, oids_trafego, trafego_count, trafego_result, device->community);

    for (int k = 0; k < trafego_count; k += 2) {
        int j_in  = index_map[k + MAX_OIDS / 2];
        int j_out = index_map[k + 1 + MAX_OIDS / 2];

        if (j_in < 0 || j_in >= device->total_oids ||
                j_out < 0 || j_out >= device->total_oids ||
                device->oids[j_in].display == NULL ||
                device->oids[j_out].display == NULL) {
                ESP_LOGW("SNMP", "OID inválido ou display NULL (j_in=%d, j_out=%d)", j_in, j_out);
                continue; // pula esse par
        }

        if (trafego_result[k] != 0xFFFFFFFF && trafego_result[k + 1] != 0xFFFFFFFF) {
            int display = atoi(device->oids[j_out].display) - 1;
            float in_kbps = 0, out_kbps = 0;
            if (calcular_taxa_trafego(device->ip, display, trafego_result[k], trafego_result[k + 1], &in_kbps, &out_kbps)) {
                trafego_info_t trafego_data = {.in_kbps = in_kbps, .out_kbps = out_kbps};
                if (display >= 0 && Device[display].xQueue != NULL && f_DeviceServico(Device[display].Servico, SNMP_Trafego)) {
                    xQueueOverwrite(Device[display].xQueue, &trafego_data);
                    xQueueOverwrite(Device[display].xQueueAlarme, &trafego_data);
                }
            }
        } else {
            int display = atoi(device->oids[j_in].display) - 1;
            if (display >= 0 && Device[display].xQueue != NULL && f_DeviceServico(Device[display].Servico, SNMP_Trafego)) {
                trafego_info_t erro_trafego = {.in_kbps = -1.0f, .out_kbps = -1.0f};
                xQueueOverwrite(Device[display].xQueue, &erro_trafego);
                xQueueOverwrite(Device[display].xQueueAlarme, &erro_trafego);
            }
        }
    }
}
