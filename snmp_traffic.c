#include "snmp_traffic.h"
#include <string.h>
#include "esp_log.h"
#include "esp_timer.h"

static const char *TAG = "SNMP_TRAFIC";

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
