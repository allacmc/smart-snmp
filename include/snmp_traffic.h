#ifndef SNMP_TRAFFIC_H
#define SNMP_TRAFFIC_H

#include <stdint.h>
#include <stdbool.h>
#include "lwip/sockets.h"
#include "snmp_defs.h"

#define MAX_TRAFFIC_HISTORY 64

typedef struct {
    char ip[32];
    int display;
    uint32_t last_in;
    uint32_t last_out;
    int64_t last_time_ms;
} TrafficHistory;

// Inicializa (zera) o histórico
void init_traffic_history(void);

// Calcula e loga a taxa de tráfego

bool calcular_taxa_trafego(const char *ip, int display, uint32_t in_atual, uint32_t out_atual, float *out_kbps_in, float *out_kbps_out);
void f_ProcessaTrafegoSNMP(int sock, IPInfo *device, struct sockaddr_in *dest);
bool f_RegistraOIDTrafego(IPInfo *device, const char *display, int index);


#endif // SNMP_TRAFFIC_H
