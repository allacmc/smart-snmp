#ifndef SNMP_READ_INTERFACE_H
#define SNMP_READ_INTERFACE_H

#include "cJSON.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_log.h"
#include "string.h"
#include "stdio.h"
#include "stdlib.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/inet.h"

#include "snmp_defs.h"  // supondo que você tem as structs TipoSelecionado, IPInfo etc.

int f_PopulaDispositivos(IPInfo *dispositivos, int max_dispositivos);
void f_ExecutaLeituraSNMP(IPInfo *dispositivos, int total_ips, bool PrintDebug);
void f_LiberaDispositivos(IPInfo *dispositivos, int total_ips);
void f_stopReadInterfaces();
int f_BuscaIndiceIP(IPInfo *dispositivos, int total, const char *ip);
// bool f_IsPPPoETarget(const char *ip, int port);
// int f_GetPPPoEDisplay(const char *ip, int port);
// int f_GetUptimeDisplay(const char *ip, int port);

// ================================
// Helpers (internal)
// ================================
typedef enum {
    ROW_KIND_INTERFACE = 0,
    ROW_KIND_TRAFEGO,
    ROW_KIND_PPPOE_LEGACY,
    ROW_KIND_PPPOE_OID_MIKROTIK,
    ROW_KIND_PPPOE_OID_HUAWEI,
    ROW_KIND_UPTIME,
    ROW_KIND_CUSTOM
} snmp_row_kind_t;

typedef struct {
    char idx_str[8];

    const char *ip;
    int port;
    const char *community;

    const char *display_str;
    int display_num;

    const char *tipo_str;

    int index; // index[...], usado para interface/trafego (pode ser -1)

    // Custom opcionais
    const char *oper;
    const char *operfact;
    const char *suffix;
    const char *custom_oid;
} snmp_row_t;

void f_setPrintDebugSNMP_ReadInterface(bool debug);


#endif // SNMP_READ_INTERFACE_H
