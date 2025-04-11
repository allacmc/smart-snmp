#include "snmp_lib.h"
#include "../../main/include/f_devices.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "lwip/sockets.h"
#include "snmp_defs.h"
#include "snmp_client.h"

bool f_RegistraOIDStatusInterface(IPInfo *device, const char *display, int index) {
    if (!device || device->total_oids >= MAX_OIDS - 1) return false;

    const char *base_oid = f_GetBaseOID(MIB_IF_OPER_STATUS);

    char oid_str[64];
    snprintf(oid_str, sizeof(oid_str), "%s%d", base_oid, index);

    int idx = device->total_oids++;
    device->oids[idx].oid = strdup(oid_str);
    device->oids[idx].display = strdup(display);
    device->oids[idx].tipo = TIPO_INTERFACE;

    return true;
}

void f_ProcessaStatusInterface(int sock, IPInfo *device, struct sockaddr_in *dest) {
    const char *oids_status[MAX_OIDS] = {0};
    int status_count = 0;
    int index_map[MAX_OIDS] = {0};

    for (int j = 0; j < device->total_oids; j++) {
        if (device->oids[j].tipo == TIPO_INTERFACE) {
            oids_status[status_count] = device->oids[j].oid;
            index_map[status_count++] = j;
        }
    }

    if (status_count == 0) return;

    char *status_result[MAX_OIDS] = {0};
    f_QueryIfStatusMulti(sock, dest, oids_status, status_count, status_result, device->community);

    for (int k = 0; k < status_count; k++) {
        int j = index_map[k];
        int display = atoi(device->oids[j].display) - 1;
        if (display >= 0 && Device[display].xQueue != NULL && f_DeviceServico(Device[display].Servico, SNMP_Interface)) {
            xQueueOverwrite(Device[display].xQueue, &status_result[k]);
            xQueueOverwrite(Device[display].xQueueAlarme, &status_result[k]);
        }
    }
}