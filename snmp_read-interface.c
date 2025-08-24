#include "snmp_read-interface.h"
#include "snmp_lib.h"  // Aqui devem estar funções como f_GetBaseOID, f_QueryIfStatusMulti etc.
#include "../../enervision_manager/include/f_configfile.h"
#include "../../enervision_manager/include/f_safefree.h"
#include "../../main/include/f_devices.h"
#include "snmp_client.h"
#include "snmp_traffic.h"
#include "snmp_uptime.h"
#include "snmp_pppoe.h"
#include "snmp_custom.h"
#include "snmp_status-interface.h"

#define TAG "SNMP_CLIENT"
bool StopReadInterface = false;
//static bool PrintDebug = false;

int f_PopulaDispositivos(IPInfo *dispositivos, int max_dispositivos) {
        StopReadInterface = false;
        cJSON *json = read_json_file("/config/snmp-interface-select.json");
        if (!json) return -1;

        int total_ips = 0;

        cJSON *item = NULL;
        cJSON_ArrayForEach(item, json) {
                const char *key = item->string;
                if (strncmp(key, "IP[", 3) != 0) continue;

                char idx_str[8];
                sscanf(key, "IP[%[^]]", idx_str);

                char ip_key[16], index_key[24], disp_key[40], tipo_key[40], oper_key[40], operFact_key[40], suffix_key[40];
                snprintf(ip_key, sizeof(ip_key), "IP[%s]", idx_str);
                snprintf(index_key, sizeof(index_key), "index[%s]", idx_str);
                snprintf(disp_key, sizeof(disp_key), "displaySelecionado[%s]", idx_str);
                snprintf(tipo_key, sizeof(tipo_key), "tipoSelecionado[%s]", idx_str);
                snprintf(oper_key, sizeof(oper_key), "operationType[%s]", idx_str);
                snprintf(operFact_key, sizeof(operFact_key), "operationFactor[%s]", idx_str);
                snprintf(suffix_key, sizeof(suffix_key), "unitSuffix[%s]", idx_str);

                char port_key[24];
                char comm_key[24];
                snprintf(comm_key, sizeof(comm_key), "community[%s]", idx_str);
                cJSON *comm_node = cJSON_GetObjectItem(json, comm_key);

                snprintf(port_key, sizeof(port_key), "Port[%s]", idx_str);
                cJSON *port_node = cJSON_GetObjectItem(json, port_key);

                cJSON *ip_node = cJSON_GetObjectItem(json, ip_key);
                cJSON *idx_node = cJSON_GetObjectItem(json, index_key);
                cJSON *disp_node = cJSON_GetObjectItem(json, disp_key);
                cJSON *tipo_node = cJSON_GetObjectItem(json, tipo_key);
                cJSON *oper_node = cJSON_GetObjectItem(json, oper_key);
                cJSON *operFact_node = cJSON_GetObjectItem(json, operFact_key);
                cJSON *suffix_node = cJSON_GetObjectItem(json, suffix_key);


                if (!ip_node || !idx_node || !disp_node || !tipo_node || !port_node || !comm_node) continue;
                if (!cJSON_IsString(ip_node)   || !cJSON_IsString(idx_node) ||
                    !cJSON_IsString(disp_node) || !cJSON_IsString(tipo_node) ||
                    !cJSON_IsString(port_node) || !cJSON_IsString(comm_node)
                ) continue;

                const char *ip = ip_node->valuestring;
                int index = atoi(idx_node->valuestring);
                const char *display = disp_node->valuestring;

                TipoSelecionado tipo;
                bool is_pppoe_count = false;
                bool is_uptime = false;
                bool is_custom = false;

                if (strcasecmp(tipo_node->valuestring, "Trafego") == 0) {
                    tipo = TIPO_TRAFEGO;
                } else if (strcasecmp(tipo_node->valuestring, "PPPoE-Count") == 0) {
                    tipo = TIPO_INTERFACE;
                    is_pppoe_count = true;
                } else if (strcasecmp(tipo_node->valuestring, "Uptime") == 0) {
                    tipo = TIPO_UPTIME;
                    is_uptime = true;
                } else if (strcasecmp(tipo_node->valuestring, "Custom") == 0) {
                    tipo = TIPO_INTERFACE;
                    is_custom = true;
                }  else {
                    tipo = TIPO_INTERFACE;
                }

                if (is_pppoe_count) {f_RegisterPPPoETarget(ip, atoi(port_node->valuestring), atoi(disp_node->valuestring));}
                if (is_uptime) {f_RegisterUptimeTarget(ip, atoi(port_node->valuestring), atoi(disp_node->valuestring));}

                int ip_idx = f_BuscaIndiceIP(dispositivos, total_ips, ip);

                if (ip_idx == -1 && total_ips < max_dispositivos) {
                    dispositivos[total_ips].ip = strdup(ip);
                    dispositivos[total_ips].port = atoi(port_node->valuestring); // 👈 salva a porta
                    dispositivos[total_ips].community = strdup(comm_node->valuestring);  // 👈 aqui
                    ip_idx = total_ips++;
                }

                if (is_custom) {
                    //Preciso encontrar uma forma de colocar o operation e operation factor
                    char custom_key[64];
                    snprintf(custom_key, sizeof(custom_key), "customOid[%s]", idx_str);
                    cJSON *oid_node = cJSON_GetObjectItem(json, custom_key);
                    if (oid_node && cJSON_IsString(oid_node) && cJSON_IsString(oper_node) && cJSON_IsString(operFact_node)) {
                            f_RegisterCustomTarget(ip, atoi(port_node->valuestring), atoi(disp_node->valuestring), oid_node->valuestring, oper_node->valuestring, operFact_node->valuestring, suffix_node->valuestring);
                    }
                    continue;
                }
                
                if (ip_idx != -1 && dispositivos[ip_idx].total_oids < MAX_OIDS - 2) {
                    if (tipo == TIPO_INTERFACE) {
                        f_RegistraOIDStatusInterface(&dispositivos[ip_idx], display, index);
                    } else if (tipo == TIPO_TRAFEGO) {
                        f_RegistraOIDTrafego(&dispositivos[ip_idx], display, index);
                    }
                }
        }
        cJSON_Delete(json);
        return total_ips;
}

void f_ExecutaLeituraSNMP(IPInfo *dispositivos, int total_ips, bool PrintDebug) {

    int16_t IntervaloLeituraSNMP;
    int16_t ret = f_KeyValueInt("IntervaloLeituraSNMP", "/config/snmp-setup.json");
    IntervaloLeituraSNMP = (ret == INT_MAX || ret <= 0) ? 5000 : ret;
   
    while (!StopReadInterface) {
            for (int i = 0; i < total_ips; i++) {
                int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
                setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                struct sockaddr_in dest = {.sin_family = AF_INET, .sin_port = htons(dispositivos[i].port), .sin_addr.s_addr = inet_addr(dispositivos[i].ip)};
                f_ProcessaStatusInterface(sock, &dispositivos[i], &dest);
                f_ProcessaTrafegoSNMP(sock, &dispositivos[i], &dest);
                f_ProcessaPPPoECount(sock, dispositivos[i].ip, dispositivos[i].port, &dest, dispositivos[i].community, PrintDebug);
                f_ProcessaUptimeSNMP(sock, dispositivos[i].ip, dispositivos[i].port, &dest, dispositivos[i].community);
                f_ProcessaSNMPCustom(sock, dispositivos[i].ip, dispositivos[i].port, dispositivos[i].community);
                close(sock);
            }
            TickType_t start = xTaskGetTickCount();
            TickType_t wait = pdMS_TO_TICKS(IntervaloLeituraSNMP); // Intervalo de leitura SNMP
            while ((xTaskGetTickCount() - start < wait) && !StopReadInterface) {
                vTaskDelay(pdMS_TO_TICKS(10));
            }
    }
}

void f_stopReadInterfaces() {StopReadInterface = true;}

void f_LiberaDispositivos(IPInfo *dispositivos, int total_ips) {
    for (int i = 0; i < total_ips; i++) {
        safe_free(&dispositivos[i].ip); // libera IP
        safe_free(&dispositivos[i].community); // libera community 👈
        for (int j = 0; j < dispositivos[i].total_oids; j++) {
            safe_free(&dispositivos[i].oids[j].oid);      // libera OID
            safe_free(&dispositivos[i].oids[j].display);  // libera display
        }
    }
    f_LiberaPPPoETargets();
    f_LiberaUptimeTargets();
    f_LiberaCustomTargets();
}

int f_BuscaIndiceIP(IPInfo *dispositivos, int total, const char *ip) {
    for (int i = 0; i < total; i++) {
        if (strcmp(dispositivos[i].ip, ip) == 0) return i;
    }
    return -1;
}
