#include "snmp_read-interface.h"
#include "snmp_lib.h"  // Aqui devem estar funções como f_GetBaseOID, f_QueryIfStatusMulti etc.
#include "../../enervision_manager/include/f_configfile.h"
#include "../../enervision_manager/include/f_safefree.h"
#include "snmp_client.h"

#define TAG "SNMP_CLIENT"

bool StopReadInterface = false;
static QueueHandle_t qInterface;

int f_PopulaDispositivos(IPInfo *dispositivos, int max_dispositivos) {
        cJSON *json = read_json_file("/snmp-interface-select.json");
        if (!json) return -1;

        int total_ips = 0;

        cJSON *item = NULL;
        cJSON_ArrayForEach(item, json) {
            const char *key = item->string;
            if (strncmp(key, "IP[", 3) != 0) continue;

            char idx_str[8];
            sscanf(key, "IP[%[^]]", idx_str);

            char ip_key[16], index_key[24], disp_key[40], tipo_key[40];
            snprintf(ip_key, sizeof(ip_key), "IP[%s]", idx_str);
            snprintf(index_key, sizeof(index_key), "index[%s]", idx_str);
            snprintf(disp_key, sizeof(disp_key), "displaySelecionado[%s]", idx_str);
            snprintf(tipo_key, sizeof(tipo_key), "tipoSelecionado[%s]", idx_str);

            cJSON *ip_node = cJSON_GetObjectItem(json, ip_key);
            cJSON *idx_node = cJSON_GetObjectItem(json, index_key);
            cJSON *disp_node = cJSON_GetObjectItem(json, disp_key);
            cJSON *tipo_node = cJSON_GetObjectItem(json, tipo_key);

            if (!ip_node || !idx_node || !disp_node || !tipo_node) continue;
            if (!cJSON_IsString(ip_node) || !cJSON_IsString(idx_node) ||
                !cJSON_IsString(disp_node) || !cJSON_IsString(tipo_node)) continue;

            const char *ip = ip_node->valuestring;
            int index = atoi(idx_node->valuestring);
            const char *display = disp_node->valuestring;
            TipoSelecionado tipo = (strcasecmp(tipo_node->valuestring, "Trafego") == 0) ? TIPO_TRAFEGO : TIPO_INTERFACE;

            int ip_idx = -1;
            for (int i = 0; i < total_ips; i++) {
                if (strcmp(dispositivos[i].ip, ip) == 0) {
                    ip_idx = i;
                    break;
                }
            }

            if (ip_idx == -1 && total_ips < max_dispositivos) {
                dispositivos[total_ips].ip = strdup(ip);
                ip_idx = total_ips++;
            }

            if (ip_idx != -1 && dispositivos[ip_idx].total_oids < MAX_OIDS - 2) {
                if (tipo == TIPO_INTERFACE) {
                    char oid_str[64];
                    snprintf(oid_str, sizeof(oid_str), "%s%d", f_GetBaseOID(MIB_IF_OPER_STATUS), index);
                    int idx = dispositivos[ip_idx].total_oids++;
                    dispositivos[ip_idx].oids[idx].oid = strdup(oid_str);
                    dispositivos[ip_idx].oids[idx].display = strdup(display);
                    dispositivos[ip_idx].oids[idx].tipo = tipo;
                } else {
                    const char *base_in = f_GetBaseOID(MIB_IF_IN_OCTETS);
                    const char *base_out = f_GetBaseOID(MIB_IF_OUT_OCTETS);

                    char oid_in[64], oid_out[64];
                    snprintf(oid_in, sizeof(oid_in), "%s%d", base_in, index);
                    snprintf(oid_out, sizeof(oid_out), "%s%d", base_out, index);

                    int idx_in = dispositivos[ip_idx].total_oids++;
                    dispositivos[ip_idx].oids[idx_in].oid = strdup(oid_in);
                    dispositivos[ip_idx].oids[idx_in].display = strdup(display);
                    dispositivos[ip_idx].oids[idx_in].tipo = tipo;

                    int idx_out = dispositivos[ip_idx].total_oids++;
                    dispositivos[ip_idx].oids[idx_out].oid = strdup(oid_out);
                    dispositivos[ip_idx].oids[idx_out].display = strdup(display);
                    dispositivos[ip_idx].oids[idx_out].tipo = tipo;
                }
            }
        }

        cJSON_Delete(json);
        ESP_LOGW(TAG, "Total de IPs: %d", total_ips);
        return total_ips;
}


void f_ExecutaLeituraSNMP(IPInfo *dispositivos, int total_ips) {
    while (!StopReadInterface) {
            for (int i = 0; i < total_ips; i++) {
                int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
                setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                struct sockaddr_in dest = {.sin_family = AF_INET, .sin_port = htons(161), .sin_addr.s_addr = inet_addr(dispositivos[i].ip)};

                const char *oids_status[MAX_OIDS] = {0};
                const char *oids_trafego[MAX_OIDS] = {0};
                int status_count = 0, trafego_count = 0;
                int index_map[MAX_OIDS] = {0};

                for (int j = 0; j < dispositivos[i].total_oids; j++) {
                    if (dispositivos[i].oids[j].tipo == TIPO_INTERFACE) {
                        oids_status[status_count] = dispositivos[i].oids[j].oid;
                        index_map[status_count++] = j;
                    } else {
                        oids_trafego[trafego_count] = dispositivos[i].oids[j].oid;
                        index_map[trafego_count + MAX_OIDS / 2] = j;
                        trafego_count++;
                    }
                }
                char *status_result[MAX_OIDS] = {0};
                if (status_count > 0) {
                    f_QueryIfStatusMulti(sock, &dest, oids_status, status_count, status_result);
                    for (int k = 0; k < status_count; k++) {
                        int j = index_map[k];
                        ESP_LOGI(TAG, "IP: %s | OID: %s | Tipo: Interface | Display: %s | Resultado: %s", dispositivos[i].ip, dispositivos[i].oids[j].oid, dispositivos[i].oids[j].display, status_result[k]);
                    }
                }
                uint32_t trafego_result[MAX_OIDS] = {0};
                if (trafego_count > 0) {
                    f_QueryTrafficMulti(sock, &dest, oids_trafego, trafego_count, trafego_result);
                    for (int k = 0; k < trafego_count; k++) {
                        int j = index_map[k + MAX_OIDS / 2];
                        if (trafego_result[k] != 0xFFFFFFFF) {
                            ESP_LOGI(TAG, "IP: %s | OID: %s | Tipo: Trafego | Display: %s | Resultado: %lu bytes", dispositivos[i].ip, dispositivos[i].oids[j].oid, dispositivos[i].oids[j].display, trafego_result[k]);
                        } else {
                            ESP_LOGW(TAG, "Erro ao ler tráfego da porta (OID: %s)", dispositivos[i].oids[j].oid);
                        }
                    }
                }
                close(sock);
            }
            vTaskDelay(pdMS_TO_TICKS(5000));
    }
}
void f_stopReadInterfaces(void *arg) {
    StopReadInterface = true;
    ESP_LOGI(TAG, "Parando leitura de status de múltiplas interfaces SNMP");
}
void f_LiberaDispositivos(IPInfo *dispositivos, int total_ips) {
    for (int i = 0; i < total_ips; i++) {
        if (dispositivos[i].ip) {
            free(dispositivos[i].ip);
        }

        for (int j = 0; j < dispositivos[i].total_oids; j++) {
            if (dispositivos[i].oids[j].oid) {
                safe_free(dispositivos[i].oids[j].oid);
            }
            if (dispositivos[i].oids[j].display) {
                safe_free(dispositivos[i].oids[j].display);
            }
        }
    }
}
