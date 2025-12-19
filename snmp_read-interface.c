#include "snmp_read-interface.h"
#include "snmp_lib.h"  // Aqui devem estar funções como f_GetBaseOID, f_QueryIfStatusMulti etc.
#include "../../enervision_manager/include/f_configfile.h"
#include "../../enervision_manager/include/f_safefree.h"
#include "../../main/include/f_devices.h"
#include "snmp_client.h"
#include "snmp_traffic.h"
#include "snmp_uptime.h"
#include "snmp_pppoe.h"
#include "snmp_pppoe_oid.h"
#include "snmp_custom.h"
#include "snmp_status-interface.h"
#define TAG "SNMP_CLIENT"
bool StopReadInterface = false;
static bool PrintDebug = false;

void f_setPrintDebugSNMP_ReadInterface(bool debug) {
    PrintDebug = debug;
    if(PrintDebug) {ESP_LOGI(TAG, "SNMP debug printing Read Interface enabled.");}
}

static const char *snmp_json_get_str(cJSON *json, const char *key) {
        if (!json || !key) return NULL;
        cJSON *n = cJSON_GetObjectItem(json, key);
        if (!n || !cJSON_IsString(n) || !n->valuestring) return NULL;
        if (n->valuestring[0] == '\0') return NULL;
        return n->valuestring;
}

static const char *snmp_json_get_str_def(cJSON *json, const char *key, const char *def) {
        const char *v = snmp_json_get_str(json, key);
        return v ? v : def;
}

static bool snmp_extract_idx(const char *key, char *out_idx, size_t out_sz) {
        if (!key || !out_idx || out_sz == 0) return false;
        out_idx[0] = '\0';
        // Limita a captura para evitar overflow em idx_str
        int ret = sscanf(key, "IP[%7[^]]", out_idx);
        return (ret == 1 && out_idx[0] != '\0');
}

static snmp_row_kind_t snmp_classify_kind(const char *tipo) {
        if (!tipo) return ROW_KIND_INTERFACE;
        if (strcasecmp(tipo, "Trafego") == 0)          return ROW_KIND_TRAFEGO;
        if (strcasecmp(tipo, "PPPoE-Count") == 0)      return ROW_KIND_PPPOE_LEGACY;
        if (strcasecmp(tipo, "PPPoE-Mikrotik") == 0)   return ROW_KIND_PPPOE_OID_MIKROTIK;
        if (strcasecmp(tipo, "PPPoE-Huawei") == 0)     return ROW_KIND_PPPOE_OID_HUAWEI;
        if (strcasecmp(tipo, "Uptime") == 0)           return ROW_KIND_UPTIME;
        if (strcasecmp(tipo, "Custom") == 0)           return ROW_KIND_CUSTOM;
        return ROW_KIND_INTERFACE;
}

static bool snmp_load_row(cJSON *json, const char *idx_str, snmp_row_t *row) {
        if (!json || !idx_str || !row) return false;

        memset(row, 0, sizeof(*row));
        strncpy(row->idx_str, idx_str, sizeof(row->idx_str) - 1);

        char key[64];

        // IP
        snprintf(key, sizeof(key), "IP[%s]", idx_str);
        row->ip = snmp_json_get_str(json, key);

        // Port
        snprintf(key, sizeof(key), "Port[%s]", idx_str);
        const char *port_str = snmp_json_get_str(json, key);
        row->port = port_str ? atoi(port_str) : -1;

        // Community (compat: "community" e "Community")
        snprintf(key, sizeof(key), "community[%s]", idx_str);
        row->community = snmp_json_get_str(json, key);
        if (!row->community) {
            snprintf(key, sizeof(key), "Community[%s]", idx_str);
            row->community = snmp_json_get_str(json, key);
        }

        // Display
        snprintf(key, sizeof(key), "displaySelecionado[%s]", idx_str);
        row->display_str = snmp_json_get_str(json, key);
        row->display_num = (row->display_str) ? atoi(row->display_str) : -1;

        // Tipo
        snprintf(key, sizeof(key), "tipoSelecionado[%s]", idx_str);
        row->tipo_str = snmp_json_get_str(json, key);

        // Index (opcional para PPPoE/Uptime/Custom)
        snprintf(key, sizeof(key), "index[%s]", idx_str);
        const char *idx_if = snmp_json_get_str(json, key);
        row->index = idx_if ? atoi(idx_if) : -1;

        // Custom opcionais (defaults)
        snprintf(key, sizeof(key), "operationType[%s]", idx_str);
        row->oper = snmp_json_get_str_def(json, key, "none");

        snprintf(key, sizeof(key), "operationFactor[%s]", idx_str);
        row->operfact = snmp_json_get_str_def(json, key, "1");

        snprintf(key, sizeof(key), "unitSuffix[%s]", idx_str);
        row->suffix = snmp_json_get_str_def(json, key, "");

        snprintf(key, sizeof(key), "customOid[%s]", idx_str);
        row->custom_oid = snmp_json_get_str(json, key); // pode ser NULL

        // Campos mínimos para criar/rodar o device no loop SNMP
        if (!row->ip || row->port <= 0 || !row->community || !row->display_str || row->display_num <= 0 || !row->tipo_str) {return false;}



        return true;
}

static int snmp_ensure_device(IPInfo *dispositivos, int *total_ips, int max_dispositivos, const char *ip, int port, const char *community) {
        int ip_idx = f_BuscaIndiceIP(dispositivos, *total_ips, ip);
        if (ip_idx != -1) return ip_idx;
        if (*total_ips >= max_dispositivos) return -1;
        dispositivos[*total_ips].ip = strdup(ip);
        dispositivos[*total_ips].port = port;
        dispositivos[*total_ips].community = strdup(community);
        dispositivos[*total_ips].total_oids = 0;
        if(PrintDebug) ESP_LOGI(TAG, "Device added: %s:%d community=%s", ip, port, community);
        return (*total_ips)++;
}

static void snmp_register_special_targets(snmp_row_kind_t kind, const snmp_row_t *row) {
    if (!row) return;
    switch (kind) {
        case ROW_KIND_PPPOE_LEGACY:
            f_RegisterPPPoETarget(row->ip, row->port, row->display_num);
            break;
        case ROW_KIND_PPPOE_OID_MIKROTIK:
            f_RegisterPPPoEOidTarget(row->ip, row->port, row->display_num, PPPoE_OID_PROFILE_MIKROTIK, NULL);
            break;
        case ROW_KIND_PPPOE_OID_HUAWEI:
            f_RegisterPPPoEOidTarget(row->ip, row->port, row->display_num, PPPoE_OID_PROFILE_HUAWEI, NULL);
            break;
        case ROW_KIND_UPTIME:
            f_RegisterUptimeTarget(row->ip, row->port, row->display_num);
            break;
        default:
            break;
    }
}

int f_PopulaDispositivos(IPInfo *dispositivos, int max_dispositivos) {
        StopReadInterface = false;
        cJSON *json = read_json_file("/config/snmp-interface-select.json");
        if (PrintDebug) ESP_LOGI(TAG, "PopulaDispositivos: Reading... /config/snmp-interface-select.json...");
        if (!json) return -1;
        int total_ips = 0;
        cJSON *item = NULL;
        cJSON_ArrayForEach(item, json) {
                const char *key = item->string;
                if (!key || strncmp(key, "IP[", 3) != 0) continue;

                char idx_str[8] = {0};
                if (!snmp_extract_idx(key, idx_str, sizeof(idx_str))) continue;
                snmp_row_t row;
                if (!snmp_load_row(json, idx_str, &row)) continue;
                snmp_row_kind_t kind = snmp_classify_kind(row.tipo_str);
                snmp_register_special_targets(kind, &row);// Registros especiais (PPPoE/Uptime) baseados na linha
                // Garante que o IP entre na lista de devices; o loop de leitura usa essa lista
                int ip_idx = snmp_ensure_device(dispositivos, &total_ips, max_dispositivos, row.ip, row.port, row.community);
                if (ip_idx < 0) continue;
                if (kind == ROW_KIND_CUSTOM) {// Custom: registra target e não adiciona OIDs de interface/tráfego
                    if (!row.custom_oid || row.custom_oid[0] == '\0') {
                        ESP_LOGW(TAG, "Custom row idx=%s sem customOid[%s]. Ignorando.", row.idx_str, row.idx_str);
                        continue;
                    }
                    f_RegisterCustomTarget(row.ip, row.port, row.display_num, row.custom_oid, row.oper, row.operfact, row.suffix);
                    continue;
                }
                // Interface/Tráfego: precisa de index válido
                // OBS: Para manter compatibilidade com o comportamento antigo, "PPPoE-Count" também registra OID de status de interface.
                const bool wants_status_oid = (kind == ROW_KIND_INTERFACE || kind == ROW_KIND_PPPOE_LEGACY);
                const bool wants_trafego_oid = (kind == ROW_KIND_TRAFEGO);
                if (wants_status_oid || wants_trafego_oid) {
                    if (row.index <= 0) continue;
                    if (dispositivos[ip_idx].total_oids < MAX_OIDS - 2) {
                        if (wants_status_oid) {
                            f_RegistraOIDStatusInterface(&dispositivos[ip_idx], row.display_str, row.index);
                        } else if (wants_trafego_oid) {
                            f_RegistraOIDTrafego(&dispositivos[ip_idx], row.display_str, row.index);
                        }
                    }
                }
        }
        cJSON_Delete(json);
        if (PrintDebug) ESP_LOGI(TAG, "PopulaDispositivos: completed. devices=%d", total_ips);
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
                f_ProcessaPPPoECountOid(sock, dispositivos[i].ip, dispositivos[i].port, &dest, dispositivos[i].community, PrintDebug);
                f_ProcessaUptimeSNMP(sock, dispositivos[i].ip, dispositivos[i].port, &dest, dispositivos[i].community);
                f_ProcessaSNMPCustom(sock, dispositivos[i].ip, dispositivos[i].port, dispositivos[i].community);
                close(sock);
                if (PrintDebug) ESP_LOGI(TAG, "Completed SNMP read for IP: %s", dispositivos[i].ip);
            }
            TickType_t start = xTaskGetTickCount();
            TickType_t wait = pdMS_TO_TICKS(IntervaloLeituraSNMP); // Intervalo de leitura SNMP
            while ((xTaskGetTickCount() - start < wait) && !StopReadInterface) {
                vTaskDelay(pdMS_TO_TICKS(10));
            }
            if(PrintDebug) ESP_LOGI(TAG, "Next SNMP read cycle.");
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
    f_LiberaPPPoEOidTargets();
    f_LiberaUptimeTargets();
    f_LiberaCustomTargets();

}

int f_BuscaIndiceIP(IPInfo *dispositivos, int total, const char *ip) {
    for (int i = 0; i < total; i++) {
        if (strcmp(dispositivos[i].ip, ip) == 0) return i;
    }
    return -1;
}




//Essa função antiga popula os dispositivos lendo o arquivo JSON - Funciona perfeitamente (trata-se de um backup do código.)

// int f_PopulaDispositivos(IPInfo *dispositivos, int max_dispositivos) {
//         StopReadInterface = false;
//         cJSON *json = read_json_file("/config/snmp-interface-select.json");
//         if (!json) return -1;

//         int total_ips = 0;

//         cJSON *item = NULL;
//         cJSON_ArrayForEach(item, json) {
//                 const char *key = item->string;
//                 if (strncmp(key, "IP[", 3) != 0) continue;

//                 char idx_str[8];
//                 sscanf(key, "IP[%[^]]", idx_str);

//                 char ip_key[16], index_key[24], disp_key[40], tipo_key[40], oper_key[40], operFact_key[40], suffix_key[40];
//                 snprintf(ip_key, sizeof(ip_key), "IP[%s]", idx_str);
//                 snprintf(index_key, sizeof(index_key), "index[%s]", idx_str);
//                 snprintf(disp_key, sizeof(disp_key), "displaySelecionado[%s]", idx_str);
//                 snprintf(tipo_key, sizeof(tipo_key), "tipoSelecionado[%s]", idx_str);
//                 snprintf(oper_key, sizeof(oper_key), "operationType[%s]", idx_str);
//                 snprintf(operFact_key, sizeof(operFact_key), "operationFactor[%s]", idx_str);
//                 snprintf(suffix_key, sizeof(suffix_key), "unitSuffix[%s]", idx_str);

//                 char port_key[24];
//                 char comm_key[24];
//                 snprintf(comm_key, sizeof(comm_key), "community[%s]", idx_str);
//                 cJSON *comm_node = cJSON_GetObjectItem(json, comm_key);

//                 snprintf(port_key, sizeof(port_key), "Port[%s]", idx_str);
//                 cJSON *port_node = cJSON_GetObjectItem(json, port_key);

//                 cJSON *ip_node = cJSON_GetObjectItem(json, ip_key);
//                 cJSON *idx_node = cJSON_GetObjectItem(json, index_key);
//                 cJSON *disp_node = cJSON_GetObjectItem(json, disp_key);
//                 cJSON *tipo_node = cJSON_GetObjectItem(json, tipo_key);
//                 cJSON *oper_node = cJSON_GetObjectItem(json, oper_key);
//                 cJSON *operFact_node = cJSON_GetObjectItem(json, operFact_key);
//                 cJSON *suffix_node = cJSON_GetObjectItem(json, suffix_key);


//                 if (!ip_node || !idx_node || !disp_node || !tipo_node || !port_node || !comm_node) continue;
//                 if (!cJSON_IsString(ip_node)   || !cJSON_IsString(idx_node) ||
//                     !cJSON_IsString(disp_node) || !cJSON_IsString(tipo_node) ||
//                     !cJSON_IsString(port_node) || !cJSON_IsString(comm_node)
//                 ) continue;

//                 const char *ip = ip_node->valuestring;
//                 int index = atoi(idx_node->valuestring);
//                 const char *display = disp_node->valuestring;

//                 TipoSelecionado tipo;
//                 bool is_pppoe_count = false;
//                 bool is_pppoe_count_oid_mikrotik = false;
//                 bool is_pppoe_count_oid_huawei   = false;

//                 bool is_uptime = false;
//                 bool is_custom = false;

//                 if (strcasecmp(tipo_node->valuestring, "Trafego") == 0) {
//                     tipo = TIPO_TRAFEGO;
//                 } else if (strcasecmp(tipo_node->valuestring, "PPPoE-Count") == 0) {
//                     tipo = TIPO_INTERFACE; // Isso estava errado, mais estava funcionando. Verificar depois
//                     is_pppoe_count = true;
//                 }  else if (strcasecmp(tipo_node->valuestring, "PPPoE-Mikrotik") == 0) {
//                     tipo = TIPO_PPPoE;
//                     is_pppoe_count_oid_mikrotik = true;
//                 } else if (strcasecmp(tipo_node->valuestring, "PPPoE-Huawei") == 0) {
//                     tipo = TIPO_PPPoE;
//                     is_pppoe_count_oid_huawei = true;
//                 }                
//                 else if (strcasecmp(tipo_node->valuestring, "Uptime") == 0) {
//                     tipo = TIPO_UPTIME;
//                     is_uptime = true;
//                 } else if (strcasecmp(tipo_node->valuestring, "Custom") == 0) {
//                     tipo = TIPO_INTERFACE;
//                     is_custom = true;
//                 }  else {
//                     tipo = TIPO_INTERFACE;
//                 }

//                 if (is_pppoe_count) {f_RegisterPPPoETarget(ip, atoi(port_node->valuestring), atoi(disp_node->valuestring));}

//                 if (is_pppoe_count_oid_mikrotik) {f_RegisterPPPoEOidTarget(ip, atoi(port_node->valuestring), atoi(disp_node->valuestring), PPPoE_OID_PROFILE_MIKROTIK, NULL);}
//                 if (is_pppoe_count_oid_huawei) {f_RegisterPPPoEOidTarget(ip, atoi(port_node->valuestring), atoi(disp_node->valuestring), PPPoE_OID_PROFILE_HUAWEI, NULL);}

//                 if (is_uptime) {f_RegisterUptimeTarget(ip, atoi(port_node->valuestring), atoi(disp_node->valuestring));}

//                 int ip_idx = f_BuscaIndiceIP(dispositivos, total_ips, ip);

//                 if (ip_idx == -1 && total_ips < max_dispositivos) {
//                     dispositivos[total_ips].ip = strdup(ip);
//                     dispositivos[total_ips].port = atoi(port_node->valuestring); // 👈 salva a porta
//                     dispositivos[total_ips].community = strdup(comm_node->valuestring);  // 👈 aqui
//                     ip_idx = total_ips++;
//                 }

//                 if (is_custom) {
//                     char custom_key[64];
//                     snprintf(custom_key, sizeof(custom_key), "customOid[%s]", idx_str);
//                     cJSON *oid_node = cJSON_GetObjectItem(json, custom_key);
//                     if (!oid_node || !cJSON_IsString(oid_node) || !oid_node->valuestring || oid_node->valuestring[0] == '\0') {
//                         ESP_LOGW(TAG, "Custom row idx=%s sem customOid[%s]. Ignorando.", idx_str, idx_str);
//                         continue;
//                     }
//                     const char *oper     = "none";
//                     const char *operfact = "1";
//                     const char *suffix   = "";
//                     if (oper_node && cJSON_IsString(oper_node) && oper_node->valuestring && oper_node->valuestring[0]) {oper = oper_node->valuestring;}
//                     if (operFact_node && cJSON_IsString(operFact_node) && operFact_node->valuestring && operFact_node->valuestring[0]) {operfact = operFact_node->valuestring;}
//                     if (suffix_node && cJSON_IsString(suffix_node) && suffix_node->valuestring) {suffix = suffix_node->valuestring;}
//                     f_RegisterCustomTarget(ip, atoi(port_node->valuestring), atoi(disp_node->valuestring), oid_node->valuestring, oper, operfact, suffix );
//                     continue;
//                 }
                
//                 if (ip_idx != -1 && dispositivos[ip_idx].total_oids < MAX_OIDS - 2) {
//                     if (tipo == TIPO_INTERFACE) {
//                         f_RegistraOIDStatusInterface(&dispositivos[ip_idx], display, index);
//                     } else if (tipo == TIPO_TRAFEGO) {
//                         f_RegistraOIDTrafego(&dispositivos[ip_idx], display, index);
//                     }
//                 }
//         }
//         cJSON_Delete(json);
//         return total_ips;
// }
