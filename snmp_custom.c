#include <string.h>
#include <stdlib.h>
#include "snmp_custom.h"
#include "snmp_traffic.h"
#include "snmp_defs.h"
#include "snmp_lib.h"
#include "snmp_client.h"
#include "snmp_main.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "snmp_custom.h"
#include "../../main/include/f_devices.h"
#include "../../enervision_manager/include/f_safefree.h"

#define MAX_CUSTOM_TARGETS 16
static CustomTarget custom_targets[MAX_CUSTOM_TARGETS];
static int total_custom_targets = 0;
static const char * TAG = "SNMP-CUSTOM:";

static bool PrintDebugSNMP = false;

void f_setPrintDebugCustom(bool valor) {
    PrintDebugSNMP = valor;
    if(PrintDebugSNMP){ESP_LOGI(TAG, "SNMP Custom Debug Activated!");}
}

void f_ProcessaSNMPCustom(int sock, const char *ip, int port, const char *community) {
        if (f_GetTotalCustomTargets() == 0) return; // não tem nada pra processar
        struct sockaddr_in dest = {0};
        dest.sin_family = AF_INET;
        dest.sin_port = htons(port);
        dest.sin_addr.s_addr = inet_addr(ip);

        for (int i = 0; i < f_GetTotalCustomTargets(); i++) {
                const CustomTarget *t = f_GetCustomTargetByIndex(i);

                if (strcmp(t->ip, ip) != 0 || t->port != port) continue;

                uint8_t oid[32];
                size_t oid_len = 0;
                if (!parse_oid_string(t->oid, oid, &oid_len)) {ESP_LOGW(TAG, "Invalid OID: %s", t->oid); continue;}

                uint8_t req[64], resp[256];
                int req_len = build_snmp_get(req, sizeof(req), oid, oid_len, 300 + i, community);
                if (req_len <= 0) continue;

                sendto(sock, req, req_len, 0, (struct sockaddr *)&dest, sizeof(dest));
                socklen_t len = sizeof(dest);
                int r = recvfrom(sock, resp, sizeof(resp) - 1, 0, (struct sockaddr *)&dest, &len);
                if (r <= 0) {
                    float desconectado = 0xFFFFFFFF;
                    if (Device[t->display].xQueue != NULL && f_DeviceServico(Device[t->display].Servico, SNMP_Custom)) {
                        if(f_GetPrintDebugSNMP()){ESP_LOGW(TAG, "[%s:%d] OID: %s → Device did not respond, marking as DISCONNECTED (0xFFFFFFFF)", ip, port, t->oid);}
                        xQueueOverwrite(Device[t->display].xQueue, &desconectado);
                        xQueueOverwrite(Device[t->display].xQueueAlarme, &desconectado);
                        xQueueOverwrite(Device[t->display].xQueueMqtt, &desconectado);
                        xQueueOverwrite(Device[t->display].xQueueDashzap, &desconectado);
                        if(PrintDebugSNMP){ESP_LOGW(TAG, "Marked Display(%d) as DISCONNECTED", t->display);}
                    }
                    continue;
                }
                if (r > 0) {
                    uint8_t tipo_asn1 = parse_snmp_value_type(resp, r);
                    if(f_GetPrintDebugSNMP()){ESP_LOGI("SNMP_CUSTOM", "ASN.1 type: 0x%02X", tipo_asn1);}
                    switch (tipo_asn1) { //Pensar em como vou fornecer esses dados
                        case 0x02: { // INTEGER
                            int valor_int = 0;
                            if (parse_snmp_integer_value(resp, r, &valor_int)) {
                                float valor_float = (float)valor_int; // Convertendo para float
                                if (Device[t->display].xQueue != NULL && f_DeviceServico(Device[t->display].Servico, SNMP_Custom)) {
                                    if(f_GetPrintDebugSNMP()){ESP_LOGI(TAG, "[%s:%d] OID: %s → %d (INTEGER) converted to %.2f (FLOAT) - Display(%d)", ip, port, t->oid, valor_int, valor_float, t->display);}
                                    xQueueOverwrite(Device[t->display].xQueue, &valor_float);
                                    xQueueOverwrite(Device[t->display].xQueueAlarme, &valor_float);
                                    xQueueOverwrite(Device[t->display].xQueueMqtt, &valor_float);
                                    xQueueOverwrite(Device[t->display].xQueueDashzap, &valor_float);
                                    if(PrintDebugSNMP){ESP_LOGI(TAG, "Updated Display(%d) with value %.2f", t->display, valor_float);}
                                } else {
                                    ESP_LOGE(TAG, "Device not Designed(%d)", t->display);
                                }                                
                            }
                            break;
                        }
                        case 0x04: { // STRING
                            char valor_str[64] = {0};
                            if (parse_snmp_string_value(resp, r, valor_str, sizeof(valor_str))) {
                                ESP_LOGI(TAG, "[%s:%d] OID: %s → %s (STRING)", ip, port, t->oid, valor_str);
                            }
                            break;
                        }
                        case 0x41:    // Counter32
                        case 0x42: { // Gauge32
                            uint8_t vtype = 0;
                            uint32_t v = 0;
                            if (parse_snmp_first_varbind_u32(resp, r, &vtype, &v)) {
                                float valor_float = (float)v;
                                if (Device[t->display].xQueue != NULL && f_DeviceServico(Device[t->display].Servico, SNMP_Custom)) {
                                    if (f_GetPrintDebugSNMP()) {
                                        ESP_LOGI(TAG, "[%s:%d] OID: %s → %lu (Gauge32) -> %.2f - Display(%d)",
                                                ip, port, t->oid, (unsigned long)v, valor_float, t->display);
                                    }
                                    xQueueOverwrite(Device[t->display].xQueue, &valor_float);
                                    xQueueOverwrite(Device[t->display].xQueueAlarme, &valor_float);
                                    xQueueOverwrite(Device[t->display].xQueueMqtt, &valor_float);
                                    xQueueOverwrite(Device[t->display].xQueueDashzap, &valor_float);
                                    if(PrintDebugSNMP){ESP_LOGI(TAG, "Updated Display(%d) with value %.2f", t->display, valor_float);}
                                }
                            } else {
                                ESP_LOGW(TAG, "Failed to parse Gauge32 for OID %s", t->oid);
                            }
                            break;
                        }

                        case 0x43: {  // TimeTicks
                            uint32_t v = 0;
                            if (parse_snmp_uint32_value(resp, r, &v)) {
                                float valor_float = (float)v;
                                // Se for TimeTicks (0x43), o padrão SNMP é 1/100s.
                                // Se você quer segundos no display:
                                if (tipo_asn1 == 0x43) {
                                    valor_float = valor_float / 100.0f;
                                }
                                // Aplicar operação do Custom (divide/multiply/none)
                                if (t->Operation == Divide && t->OperationFactor > 0) {
                                    valor_float /= (float)t->OperationFactor;
                                } else if (t->Operation == Multiply) {
                                    valor_float *= (float)t->OperationFactor;
                                }
                                if (Device[t->display].xQueue != NULL && f_DeviceServico(Device[t->display].Servico, SNMP_Custom)) {
                                    if (f_GetPrintDebugSNMP()) {
                                        const char *type_str =
                                            (tipo_asn1 == 0x41) ? "Counter32" :
                                            (tipo_asn1 == 0x42) ? "Gauge32"   :
                                            (tipo_asn1 == 0x43) ? "TimeTicks" : "u32";
                                        ESP_LOGI(TAG, "[%s:%d] OID: %s → %lu (%s) -> %.2f - Display(%d)",
                                                ip, port, t->oid, (unsigned long)v, type_str, valor_float, t->display);
                                    }
                                    xQueueOverwrite(Device[t->display].xQueue, &valor_float);
                                    xQueueOverwrite(Device[t->display].xQueueAlarme, &valor_float);
                                    xQueueOverwrite(Device[t->display].xQueueMqtt, &valor_float);
                                    xQueueOverwrite(Device[t->display].xQueueDashzap, &valor_float);
                                    if(PrintDebugSNMP){ESP_LOGW(TAG, "Updated Display(%d) with value %.2f", t->display, valor_float);}
                                }
                            }
                            break;
                        }
                        case 0x80:
                        case 0x81:
                        case 0x82:
                            ESP_LOGW(TAG, "[%s:%d] OID: %s → No value (ASN.1 = 0x%02X)", ip, port, t->oid, tipo_asn1);
                            break;

                        default:
                            ESP_LOGW(TAG, "ASN.1 type 0x%02X not handled directly. Displaying raw buffer:", tipo_asn1);
                            ESP_LOG_BUFFER_HEX(TAG, resp, r);
                            break;
                    }
                }
        }
}

void f_RegisterCustomTarget(const char *ip, int port, int display, const char *oid, const char *oper, const char *operfact, const char * suffix) {
        if (total_custom_targets >= MAX_CUSTOM_TARGETS) return;
        custom_targets[total_custom_targets].ip = strdup(ip);
        custom_targets[total_custom_targets].port = port;
        custom_targets[total_custom_targets].display = (display-1); // Ajusta o Display Indexado..
        custom_targets[total_custom_targets].oid = strdup(oid);
        custom_targets[total_custom_targets].OperationFactor = atoi(operfact);
        custom_targets[total_custom_targets].Suffix = strdup(suffix);
        //Precisa aqui fazer a correta corelação
        if(f_GetPrintDebugSNMP()){ESP_LOGW(TAG, "Operation(%s), OperFact(%s)", oper, operfact);}
        
        if (strcmp(oper, "divide") == 0) {
            custom_targets[total_custom_targets].Operation = Divide;
        } else if (strcmp(oper, "multiply") == 0) {
            custom_targets[total_custom_targets].Operation = Multiply;
        } else if (strcmp(oper, "none") == 0) {
            custom_targets[total_custom_targets].Operation = None;
        }
        total_custom_targets++;
}

int f_GetCustomDisplay(const char *ip, int port, const char *oid) {
    for (int i = 0; i < total_custom_targets; i++) {
        if (strcmp(custom_targets[i].ip, ip) == 0 &&
            custom_targets[i].port == port &&
            strcmp(custom_targets[i].oid, oid) == 0) {
            return custom_targets[i].display;
        }
    }
    return -1;
}

void f_LiberaCustomTargets(void) {
    for (int i = 0; i < total_custom_targets; i++) {
        safe_free(&custom_targets[i].ip);
        safe_free(&custom_targets[i].oid);
    }
    total_custom_targets = 0;
}

int f_GetTotalCustomTargets(void) {
    return total_custom_targets;
}

const CustomTarget *f_GetCustomTargetByIndex(int index) {
    if (index < 0 || index >= total_custom_targets) return NULL;
    return &custom_targets[index];
}

const CustomTarget *f_GetCustomTargetByDisplay(int display) {
    for (int i = 0; i < total_custom_targets; i++) {
        if (custom_targets[i].display == display) {
            return &custom_targets[i];
        }
    }
    return NULL;
}
