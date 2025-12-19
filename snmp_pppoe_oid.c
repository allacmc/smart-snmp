#include "snmp_pppoe_oid.h"

#include "esp_log.h"
#include <string.h>
#include <stdlib.h>

#include "snmp_lib.h"
#include "snmp_defs.h"
#include "../../main/include/f_devices.h"
#include "../enervision_manager/include/f_safefree.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define TAG "SNMP_PPPOE_OID"

#define OID_PPPOE_MIKROTIK "1.3.6.1.4.1.9.9.150.1.1.1.0"
#define OID_PPPOE_HUAWEI   "1.3.6.1.4.1.2011.5.2.1.14.1.2.0"

typedef struct {
    char *ip;
    int port;
    int display;

    snmp_pppoe_oid_profile_t profile;
    char *custom_oid; // usado apenas quando profile == CUSTOM
} PPPoEOidTarget;

#define MAX_PPPOE_OID_TARGETS 16
static PPPoEOidTarget pppoe_oid_targets[MAX_PPPOE_OID_TARGETS];
static int total_pppoe_oid_targets = 0;

static int f_FindPPPoEOidTargetIndex(const char *ip, int port) {
    for (int i = 0; i < total_pppoe_oid_targets; i++) {
        if (pppoe_oid_targets[i].ip &&
            strcmp(pppoe_oid_targets[i].ip, ip) == 0 &&
            pppoe_oid_targets[i].port == port) {
            return i;
        }
    }
    return -1;
}

static const char *f_GetPPPoEOidByProfile(snmp_pppoe_oid_profile_t profile, const char *custom_oid) {
        switch (profile) {
            case PPPoE_OID_PROFILE_MIKROTIK: return OID_PPPOE_MIKROTIK;
            case PPPoE_OID_PROFILE_HUAWEI:   return OID_PPPOE_HUAWEI;
            case PPPoE_OID_PROFILE_CUSTOM:   return custom_oid;
            default:                         return NULL;
        }
}

/**
 * Parser local: encontra o 1º OID (tag 0x06) e lê o valor logo após ele.
 * Aceita INTEGER(0x02), Counter32(0x41), Gauge32(0x42).
 * Trata noSuchObject/noSuchInstance/endOfMibView (0x80/0x81/0x82) como erro.
 */
// static bool f_ParseScalarU32AfterFirstOid(const uint8_t *packet, int length, uint32_t *out_value, uint8_t *out_type) {
//         if (!packet || length <= 0 || !out_value) return false;

//         for (int i = 0; i < length - 4; i++) {
//             if (packet[i] != 0x06) continue;          // OID
//             uint8_t oid_len = packet[i + 1];
//             int val_pos = i + 2 + oid_len;

//             if (val_pos + 2 >= length) return false;

//             uint8_t type = packet[val_pos + 0];
//             uint8_t vlen = packet[val_pos + 1];

//             if (out_type) *out_type = type;

//             // SNMP exceptions
//             if (type == 0x80 || type == 0x81 || type == 0x82) {
//                 return false;
//             }

//             // Aceitar INTEGER / Counter32 / Gauge32
//             if (!(type == 0x02 || type == 0x41 || type == 0x42)) {
//                 return false;
//             }

//             if (vlen == 0) return false;
//             if (val_pos + 2 + vlen > length) return false;

//             // Limite prático: PPPoE count cabe em uint32
//             if (vlen > 5) return false;

//             uint32_t value = 0;
//             // Se vier 5 bytes, geralmente é 0x00 + 4 bytes; vamos absorver assim mesmo.
//             for (int b = 0; b < vlen; b++) {
//                 value = (value << 8) | packet[val_pos + 2 + b];
//             }

//             *out_value = value;
//             return true;
//         }

//         return false;
// }

static bool f_ParseScalarU32AfterFirstOid(const uint8_t *packet, int length, uint32_t *out_value, uint8_t *out_type) {
    if (!packet || length <= 0 || !out_value) return false;
    if (out_type) *out_type = 0x00;

    for (int i = 0; i < length - 4; i++) {
        if (packet[i] != 0x06) continue; // TAG OID
        uint8_t oid_len = packet[i + 1];

        // Sanidade: evita confundir "0x06" que é LENGTH do community (04 06 ...)
        // e outros falsos positivos.
        if (oid_len == 0 || oid_len > 40) {continue;}
        int val_pos = i + 2 + oid_len;
        if (val_pos + 2 > length) {continue;}

        uint8_t type = packet[val_pos + 0];
        uint8_t vlen = packet[val_pos + 1];

        if (out_type) *out_type = type;
        // Exceptions SNMP (noSuchObject/noSuchInstance/endOfMibView)
        if (type == 0x80 || type == 0x81 || type == 0x82) {
            return false; // aqui sim: OID válido respondeu exception
        }

        // Aceitar tipos escalares usuais para contagem PPPoE
        if (!(type == 0x02 || type == 0x41 || type == 0x42)) {
            continue;
        }

        if (vlen == 0) continue;
        if (val_pos + 2 + vlen > length) continue;

        // Gauge32/Counter32 normalmente até 4 bytes; alguns agentes podem mandar 0x00 + 4
        if (vlen > 5) continue;

        uint32_t value = 0;
        for (int b = 0; b < vlen; b++) {
            value = (value << 8) | packet[val_pos + 2 + b];
        }

        *out_value = value;
        return true;
    }

    return false;
}

static int16_t f_PPPoECountByOid(int sock, struct sockaddr_in *dest, const char *community, const char *oid_str, bool PrintDebug) {
        if (!dest || !community || !oid_str || sock < 0) return -1;

        uint8_t oid_bin[32];
        size_t oid_len = 0;

        if (!parse_oid_string(oid_str, oid_bin, &oid_len)) {
            if (PrintDebug) ESP_LOGE(TAG, "OID inválido: %s", oid_str);
            return -1;
        }

        uint8_t req[96];
        uint8_t resp[256];
        socklen_t from_len = sizeof(*dest);

        // request-id variável (1 byte no seu encoder)
        static uint8_t req_id = 0x31;
        int req_len = build_snmp_get(req, sizeof(req), oid_bin, oid_len, req_id++, community);
        if (req_len <= 0) {
            if (PrintDebug) ESP_LOGE(TAG, "Falha ao montar SNMP GET (oid=%s)", oid_str);
            return -1;
        }

        bool resposta_ok = false;
        int r = 0;

        // Tentativas simples (mesmo padrão do seu snmp_pppoe.c)
        for (int tentativa = 0; tentativa < 4 && !resposta_ok; tentativa++) {
            sendto(sock, req, req_len, 0, (struct sockaddr *)dest, sizeof(*dest));
            r = recvfrom(sock, resp, sizeof(resp) - 1, 0, (struct sockaddr *)dest, &from_len);
            if (r > 0) {
                resposta_ok = true;
                break;
            }
            vTaskDelay(pdMS_TO_TICKS(10));
        }

        if (!resposta_ok || r <= 0) {
            if (PrintDebug) ESP_LOGW(TAG, "Sem resposta SNMP (oid=%s)", oid_str);
            return -1;
        }

        uint32_t value_u32 = 0;
        uint8_t  value_type = 0;
        if (!f_ParseScalarU32AfterFirstOid(resp, r, &value_u32, &value_type)) {
            if (PrintDebug) {
                ESP_LOGW(TAG, "Falha ao extrair valor (oid=%s). type=0x%02X", oid_str, value_type);
                ESP_LOG_BUFFER_HEXDUMP(TAG, resp, r, ESP_LOG_WARN);
            }
            return -1;
        }

        // Mantém compatibilidade com o resto do seu pipeline (int16_t como no legado)
        if (value_u32 > 32767) {
            if (PrintDebug) ESP_LOGW(TAG, "Valor PPPoE muito alto (%lu). Saturando em 32767.", (unsigned long)value_u32);
            return 32767;
        }

        return (int16_t)value_u32;
}

void f_RegisterPPPoEOidTarget(const char *ip, int port, int display, snmp_pppoe_oid_profile_t profile, const char *custom_oid) {
        if (!ip) return;
        if (total_pppoe_oid_targets >= MAX_PPPOE_OID_TARGETS) return;

        // Se já existir, atualiza
        int idx = f_FindPPPoEOidTargetIndex(ip, port);
        if (idx >= 0) {
            pppoe_oid_targets[idx].display = display;
            pppoe_oid_targets[idx].profile = profile;

            safe_free(&pppoe_oid_targets[idx].custom_oid);
            if (profile == PPPoE_OID_PROFILE_CUSTOM && custom_oid && custom_oid[0] != '\0') {
                pppoe_oid_targets[idx].custom_oid = strdup(custom_oid);
            } else {
                pppoe_oid_targets[idx].custom_oid = NULL;
            }
            return;
        }

        PPPoEOidTarget *t = &pppoe_oid_targets[total_pppoe_oid_targets];

        t->ip = strdup(ip);
        t->port = port;
        t->display = display;
        t->profile = profile;

        if (profile == PPPoE_OID_PROFILE_CUSTOM && custom_oid && custom_oid[0] != '\0') {
            t->custom_oid = strdup(custom_oid);
        } else {
            t->custom_oid = NULL;
        }

        total_pppoe_oid_targets++;
}

int f_GetPPPoEOidDisplay(const char *ip, int port) {
    int idx = f_FindPPPoEOidTargetIndex(ip, port);
    if (idx < 0) return -1;
    return pppoe_oid_targets[idx].display;
}

bool f_IsPPPoEOidTarget(const char *ip, int port) {
    return (f_FindPPPoEOidTargetIndex(ip, port) >= 0);
}

void f_LiberaPPPoEOidTargets(void) {
    for (int i = 0; i < total_pppoe_oid_targets; i++) {
        safe_free(&pppoe_oid_targets[i].ip);
        safe_free(&pppoe_oid_targets[i].custom_oid);
    }
    total_pppoe_oid_targets = 0;
}

void f_ProcessaPPPoECountOid(int sock, const char *ip, int port, struct sockaddr_in *dest, const char *community, bool PrintDebug) {
        if (!ip || !dest || !community) return;

        int idx = f_FindPPPoEOidTargetIndex(ip, port);
        if (idx < 0) return;

        int display = pppoe_oid_targets[idx].display - 1;
        if (display < 0) return;

        const char *oid_str = f_GetPPPoEOidByProfile(pppoe_oid_targets[idx].profile, pppoe_oid_targets[idx].custom_oid);

        if (!oid_str) {
            if (PrintDebug) ESP_LOGW(TAG, "OID profile inválido para %s:%d", ip, port);
            return;
        }

        int16_t pppoe_total = f_PPPoECountByOid(sock, dest, community, oid_str, PrintDebug);

        if (Device[display].xQueue != NULL && f_DeviceServico(Device[display].Servico, SNMP_PPPoE_Count)) {
            xQueueOverwrite(Device[display].xQueue, &pppoe_total);
            xQueueOverwrite(Device[display].xQueueAlarme, &pppoe_total);
            xQueueOverwrite(Device[display].xQueueMqtt, &pppoe_total);
            xQueueOverwrite(Device[display].xQueueDashzap, &pppoe_total);

            if (PrintDebug) {
                ESP_LOGI(TAG, "PPPoE(OID) %s:%d oid=%s → %d", ip, port, oid_str, pppoe_total);
            }
        } else {
            if (PrintDebug) {
                ESP_LOGW(TAG, "Device %s:%d (Display %d) does not have queue for PPPoE", ip, port, display + 1);
            }
        }
}
