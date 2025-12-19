#include "snmp_lib.h"
#include <string.h>
#include <stdbool.h>
#include "esp_log.h"
#include <stdio.h> // Adicionado para declarar printf
#include <stdint.h>
#include "cJSON.h"

//static const char *TAG = "SNMP_PARSER";

int build_snmp_get(uint8_t *buffer, size_t max_len, const uint8_t *oid, size_t oid_len, uint8_t request_id, const char *community) {
            if (max_len < 64 || oid_len > 32) return -1; // Limite simples

            int pos = 0;

            buffer[pos++] = 0x30; // Sequence
            buffer[pos++] = 0x00; // Placeholder total length

            buffer[pos++] = 0x02; buffer[pos++] = 0x01; buffer[pos++] = 0x01; // SNMP v2c

            // buffer[pos++] = 0x04; buffer[pos++] = 0x06;
            // memcpy(&buffer[pos], "public", 6); pos += 6;

                size_t comm_len = strlen(community);
                buffer[pos++] = 0x04;
                buffer[pos++] = comm_len;
                memcpy(&buffer[pos], community, comm_len);
                pos += comm_len;


            buffer[pos++] = 0xA0; buffer[pos++] = 0x00; // GetRequest
            int pdu_start = pos;

            buffer[pos++] = 0x02; buffer[pos++] = 0x04;
            buffer[pos++] = 0x00; buffer[pos++] = 0x00;
            buffer[pos++] = 0x00; buffer[pos++] = request_id;

            buffer[pos++] = 0x02; buffer[pos++] = 0x01; buffer[pos++] = 0x00; // error
            buffer[pos++] = 0x02; buffer[pos++] = 0x01; buffer[pos++] = 0x00; // error index

            buffer[pos++] = 0x30; buffer[pos++] = 0x00; // VarBind list
            int vb_start = pos;

            buffer[pos++] = 0x30; buffer[pos++] = 0x00; // VarBind
            int vb_inner_start = pos;

            buffer[pos++] = 0x06; buffer[pos++] = oid_len;
            memcpy(&buffer[pos], oid, oid_len); pos += oid_len;

            buffer[pos++] = 0x05; buffer[pos++] = 0x00; // NULL

            // Tamanhos internos
            buffer[vb_inner_start - 1] = pos - vb_inner_start;
            buffer[vb_start - 1] = pos - vb_start;
            buffer[pdu_start - 1] = pos - pdu_start;
            buffer[1] = pos - 2;

            return pos;
}

const char *f_GetOperStatusString(int oper_status) {
    switch (oper_status) {
        case 1: return "UP";
        case 2: return "DOWN";
        case 3: return "TESTING";
        case 4: return "UNKNOWN";
        case 5: return "DORMANT";
        case 6: return "NOT_PRESENT";
        case 7: return "LOWER_LAYER_DOWN";
        default: return "???";
    }
}

bool parse_snmp_string_value(const uint8_t *buffer, int len, char *out, size_t out_size) {
    if (!buffer || len <= 0 || !out || out_size == 0) return false;

    bool found_oid = false;

    for (int i = 0; i < len - 2; i++) {
        uint8_t tag = buffer[i];
        uint8_t length = buffer[i + 1];

        if (i + 2 + length > len) continue;

        if (tag == 0x06) {
            // Encontramos o OID
            found_oid = true;
            i += 1 + length; // pula o OID
        }
        else if (tag == 0x04 && found_oid) {
            // OCTET STRING logo após o OID
            if (length == 0 || length >= out_size) return false;

            memcpy(out, &buffer[i + 2], length);
            out[length] = '\0';

            ESP_LOGD("SNMP_PARSER", "String SNMP extraída: \"%s\"", out);
            return true;
        }
    }

    //ESP_LOGW("SNMP_PARSER", "Não foi possível extrair uma OCTET STRING após o OID.");
    return false;
}

bool parse_snmp_integer_value(const uint8_t *buffer, int len, int *out_value) {
    if (!buffer || len <= 0 || !out_value) return false;

    for (int i = 0; i < len - 2; i++) {
        if (buffer[i] == 0x06) { // OID
            uint8_t oid_len = buffer[i + 1];
            int oid_total_len = 2 + oid_len;

            if (i + oid_total_len + 2 >= len) continue; // espaço pro INTEGER

            int val_pos = i + oid_total_len;

            if (buffer[val_pos] == 0x02) { // INTEGER logo após OID
                uint8_t int_len = buffer[val_pos + 1];

                if (int_len == 0 || int_len > 4 || val_pos + 2 + int_len > len) {
                    continue;
                }

                int value = 0;
                for (int b = 0; b < int_len; b++) {
                    value = (value << 8) | buffer[val_pos + 2 + b];
                }

                *out_value = value;
                return true;
            }
        }
    }

    ESP_LOGW("SNMP_PARSER", "Não foi possível extrair valor INTEGER após OID.");
    return false;
}

bool parse_snmp_uint32_value(const uint8_t *buffer, int len, uint32_t *out_value) {
    if (!buffer || len <= 0 || !out_value) return false;

    int int_found = 0;

    for (int i = 0; i < len - 2; i++) {
        //if (buffer[i] == 0x02 || buffer[i] == 0x42) {  // INTEGER ou Gauge32
        if (buffer[i] == 0x02 || buffer[i] == 0x41 || buffer[i] == 0x42 || buffer[i] == 0x43) {
            uint8_t val_len = buffer[i + 1];
            if (val_len == 0 || val_len > 4 || i + 2 + val_len > len) continue;

            int_found++;

            // Ignora os 4 primeiros inteiros (versão, request-id, error, index)
            if (int_found <= 4) continue;

            uint32_t value = 0;
            for (int b = 0; b < val_len; b++) {
                value = (value << 8) | buffer[i + 2 + b];
            }

            *out_value = value;
            return true;
        }
    }

    ESP_LOGW("SNMP_PARSER", "Não foi possível extrair uint32 após os 4 primeiros INTEGERs.");
    return false;
}

char *print_oid_readable(const uint8_t *oid, size_t oid_len) {
    if (!oid || oid_len < 2) return NULL;

    static char oid_str[256];
    size_t pos = 0;

    // Primeiro byte é codificação de dois primeiros números
    uint8_t first = oid[0];
    pos += snprintf(oid_str + pos, sizeof(oid_str) - pos, "%u.%u", first / 40, first % 40);

    size_t i = 1;
    while (i < oid_len && pos < sizeof(oid_str) - 1) {
        uint32_t value = 0;
        do {
            value = (value << 7) | (oid[i] & 0x7F);
        } while ((oid[i++] & 0x80) && i < oid_len);

        pos += snprintf(oid_str + pos, sizeof(oid_str) - pos, ".%lu", (unsigned long)value);
    }

    oid_str[sizeof(oid_str) - 1] = '\0'; // Garantir terminação
    return oid_str;
}

bool parse_oid_string(const char *oid_str, uint8_t *oid_out, size_t *oid_len_out) {
    if (!oid_str || !oid_out || !oid_len_out) return false;

    char oid_copy[128];
    strncpy(oid_copy, oid_str, sizeof(oid_copy));
    oid_copy[sizeof(oid_copy) - 1] = '\0';

    char *token = strtok(oid_copy, ".");
    int subids[32];
    int subid_count = 0;

    while (token && subid_count < 32) {
        subids[subid_count++] = atoi(token);
        token = strtok(NULL, ".");
    }

    if (subid_count < 2) return false;

    // Primeiro byte: (first * 40) + second
    int pos = 0;
    oid_out[pos++] = (uint8_t)(subids[0] * 40 + subids[1]);

    for (int i = 2; i < subid_count; i++) {
        uint32_t val = subids[i];
        uint8_t temp[5];  // Máximo 5 bytes para codificar uint32
        int temp_pos = 0;

        // Codifica em base 128 com MSB = 1 nos bytes intermediários
        do {
            temp[temp_pos++] = val & 0x7F;
            val >>= 7;
        } while (val > 0);

        // Escreve os bytes em ordem reversa, com MSB setado corretamente
        for (int j = temp_pos - 1; j >= 0; j--) {
            oid_out[pos++] = temp[j] | (j == 0 ? 0x00 : 0x80);
        }
    }
    *oid_len_out = pos;
    if (*oid_len_out < 2) return false;
    return true;
}

bool parse_snmp_counter32_value(const uint8_t *packet, int length, uint32_t *out_value) {
    if (!packet || !out_value || length <= 0) return false;

    for (int i = 0; i < length - 2; i++) {
        // Procura pelo tipo Counter32 (0x41)
        if (packet[i] == 0x41) {
            uint8_t len = packet[i + 1];
            if (len > 5 || i + 2 + len > length) return false;  // valor inválido

            uint32_t value = 0;
            for (int j = 0; j < len; j++) {
                value <<= 8;
                value |= packet[i + 2 + j];
            }

            *out_value = value;
            return true;
        }
    }

    return false;  // não achou o tipo Counter32
}

const char *f_GetBaseOID(MIBMetric metric) {
    switch (metric) {
        case MIB_IF_OPER_STATUS:
            return "1.3.6.1.2.1.2.2.1.8.";
        case MIB_IF_IN_OCTETS:
            return "1.3.6.1.2.1.2.2.1.10.";
        case MIB_IF_OUT_OCTETS:
            return "1.3.6.1.2.1.2.2.1.16.";
        case MIB_IF_SPEED:
            return "1.3.6.1.2.1.2.2.1.5.";
        case MIB_IF_DESCR:
            return "1.3.6.1.2.1.2.2.1.2.";
        default:
            return NULL;
    }
}


void f_FormatTraffic(char *out, size_t len, float kbps) {
    if (kbps >= 1000000.0f) {
        snprintf(out, len, "%.2f Gbps", kbps / 1000000.0f);
    } else if (kbps >= 1000.0f) {
        snprintf(out, len, "%.2f Mbps", kbps / 1000.0f);
    } else {
        snprintf(out, len, "%.2f kbps", kbps);
    }
}

int build_snmp_getnext(uint8_t *buffer, size_t max_len, const uint8_t *oid, size_t oid_len, uint8_t request_id, const char *community) {
    if (max_len < 64 || oid_len > 32) return -1;

    int pos = 0;

    buffer[pos++] = 0x30; // Sequence
    buffer[pos++] = 0x00; // Placeholder total length

    buffer[pos++] = 0x02; buffer[pos++] = 0x01; buffer[pos++] = 0x01; // SNMP v2c

    // buffer[pos++] = 0x04; buffer[pos++] = 0x06;
    // memcpy(&buffer[pos], "public", 6); pos += 6;

        size_t comm_len = strlen(community);
        buffer[pos++] = 0x04;
        buffer[pos++] = comm_len;
        memcpy(&buffer[pos], community, comm_len);
        pos += comm_len;


    buffer[pos++] = 0xA1; buffer[pos++] = 0x00; // ← GETNEXT (A1)
    int pdu_start = pos;

    buffer[pos++] = 0x02; buffer[pos++] = 0x04;
    buffer[pos++] = 0x00; buffer[pos++] = 0x00;
    buffer[pos++] = 0x00; buffer[pos++] = request_id;

    buffer[pos++] = 0x02; buffer[pos++] = 0x01; buffer[pos++] = 0x00; // error
    buffer[pos++] = 0x02; buffer[pos++] = 0x01; buffer[pos++] = 0x00; // error index

    buffer[pos++] = 0x30; buffer[pos++] = 0x00; // VarBind list
    int vb_start = pos;

    buffer[pos++] = 0x30; buffer[pos++] = 0x00; // VarBind
    int vb_inner_start = pos;

    buffer[pos++] = 0x06; buffer[pos++] = oid_len;
    memcpy(&buffer[pos], oid, oid_len); pos += oid_len;

    buffer[pos++] = 0x05; buffer[pos++] = 0x00; // NULL

    // Tamanhos
    buffer[vb_inner_start - 1] = pos - vb_inner_start;
    buffer[vb_start - 1] = pos - vb_start;
    buffer[pdu_start - 1] = pos - pdu_start;
    buffer[1] = pos - 2;

    return pos;
}

bool parse_oid_from_packet(const uint8_t *packet, int len, uint8_t *out_oid, size_t *out_len) {
    if (!packet || len <= 0 || !out_oid || !out_len) return false;

    // procura pela sequência "30 ?? 30 ?? 06 ?? <OID>"
    for (int i = 0; i < len - 6; i++) {
        if (packet[i] == 0x30 &&             // sequence (VarBindList)
            packet[i+2] == 0x30 &&           // sequence (VarBind)
            packet[i+4] == 0x06) {           // OID

            uint8_t oid_len = packet[i+5];
            if (i + 6 + oid_len > len) return false;

            memcpy(out_oid, &packet[i + 6], oid_len);
            *out_len = oid_len;
            return true;
        }
    }

    return false;
}

char *print_oid_readable_from_packet(const uint8_t *packet, int len) {
    static char oid_str[256];
    uint8_t oid[32];
    size_t oid_len = 0;

    if (!parse_oid_from_packet(packet, len, oid, &oid_len)) return NULL;

    size_t pos = 0;
    uint8_t first = oid[0];
    pos += snprintf(oid_str + pos, sizeof(oid_str) - pos, "%u.%u", first / 40, first % 40);

    for (size_t i = 1; i < oid_len; ) {
        uint32_t value = 0;
        do {
            value = (value << 7) | (oid[i] & 0x7F);
        } while ((oid[i++] & 0x80) && i < oid_len);
        pos += snprintf(oid_str + pos, sizeof(oid_str) - pos, ".%lu", value);
    }

    oid_str[sizeof(oid_str) - 1] = '\0';
    return oid_str;
}

void f_FormatUptime(uint32_t ticks, char *out_str, size_t out_len) {
        uint32_t total_secs = ticks / 100;
        uint32_t days = total_secs / 86400;
        uint32_t hours = (total_secs % 86400) / 3600;
        uint32_t minutes = (total_secs % 3600) / 60;
        uint32_t seconds = total_secs % 60;

        snprintf(out_str, out_len, "%lu dias, %02lu:%02lu:%02lu", days, hours, minutes, seconds);
}

bool parse_snmp_timeticks_value(const uint8_t *packet, int length, uint32_t *out_value) {
    if (!packet || !out_value || length <= 0) return false;

    for (int i = 0; i < length - 2; i++) {
        if (packet[i] == 0x43) {  // ← tipo TimeTicks (Application[3])
            uint8_t len = packet[i + 1];
            if (len > 5 || i + 2 + len > length) return false;

            uint32_t value = 0;
            for (int j = 0; j < len; j++) {
                value = (value << 8) | packet[i + 2 + j];
            }

            *out_value = value;
            return true;
        }
    }

    return false;
}

void mergeJsonWithReindex(cJSON *destino, cJSON *origem) {
    int maior_indice = -1;
    cJSON *item = NULL;

    // 1. Achar o maior índice atual do destino
    cJSON_ArrayForEach(item, destino) {
        const char *key = item->string;
        const char *abre = strchr(key, '[');
        const char *fecha = strchr(key, ']');
        if (abre && fecha && fecha > abre) {
            char idx_str[8] = {0};
            strncpy(idx_str, abre + 1, fecha - abre - 1);
            int idx = atoi(idx_str);
            if (idx > maior_indice) maior_indice = idx;
        }
    }

    // 2. Mapear os índices usados no JSON novo
    typedef struct { char original[8]; } IndexMap;
    IndexMap blocos[32];
    int total_blocos = 0;

    cJSON_ArrayForEach(item, origem) {
        const char *key = item->string;
        const char *abre = strchr(key, '[');
        const char *fecha = strchr(key, ']');
        if (abre && fecha && fecha > abre) {
            char idx_str[8] = {0};
            strncpy(idx_str, abre + 1, fecha - abre - 1);
            bool ja_existe = false;
            for (int i = 0; i < total_blocos; i++) {
                if (strcmp(blocos[i].original, idx_str) == 0) {
                    ja_existe = true;
                    break;
                }
            }
            if (!ja_existe) {
                strncpy(blocos[total_blocos++].original, idx_str, sizeof(blocos[0].original));
            }
        }
    }

    // 3. Pra cada bloco, criar novo índice e copiar todas as chaves relacionadas
    for (int i = 0; i < total_blocos; i++) {
        const char *old_idx = blocos[i].original;
        int new_idx = ++maior_indice;

        cJSON_ArrayForEach(item, origem) {
            const char *key = item->string;
            char busca[16];
            snprintf(busca, sizeof(busca), "[%s]", old_idx);
            if (strstr(key, busca)) {
                // gera nova chave com novo índice
                char nova_chave[64];
                char prefixo[32];
                strncpy(prefixo, key, strstr(key, "[") - key);
                prefixo[strstr(key, "[") - key] = '\0';
                snprintf(nova_chave, sizeof(nova_chave), "%s[%d]", prefixo, new_idx);
                cJSON_AddItemToObject(destino, nova_chave, cJSON_Duplicate(item, true));
            }
        }
    }
}

uint8_t parse_snmp_value_type(const uint8_t *resp, size_t len) {
    if (!resp || len < 2) return 0xFF;

    // Tenta encontrar o último VarBind
    for (size_t i = 0; i < len - 2; i++) {
        if (resp[i] == 0x06) {  // OID
            size_t oid_len = resp[i + 1];
            size_t next_type_pos = i + 2 + oid_len;
            if (next_type_pos < len) {
                return resp[next_type_pos];  // Tipo do valor
            }
        }
    }

    return 0xFF;
}

static bool ber_read_len(const uint8_t *buf, size_t len, size_t *pos, size_t *out_len) {
    if (*pos >= len) return false;

    uint8_t b = buf[(*pos)++];
    if ((b & 0x80) == 0) { // short form
        *out_len = b;
        return (*pos + *out_len <= len);
    }

    uint8_t n = b & 0x7F; // number of length bytes
    if (n == 0 || n > 4) return false;
    if (*pos + n > len) return false;

    size_t L = 0;
    for (uint8_t i = 0; i < n; i++) {
        L = (L << 8) | buf[(*pos)++];
    }
    *out_len = L;
    return (*pos + *out_len <= len);
}

bool parse_snmp_first_varbind_u32(const uint8_t *buf, size_t len, uint8_t *out_type, uint32_t *out_value) {
    if (!buf || len < 8 || !out_value) return false;
    for (size_t i = 0; i + 2 < len; i++) {
            if (buf[i] != 0x06) continue; // OID tag

            size_t pos = i + 1;
            size_t oid_len = 0;
            if (!ber_read_len(buf, len, &pos, &oid_len)) continue;

            // pula bytes do OID
            pos += oid_len;
            if (pos + 2 > len) continue;

            uint8_t vtype = buf[pos++];

            size_t vlen = 0;
            if (!ber_read_len(buf, len, &pos, &vlen)) continue;

            // agora buf[pos .. pos+vlen-1] é o valor
            uint32_t v = 0;
            if (vlen == 0 || vlen > 4) return false;

            for (size_t b = 0; b < vlen; b++) {
                v = (v << 8) | buf[pos + b];
            }

            if (out_type) *out_type = vtype;
            *out_value = v;
            return true;
    }

    return false;
}


//Essa função abaixo funcionava perfeito, no Scan Interface, Status Interface, PPPoE, Uptime, Trafego, só não funcionou no SNMP CUSTOM
//

// bool parse_oid_string(const char *oid_str, uint8_t *oid_out, size_t *oid_len_out) {
//         if (!oid_str || !oid_out || !oid_len_out) return false;

//         char oid_copy[128];
//         strncpy(oid_copy, oid_str, sizeof(oid_copy));
//         oid_copy[sizeof(oid_copy) - 1] = '\0';

//         char *token = strtok(oid_copy, ".");
//         int count = 0;

//         while (token && count < 32) {
//             int value = atoi(token);
//             if (count == 0) {
//                 if (value != 1) return false;
//             } else if (count == 1) {
//                 if (value != 3) return false;
//                 oid_out[0] = 40 * 1 + 3; // 0x2b
//             } else {
//                 oid_out[count - 1] = (uint8_t)value;
//             }

//             token = strtok(NULL, ".");
//             count++;
//         }

//         *oid_len_out = count - 1;
//         return true;
// }
