#include "snmp_main.h"
#include "snmp_client.h"
#include "snmp_lib.h"
#include "esp_log.h"
#include "string.h"
#include "snmp_lib.h"
#include "lwip/sockets.h"
#include <string.h>
#include <errno.h>
#include "../../enervision_manager/include/f_wifi.h"
#include "../../enervision_manager/include/f_configfile.h"
#include "../../enervision_manager/include/f_safefree.h"
#include <arpa/inet.h>  // já incluso pelo netdb/socket normalmente

#include "snmp_read-interface.h"
#include "snmp_defs.h"
#define SNMP_PORT 161
static const char *TAG = "SNMP_CLIENT";
static bool StatusScan = false;
static void f_SelectInterfaces(void *args);

static bool PrintDebugSNMP = false;
static void debug_dispositivos(IPInfo *dispositivos, int total_ips);

char* clean_json_string(const char* input) {
    size_t len = strlen(input);
    char* output = (char*)malloc(len + 1);
    if (!output) {
        return NULL;
    }

    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (isprint((unsigned char)input[i]) && !isspace((unsigned char)input[i])) {
            output[j++] = input[i];
        }
    }
    output[j] = '\0';
    return output;
}

char* f_scan_snmp_status_cb() {
    char *html_content = malloc(512); // Aloca memória dinamicamente
    if (html_content != NULL) {
        int InterfaceDiscovery = f_iDiscoveryCount();
        if(StatusScan){
            snprintf(html_content, 512, "{\"status\": \"run\", \"interfaces_discovered\": %d}", InterfaceDiscovery);
        }else{      
            snprintf(html_content, 512, "{\"status\": \"stop\", \"interfaces_discovered\": %d}", InterfaceDiscovery);
        }
        char* clean_html_content = clean_json_string(html_content);
        free(html_content);
        return clean_html_content;  
    }
    return NULL;
}

char* f_scan_snmp_cb() {
    xTaskCreate(f_startListInterfaces, "f_startListInterfaces", 4096, NULL, 5, NULL);
    char *html_content = malloc(512); // Aloca memória dinamicamente
    if (html_content != NULL) {
        snprintf(html_content, 512, "{\"message\": \"Scan Started\"}");
        char* clean_html_content = clean_json_string(html_content);
        free(html_content);
        return clean_html_content;
    }
    return NULL;
}

void f_startListInterfaces(void * args) {
        while (!f_Wifi_Conectado()){vTaskDelay(pdMS_TO_TICKS(100));}
        xTaskCreate(f_ScanInterface, "f_ScanInterface", 6000, NULL, 5, NULL);
        vTaskDelete(NULL);    
}

void f_ScanInterface(void *args) {
        StatusScan = true;
        f_stopReadInterfaces();
        while (f_StatusReadInterface() != STOPPED) {vTaskDelay(pdMS_TO_TICKS(100));}
        vTaskDelay(pdMS_TO_TICKS(2000));
        const char * ip_address  = f_KeyValue("DeviceIP", "/snmp-scan.json");
        if (!ip_address || inet_addr(ip_address) == INADDR_NONE) { ESP_LOGE(TAG, "Endereço IP inválido: %s", ip_address ? ip_address : "NULL"); StatusScan = false;vTaskDelete(NULL); return; }
        const char * port_str = f_KeyValue("DevicePort", "/snmp-scan.json");
        if (!port_str) { ESP_LOGE(TAG, "Campo DevicePort não encontrado."); vTaskDelete(NULL); return; }
        char *endptr;
        long port = strtol(port_str, &endptr, 10);
        if (endptr == port_str || port <= 0 || port > 65535) { ESP_LOGE(TAG, "Porta SNMP inválida: '%s'", port_str); StatusScan = false;vTaskDelete(NULL); return; }
        int timeout_val = f_KeyValueInt("Timeout", "/snmp-scan.json");
        if (timeout_val < 2 || timeout_val > 30) { ESP_LOGE(TAG, "Timeout inválido: %d. O valor deve estar entre 2 e 20.", timeout_val); StatusScan = false;vTaskDelete(NULL); return; }
        int maxInterface_val = f_KeyValueInt("MaxInterface", "/snmp-scan.json");
        if (maxInterface_val < 1 || maxInterface_val > 128) { ESP_LOGE(TAG, "Timeout inválido: %d. O valor deve estar entre 2 e 20.", maxInterface_val); StatusScan = false;vTaskDelete(NULL); return; }
        ESP_LOGI(TAG, "Iniciando task de Scan SNMP para %s na porta %ld, timeout %d, max-interface %d", ip_address, port, timeout_val, maxInterface_val);
        const char * community = f_KeyValue("Community", "/snmp-scan.json");
        if (!community || strlen(community) == 0) { ESP_LOGE(TAG, "Campo Community inválido ou não encontrado."); StatusScan = false; vTaskDelete(NULL); return; }
        esp_err_t result = f_ListInterfaces(ip_address, port, timeout_val, maxInterface_val, community);
        int discovered_interfaces = f_iDiscoveryCount();
        ESP_LOGI(TAG, "Listagem de interfaces %s. Interfaces descobertas: %d",(result == ESP_OK) ? "concluída" : esp_err_to_name(result), discovered_interfaces);
        StatusScan = false;
        vTaskDelete(NULL);
}

void f_startSelectInterfaces() {
    xTaskCreate(f_SelectInterfaces, "f_SelectInterfaces", 4096, NULL, 5, NULL);
}

static void f_SelectInterfaces(void *args) {
            ESP_LOGI(TAG, "Iniciando tarefa de seleção de interfaces SNMP");
            vTaskDelay(pdMS_TO_TICKS(500));
            char *json_data = f_lerArquivo("/snmp.json"); if (!json_data) { ESP_LOGE(TAG, "Falha ao ler o arquivo JSON"); vTaskDelete(NULL); return; }
            cJSON *json_novo = cJSON_Parse(json_data); safe_free(&json_data); if (!json_novo) { ESP_LOGE(TAG, "Erro ao analisar o JSON"); vTaskDelete(NULL); return; }
            cJSON *snmp_action = cJSON_GetObjectItem(json_novo, "snmpAction"); if (!cJSON_IsString(snmp_action) || snmp_action->valuestring == NULL) { ESP_LOGE(TAG, "Chave snmpAction ausente ou inválida"); cJSON_Delete(json_novo); vTaskDelete(NULL); return; }
            if (strcmp(snmp_action->valuestring, "substituir") == 0) {
                    if (saveJsonToFile("/snmp-interface-select.json", json_novo) == 0) {
                        ESP_LOGI(TAG, "Arquivo snmp-interface-select.json criado com sucesso");
                    } else {
                        ESP_LOGE(TAG, "Erro ao salvar o arquivo snmp-interface-select.json");
                    }
            } else if (strcmp(snmp_action->valuestring, "adicionar") == 0) {
                cJSON *json_existente = read_json_file("/snmp-interface-select.json");
                if (!json_existente) {
                    ESP_LOGW(TAG, "Arquivo existente não encontrado. Criando novo.");
                    json_existente = cJSON_CreateObject();
                }
            
                mergeJsonWithReindex(json_existente, json_novo);  // 👈 aqui tá o pulo do gato
            
                cJSON_DeleteItemFromObject(json_existente, "snmpAction");
                cJSON_DeleteItemFromObject(json_existente, "xx");
            
                if (saveJsonToFile("/snmp-interface-select.json", json_existente) == 0) {
                    ESP_LOGI(TAG, "Arquivo snmp-interface-select.json atualizado com sucesso");
                } else {
                    ESP_LOGE(TAG, "Erro ao atualizar o arquivo snmp-interface-select.json");
                }
                cJSON_Delete(json_existente);
            }        
            cJSON_Delete(json_novo);
            vTaskDelete(NULL);
}


void f_startAddCustomOID() {
    xTaskCreate(f_AdicionarCustomOID, "f_SelectInterfaces", 4096, NULL, 5, NULL);
}

void f_AdicionarCustomOID() {
        ESP_LOGI("CUSTOM_OID", "Iniciando adição de SNMP Custom OID");

        char *json_str = f_lerArquivo("/snmp-custom-oid.json");
        if (!json_str) {
            ESP_LOGE("CUSTOM_OID", "Erro ao ler snmp-custom-oid.json");
            return;
        }

        cJSON *json_custom = cJSON_Parse(json_str);
        safe_free(&json_str);
        if (!json_custom) {
            ESP_LOGE("CUSTOM_OID", "Erro ao fazer parse do JSON custom");
            return;
        }

        // Verifica se os campos obrigatórios estão presentes
        cJSON *ip_item = cJSON_GetObjectItem(json_custom, "IP");
        cJSON *port_item = cJSON_GetObjectItem(json_custom, "Port");
        cJSON *community_item = cJSON_GetObjectItem(json_custom, "Community");

        if (!cJSON_IsString(ip_item) || !cJSON_IsString(port_item) || !cJSON_IsString(community_item)) {
            ESP_LOGE("CUSTOM_OID", "Campos IP, Port ou Community ausentes ou inválidos no JSON");
            cJSON_Delete(json_custom);
            return;
        }

        const char *ip = ip_item->valuestring;
        const char *porta = port_item->valuestring;
        const char *community = community_item->valuestring;

        cJSON *json_destino = read_json_file("/snmp-interface-select.json");
        if (!json_destino) {
            ESP_LOGW("CUSTOM_OID", "Arquivo snmp-interface-select.json não existe. Criando novo.");
            json_destino = cJSON_CreateObject();
        }

        int maior_indice = -1;
        cJSON *item = NULL;
        cJSON_ArrayForEach(item, json_destino) {
            const char *key = item->string;
            const char *abre = strchr(key, '[');
            const char *fecha = strchr(key, ']');
            if (abre && fecha && fecha > abre) {
                char idx_str[16] = {0};
                strncpy(idx_str, abre + 1, fecha - abre - 1);
                int idx = atoi(idx_str);
                if (idx > maior_indice) maior_indice = idx;
            }
        }

        int novo_indice = maior_indice + 1;
        char idx_str[16];
        snprintf(idx_str, sizeof(idx_str), "%d", novo_indice);
        char key[64];

        snprintf(key, sizeof(key), "selectedRow[%s]", idx_str);
        cJSON_AddStringToObject(json_destino, key, "on");

        snprintf(key, sizeof(key), "IP[%s]", idx_str);
        cJSON_AddStringToObject(json_destino, key, ip);

        snprintf(key, sizeof(key), "Port[%s]", idx_str);
        cJSON_AddStringToObject(json_destino, key, porta);

        snprintf(key, sizeof(key), "Community[%s]", idx_str);
        cJSON_AddStringToObject(json_destino, key, community);

        snprintf(key, sizeof(key), "index[%s]", idx_str);
        cJSON_AddStringToObject(json_destino, key, "999");

        snprintf(key, sizeof(key), "name[%s]", idx_str);
        cJSON_AddStringToObject(json_destino, key, "Custom OID");

        snprintf(key, sizeof(key), "status[%s]", idx_str);
        cJSON_AddStringToObject(json_destino, key, "UP");

        snprintf(key, sizeof(key), "type[%s]", idx_str);
        cJSON_AddStringToObject(json_destino, key, "999");

        snprintf(key, sizeof(key), "tipoSelecionado[%s]", idx_str);
        cJSON_AddStringToObject(json_destino, key, "Custom");

        snprintf(key, sizeof(key), "displaySelecionado[%s]", idx_str);
        cJSON_AddStringToObject(json_destino, key, cJSON_GetObjectItem(json_custom, "snmp-custom-display")->valuestring);

        snprintf(key, sizeof(key), "customOid[%s]", idx_str);
        cJSON_AddItemToObject(json_destino, key, cJSON_Duplicate(cJSON_GetObjectItem(json_custom, "customOid"), 1));

        snprintf(key, sizeof(key), "operationType[%s]", idx_str);
        cJSON_AddItemToObject(json_destino, key, cJSON_Duplicate(cJSON_GetObjectItem(json_custom, "operationType"), 1));

        snprintf(key, sizeof(key), "operationFactor[%s]", idx_str);
        cJSON_AddItemToObject(json_destino, key, cJSON_Duplicate(cJSON_GetObjectItem(json_custom, "operationFactor"), 1));

        snprintf(key, sizeof(key), "unitSuffix[%s]", idx_str);
        cJSON_AddItemToObject(json_destino, key, cJSON_Duplicate(cJSON_GetObjectItem(json_custom, "unitSuffix"), 1));

        cJSON_DeleteItemFromObject(json_destino, "xx");

        if (saveJsonToFile("/snmp-interface-select.json", json_destino) == 0) {
            ESP_LOGI("CUSTOM_OID", "Arquivo snmp-interface-select.json atualizado com sucesso!");
        } else {
            ESP_LOGE("CUSTOM_OID", "Erro ao salvar snmp-interface-select.json");
        }

        cJSON_Delete(json_custom);
        cJSON_Delete(json_destino);
        vTaskDelete(NULL);
}

TaskHandle_t hReadInterface = NULL;

void f_startReadInterfaces() {
    while (!f_Wifi_Conectado()){vTaskDelay(pdMS_TO_TICKS(100));}
    if (hReadInterface == NULL) {
        xTaskCreate(f_ReadInterfaces, "f_ReadInterfaces", 6500, NULL, 5, &hReadInterface);
    } else {
        ESP_LOGW(TAG, "Tarefa de leitura de status da Interface SNMP já está em execução");
    }
}

void f_ReadInterfaces(void *args) {
        ESP_LOGI(TAG, "Iniciando monitoramento automático de interfaces SNMP");
        IPInfo dispositivos[MAX_IPS] = {0};
        int total_ips = f_PopulaDispositivos(dispositivos, MAX_IPS);
        if (total_ips <= 0) {
            ESP_LOGE(TAG, "Nenhum dispositivo válido encontrado");
            hReadInterface = NULL;
            vTaskDelete(NULL);
            return;
        }
        PrintDebugSNMP = f_KeyStatus("DebugSNMP", "/setup.json");
        if(PrintDebugSNMP){debug_dispositivos(dispositivos, total_ips);}
        f_ExecutaLeituraSNMP(dispositivos, total_ips);
        f_LiberaDispositivos(dispositivos, total_ips);
        ESP_LOGI(TAG, "Encerrando leitura automática de interfaces SNMP");
        hReadInterface = NULL;
        vTaskDelete(NULL);
}

f_StatusReadInterface_t f_StatusReadInterface() {
    if (hReadInterface != NULL) {
        return RUNNING;
    } else {
        return STOPPED;
    }
}

static void debug_dispositivos(IPInfo *dispositivos, int total_ips) {
    ESP_LOGW(TAG, "Inicio");
    for (int i = 0; i < total_ips; i++) {
        ESP_LOGI(TAG, "Dispositivo #%d", i);
        ESP_LOGI(TAG, "  IP: %s", dispositivos[i].ip);
        ESP_LOGI(TAG, "  Porta: %d", dispositivos[i].port);
        ESP_LOGI(TAG, "  Community: %s", dispositivos[i].community);
        ESP_LOGI(TAG, "  Total OIDs: %d", dispositivos[i].total_oids);
        for (int j = 0; j < dispositivos[i].total_oids; j++) {
            ESP_LOGI(TAG, "    OID #%d:", j);
            ESP_LOGI(TAG, "      OID: %s", dispositivos[i].oids[j].oid);
            ESP_LOGI(TAG, "      Display: %s", dispositivos[i].oids[j].display);
            ESP_LOGI(TAG, "      Tipo: %d", dispositivos[i].oids[j].tipo); // pode mapear esse enum depois se quiser
        }
    }
    ESP_LOGW(TAG, "Fim");
}

bool f_GetPrintDebugSNMP() {return PrintDebugSNMP;}