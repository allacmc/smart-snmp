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
                    if (!json_existente) { ESP_LOGW(TAG, "Arquivo existente não encontrado. Criando novo."); json_existente = cJSON_CreateObject(); }
                    cJSON *item = NULL;
                    cJSON_ArrayForEach(item, json_novo) {
                        const char *key = item->string;
                        if (!cJSON_HasObjectItem(json_existente, key)) {
                            cJSON_AddItemToObject(json_existente, key, cJSON_Duplicate(item, true));
                        } 
                    }
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
