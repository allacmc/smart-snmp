# smart-snmp (Enervision Mega Dash)

Componente **SNMP “smart”** do ecossistema Enervision, usado em conjunto com o componente **enervision-manager** para realizar **descoberta (scan) de interfaces SNMP** e **monitoramento periódico** (Interface Status, Tráfego, PPPoE Count, Uptime e OIDs Customizados) em dispositivos SNMP via **UDP + Community**.

Este componente foi projetado para o produto **Enervision Mega Dash**, mas foi organizado de forma a ser reutilizável em outros firmwares/produtos baseados em ESP-IDF.

---

## Sumário

- [Visão geral](#visão-geral)
- [Principais recursos](#principais-recursos)
- [Arquitetura e fluxo](#arquitetura-e-fluxo)
- [Estrutura de arquivos](#estrutura-de-arquivos)
- [Dependências](#dependências)
- [Limites e considerações](#limites-e-considerações)
- [Configuração por arquivos JSON](#configuração-por-arquivos-json)
  - [`/config/snmp-setup.json`](#configsnmp-setupjson)
  - [`/config/setup.json`](#configsetupjson)
  - [`/config/snmp-scan.json`](#configsnmp-scanjson)
  - [`/config/snmp-interface-select.json`](#configsnmp-interface-selectjson)
  - [`/config/snmp.json` (seleção: substituir/adicionar)](#configsnmpjson-seleção-substituiradicionar)
  - [`/config/snmp-custom-oid.json` (inserção rápida de Custom OID)](#configsnmp-custom-oidjson-inserção-rápida-de-custom-oid)
  - Arquivo gerado: [`/config/ScanInterfaces.json`](#arquivo-gerado-configscaninterfacesjson)
- [API pública (funções principais)](#api-pública-funções-principais)
- [Integração no firmware](#integração-no-firmware)
- [Troubleshooting](#troubleshooting)
- [Extensões (como adicionar novas leituras)](#extensões-como-adicionar-novas-leituras)
- [Licença e notas](#licença-e-notas)

---

## Visão geral

O `smart-snmp` implementa um pipeline completo de SNMP para uso embarcado:

1. **Scan de interfaces** (ifDescr/ifOperStatus/ifType) a partir de um IP alvo, gravando resultados em JSON.
2. **Seleção de itens de monitoramento** via JSON de configuração (tipos: Interface, Tráfego, PPPoE, Uptime, Custom).
3. **Loop periódico** que abre socket UDP por device e executa as leituras SNMP configuradas.
4. **Publicação dos resultados** em filas/estruturas do firmware (ex.: `Device[display].xQueue...`), para atualização de display, alarme, MQTT, DashZap etc.

---

## Principais recursos

- **SNMP GET** e **GETNEXT** (SNMP v1 “community-based”) usando encoder/decoder leve.
- **Descoberta de interfaces** (`f_ListInterfaces`) com saída em `/config/ScanInterfaces.json`.
- Leitura periódica:
  - **Status de interface** (`ifOperStatus`)
  - **Tráfego** (in/out octets + cálculo de kbps)
  - **PPPoE Count (legado)** via varredura GETNEXT em `ifDescr` e match `<pppoe-`
  - **PPPoE Count via OID (rápido)** (Mikrotik/Huawei/Custom)
  - **Uptime** (`sysUpTime.0`)
  - **Custom OID** (INTEGER/Counter32/Gauge32/TimeTicks com operações divide/multiply e sufixo)
- **Modo DebugSNMP** para logs detalhados.
- “Plumbing” pronto para integração com Web UI: callbacks que retornam JSON de status/ação.

---

## Arquitetura e fluxo

Fluxo de alto nível (simplificado):

[Web UI / Config JSON]
|
v
/config/snmp-scan.json ------------------> f_ScanInterface() -> /config/ScanInterfaces.json
/config/snmp.json (substituir/adicionar) -> f_startSelectInterfaces() -> /config/snmp-interface-select.json
/config/snmp-interface-select.json ------> f_PopulaDispositivos() -> lista IPInfo + targets especiais
|
v
f_startReadSnmp() -> task t_SNMP (loop)
|
+--> f_ProcessaStatusInterface()
+--> f_ProcessaTrafegoSNMP()
+--> f_ProcessaPPPoECount() (legado)
+--> f_ProcessaPPPoECountOid() (OID rápido)
+--> f_ProcessaUptimeSNMP()
+--> f_ProcessaSNMPCustom()
|
v
[Device[display].xQueue / xQueueAlarme / xQueueMqtt / xQueueDashzap]

markdown
Copiar código

---

## Estrutura de arquivos

Principais módulos:

- `snmp_main.c/.h`  
  Orquestra tarefas (scan, seleção, start do loop de leitura) e expõe callbacks para web.
- `snmp_client.c/.h`  
  Execução SNMP em socket UDP (scan de interfaces, queries multi, helpers de parsing).
- `snmp_lib.c/.h`  
  Encoder/decoder SNMP (GET/GETNEXT), parsing ASN.1 básico, utilitários (OID, timeticks, merge JSON etc.).
- `snmp_read-interface.c/.h`  
  Lê `/config/snmp-interface-select.json`, monta `IPInfo[]`, registra “targets” (PPPoE/Uptime/Custom), executa o loop periódico e libera memória.
- `snmp_status-interface.c/.h`  
  Registro e leitura do `ifOperStatus`.
- `snmp_traffic.c/.h`  
  Registro e leitura de tráfego, cálculo de kbps com histórico por IP/display.
- `snmp_pppoe.c/.h`  
  PPPoE legado por varredura GETNEXT em `ifDescr`.
- `snmp_pppoe_oid.c/.h`  
  PPPoE por OID escalar (Mikrotik/Huawei/Custom).
- `snmp_uptime.c/.h`  
  Leitura de `sysUpTime.0` e envio para display/filas.
- `snmp_custom.c/.h`  
  Leitura de OIDs customizados, com operações e suporte a múltiplos tipos ASN.1.
- `snmp_sysname.c/.h`  
  Leitura de `sysName.0` para enriquecer o scan.

---

## Dependências

Este componente foi escrito para **ESP-IDF 5.x** e assume:

- **FreeRTOS** (tasks, delays, queues)
- **lwIP sockets** (`socket`, `sendto`, `recvfrom`, `setsockopt`, `close`)
- **cJSON**
- Funções utilitárias do seu projeto (via `enervision-manager` / firmware):
  - `f_Wifi_Conectado()`
  - `f_KeyValue()`, `f_KeyValueInt()`, `f_KeyStatus()`
  - `read_json_file()`, `saveJsonToFile()`, `f_lerArquivo()`, `mergeJsonWithReindex()`
  - `safe_free()`, `safe_strdup()`
  - Estrutura global `Device[]` e função `f_DeviceServico(...)` (para roteamento do dado por “serviço”)

Se você for reutilizar em outro produto, o caminho mais simples é manter um “adapter layer” com essas funções/estruturas, ou substituir por equivalentes do novo firmware.

---

## Limites e considerações

Constantes e limites atuais (ajustáveis em `snmp_defs.h` e módulos específicos):

- `MAX_IPS = 10` (máximo de dispositivos por ciclo de monitoramento)
- `MAX_OIDS = 20` (por IP; tráfego consome 2 OIDs por seleção)
- Targets especiais:
  - PPPoE legacy targets: até 16
  - PPPoE OID targets: até 16
  - Uptime targets: até 16
  - Custom targets: até 16
- Histórico de tráfego: `MAX_TRAFFIC_HISTORY = 64`
- Scan suporta `MaxInterface` até 128 (validado), podendo ser ajustado.

Observações de operação:

- Cada ciclo abre **um socket UDP por IP** e executa as leituras configuradas.
- Timeout do socket do loop periódico está fixado em 2s (em `f_ExecutaLeituraSNMP`) e o do scan é configurável (`/config/snmp-scan.json`).
- O componente é “read-only”: não implementa SET.

---

## Configuração por arquivos JSON

### `/config/snmp-setup.json`

Usado para habilitar e controlar intervalo do loop.

Exemplo:

```json
{
  "enable-snmp": "on",
  "IntervaloLeituraSNMP": 5000
}
enable-snmp: precisa estar “on” para f_startReadSnmp() iniciar.

IntervaloLeituraSNMP: intervalo em ms (default: 5000 se ausente/inválido).

/config/setup.json
Controla debug.

Exemplo:

json
Copiar código
{
  "DebugSNMP": "on"
}
Quando ligado, habilita logs em:

tráfego, status, custom e leitura geral.

/config/snmp-scan.json
Parâmetros do scan de interfaces.

Exemplo:

json
Copiar código
{
  "DeviceIP": "192.168.1.1",
  "DevicePort": "161",
  "Community": "public",
  "Timeout": 5,
  "MaxInterface": 64
}
Validações importantes:

IP válido

Porta 1..65535

Timeout 2..30

MaxInterface 1..128

/config/snmp-interface-select.json
É o “banco” principal do monitoramento. Este arquivo é lido por f_PopulaDispositivos() e define o que será monitorado.

Chaves (por linha i):

selectedRow[i] = "on" (marcado/ativo)

IP[i] = "x.x.x.x"

Port[i] = "161"

Community[i] ou community[i] = "public" (o código aceita ambos)

displaySelecionado[i] = "1".."N" (atenção: no runtime o display vira display-1)

tipoSelecionado[i] = um dos valores abaixo:

"Interface"

"Trafego"

"PPPoE-Count" (legado)

"PPPoE-Mikrotik" (OID rápido)

"PPPoE-Huawei" (OID rápido)

"Uptime"

"Custom"

index[i] = "1..N" (necessário para Interface/Tráfego; ignorado para PPPoE OID/Uptime/Custom)

Campos adicionais quando tipoSelecionado[i] == "Custom":

customOid[i] = "1.3.6.1...."

operationType[i] = "divide" | "multiply" | "none"

operationFactor[i] = "10" (string numérica; default 1)

unitSuffix[i] = "dBm" (default vazio)

Exemplo mínimo de duas linhas:

json
Copiar código
{
  "selectedRow[0]": "on",
  "IP[0]": "192.168.1.1",
  "Port[0]": "161",
  "Community[0]": "public",
  "displaySelecionado[0]": "1",
  "tipoSelecionado[0]": "Interface",
  "index[0]": "2",

  "selectedRow[1]": "on",
  "IP[1]": "192.168.1.1",
  "Port[1]": "161",
  "Community[1]": "public",
  "displaySelecionado[1]": "2",
  "tipoSelecionado[1]": "PPPoE-Mikrotik",
  "index[1]": "0"
}
/config/snmp.json (seleção: substituir/adicionar)
Este arquivo é consumido por f_startSelectInterfaces() para criar/atualizar o snmp-interface-select.json.

snmpAction:

"substituir": grava o arquivo de seleção “do zero”

"adicionar": faz merge e reindexa usando mergeJsonWithReindex()

Exemplo:

json
Copiar código
{
  "snmpAction": "substituir",
  "selectedRow[0]": "on",
  "IP[0]": "10.0.0.1",
  "Port[0]": "161",
  "Community[0]": "public",
  "displaySelecionado[0]": "1",
  "tipoSelecionado[0]": "Trafego",
  "index[0]": "5"
}
/config/snmp-custom-oid.json (inserção rápida de Custom OID)
Usado por f_startAddCustomOID()/f_AdicionarCustomOID() para “injetar” rapidamente uma linha Custom no snmp-interface-select.json, com novo índice automaticamente.

Exemplo:

json
Copiar código
{
  "IP": "10.0.0.2",
  "Port": "161",
  "Community": "public",
  "snmp-custom-display": "3",
  "customOid": "1.3.6.1.2.1.1.3.0",
  "operationType": "none",
  "operationFactor": "1",
  "unitSuffix": "ticks"
}
Arquivo gerado: /config/ScanInterfaces.json
Gerado pelo scan (f_ListInterfaces), formato array:

json
Copiar código
[
  {
    "sysName": "Router-XYZ",
    "IP": "192.168.1.1",
    "Port": 161,
    "Community": "public",
    "index": 1,
    "name": "ether1",
    "status": "UP",
    "type": 6
  }
]
Se não houver resposta, grava uma entrada “placeholder” com status: "SEM_RESPOSTA".

API pública (funções principais)
Header principal: snmp_main.h

Scan de interfaces
char* f_scan_snmp_cb();
Dispara o scan (cria task) e retorna JSON simples: {"message":"Scan Started"}.

char* f_scan_snmp_status_cb();
Retorna JSON: status run/stop e interfaces_discovered.

Tasks internas:

void f_startListInterfaces(void *arg);

void f_ScanInterface(void *args);

Seleção de interfaces/itens monitorados
void f_startSelectInterfaces();
Lê /config/snmp.json e atualiza /config/snmp-interface-select.json conforme snmpAction.

Custom OID rápido (injeção)
void f_startAddCustomOID();

void f_AdicionarCustomOID();

Monitoramento SNMP
void f_startReadSnmp();
Inicia a task t_SNMP se enable-snmp estiver “on” e Wi-Fi estiver conectado.

void f_ReadSnmp(void *args);
Loop principal (chamado pela task).

f_StatusReadInterface_t f_StatusReadInterface();
RUNNING/STOPPED

bool f_GetPrintDebugSNMP();
Retorna flag atual de debug.

Para parar o loop:

void f_stopReadInterfaces(); (em snmp_read-interface.h)

Integração no firmware
1) Inserir como componente do ESP-IDF
Estratégia típica:

components/smart-snmp/ contendo os .c/.h

CMakeLists.txt do componente registrando fontes e includes

Adicionar dependências (cJSON, lwip, freertos, e seus componentes enervision-manager/adapters)

2) Chamar o start do monitoramento no momento correto
O componente espera Wi-Fi conectado (f_Wifi_Conectado()), então normalmente você chama após o boot e init de rede:

c
Copiar código
#include "snmp_main.h"

void app_main(void) {
    // ... init do sistema, Wi-Fi, FS, etc.
    f_startReadSnmp();
}
3) Expor endpoints no seu WebServer (opcional)
Se você já tem um roteador de rotas/handlers, você pode mapear:

GET /snmp-scan -> f_scan_snmp_cb()

GET /snmp-scan-status -> f_scan_snmp_status_cb()

Além disso, sua UI pode gravar os JSONs em /config para controlar o componente.

4) Garantir o “bridge” de dados (Device[] / filas)
O smart-snmp publica resultados via:

Device[display].xQueue

Device[display].xQueueAlarme

Device[display].xQueueMqtt

Device[display].xQueueDashzap

E faz gate por serviço:

f_DeviceServico(Device[display].Servico, SNMP_Interface | SNMP_Trafego | SNMP_PPPoE_Count | SNMP_Uptime | SNMP_Custom)

Para reutilizar em outro produto, você pode:

manter esse contrato (recomendado dentro do ecossistema Enervision), ou

adaptar para uma interface genérica (callbacks por métrica, event bus, etc.).

Troubleshooting
“No valid device found”

Verifique se /config/snmp-interface-select.json existe e contém linhas completas.

Campos mínimos exigidos por linha: IP, Port, Community|community, displaySelecionado, tipoSelecionado.

Scan não encontra interfaces

Confirme IP/Port/Community em /config/snmp-scan.json.

Ajuste Timeout e MaxInterface.

Verifique se o dispositivo responde SNMP (mesma rede, ACL, firewall).

Valores “DESCON” / 0xFFFFFFFF

Indica timeout/sem resposta SNMP para aquela leitura.

Acontece em status, tráfego, uptime ou custom conforme o caso.

PPPoE lento

O modo legado (PPPoE-Count) usa GETNEXT e pode ser custoso.

Prefira PPPoE-Mikrotik / PPPoE-Huawei (OID rápido) quando possível.

Debug

Ative DebugSNMP em /config/setup.json para logs detalhados.

Extensões (como adicionar novas leituras)
Padrão atual para adicionar uma nova métrica:

Criar um módulo snmp_<feature>.c/.h com:

f_Register<Feature>Target(...) (se precisar de targets especiais)

f_Processa<Feature>(...) (executa SNMP e publica)

f_Libera<Feature>Targets() (se alocar memória)

Em snmp_read-interface.c:

Classificar o novo tipoSelecionado[...] em snmp_classify_kind()

Registrar targets (se necessário) em snmp_register_special_targets()

Adicionar chamada no loop f_ExecutaLeituraSNMP()

Ajustar UI/JSON para gravar o novo tipo.

