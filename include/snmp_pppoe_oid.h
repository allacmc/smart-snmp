#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "lwip/sockets.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PPPoE_OID_PROFILE_MIKROTIK = 0,
    PPPoE_OID_PROFILE_HUAWEI   = 1,
    PPPoE_OID_PROFILE_CUSTOM   = 2
} snmp_pppoe_oid_profile_t;

/**
 * Registra um target PPPoE (por OID).
 * - profile: Mikrotik/Huawei/Custom
 * - custom_oid: usado apenas se profile == PPPoE_OID_PROFILE_CUSTOM
 */
void f_RegisterPPPoEOidTarget(const char *ip, int port, int display,
                             snmp_pppoe_oid_profile_t profile,
                             const char *custom_oid);

/** Retorna o display (1..N) cadastrado para ip:port, ou -1 se não existir */
int  f_GetPPPoEOidDisplay(const char *ip, int port);

/** Retorna true se ip:port está cadastrado como PPPoE OID target */
bool f_IsPPPoEOidTarget(const char *ip, int port);

/** Libera memória alocada internamente e zera lista */
void f_LiberaPPPoEOidTargets(void);

/**
 * Processa o PPPoE Count via OID (GET escalar) e publica nas filas do Device[display].
 * Mantém a mesma semântica do snmp_pppoe.c legado (atualiza filas xQueue/xQueueAlarme/xQueueMqtt/xQueueDashzap).
 */
void f_ProcessaPPPoECountOid(int sock, const char *ip, int port,
                            struct sockaddr_in *dest,
                            const char *community,
                            bool PrintDebug);

#ifdef __cplusplus
}
#endif
