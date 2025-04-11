#pragma once

#define MAX_OIDS 20
#define MAX_IPS 10

typedef enum {
    TIPO_INTERFACE,
    TIPO_TRAFEGO,
    TIPO_UPTIME,
    TIPO_PPPoE    
} TipoSelecionado;

typedef struct {
    char *oid;
    char *display;
    TipoSelecionado tipo;
} OIDInfo;

typedef struct {
    char *ip;
    int port;  // 👈 novo campo
    int total_oids;
    OIDInfo oids[MAX_OIDS];
    const char *community;
} IPInfo;

typedef struct {
    int index;
    char name[128];
    char status[16];
    int type;
} InterfaceInfo;
