#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

typedef enum {
    Divide,
    Multiply,
    None
} Operation_t;


typedef struct {
    char *ip;
    int port;
    int display;
    char *oid;
    Operation_t Operation;
    int OperationFactor;
    char *Suffix;
} CustomTarget;

void f_RegisterCustomTarget(const char *ip, int port, int display, const char *oid, const char * oper, const char * OperFact, const char * suffix);
void f_LiberaCustomTargets(void);
int  f_GetCustomDisplay(const char *ip, int port, const char *oid);
void f_ProcessaSNMPCustom(int sock, const char *ip, int port, const char *community);
const CustomTarget *f_GetCustomTargetByDisplay(int display);

int f_GetTotalCustomTargets(void);
const CustomTarget *f_GetCustomTargetByIndex(int index);

void f_setPrintDebugCustom(bool valor);


#ifdef __cplusplus
}
#endif



// void f_RegisterCustomTarget(const char *ip, int port, int display);
// int f_GetCustomDisplay(const char *ip, int port);
// void f_ProcessaSNMPCustom(int sock, IPInfo *device, struct sockaddr_in *dest, const char *community); 
