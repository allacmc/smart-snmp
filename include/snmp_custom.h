#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    Divide,
    Multiply
} Operation_t;


typedef struct {
    char *ip;
    int port;
    int display;
    char *oid;
    Operation_t Operation;
    int OperationFactor;
} CustomTarget;


void f_RegisterCustomTarget(const char *ip, int port, int display, const char *oid);
void f_LiberaCustomTargets(void);
int  f_GetCustomDisplay(const char *ip, int port, const char *oid);
void f_ProcessaSNMPCustom(int sock, const char *ip, int port, const char *community);

int f_GetTotalCustomTargets(void);
const CustomTarget *f_GetCustomTargetByIndex(int index);

#ifdef __cplusplus
}
#endif



// void f_RegisterCustomTarget(const char *ip, int port, int display);
// int f_GetCustomDisplay(const char *ip, int port);
// void f_ProcessaSNMPCustom(int sock, IPInfo *device, struct sockaddr_in *dest, const char *community); 
