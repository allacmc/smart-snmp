#pragma once
#include <stdio.h>
#include <stdbool.h> // Necessário para o tipo bool

typedef enum {
    RUNNING,
    STOPPED
} f_StatusReadInterface_t;

void f_startListInterfaces(void *arg);
void f_ScanInterface(void *args) ;
void f_ReadInterfaces(void *args);
void f_startReadInterfaces();
char* f_scan_snmp_cb();
char* f_scan_snmp_status_cb();
void f_startSelectInterfaces();
f_StatusReadInterface_t f_StatusReadInterface();
void f_AdicionarCustomOID();
void f_startAddCustomOID();
bool f_GetPrintDebugSNMP();