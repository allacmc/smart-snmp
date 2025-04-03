#pragma once

void f_startListInterfaces(void *arg);
void f_ScanInterface(const char *ip_address);
void f_ReadInterfaces(void *args);
void f_startReadInterfaces();
char* f_scan_snmp_cb();
char* f_scan_snmp_status_cb();
void f_startSelectInterfaces();
void f_ConsumidorInterfaces(void *args);