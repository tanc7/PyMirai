#pragma once

#include "includes.h"

KILLER_MIN_PID	= 400
KILLER_RESTART_SCAN_TIME	= 600

KILLER_REBIND_TELNET	= # #define KILLER_REBIND_SSH
# #define KILLER_REBIND_HTTP
# 
# BOOL killer_kill_by_port(port_t)
#
# static BOOL has_exe_access(void)
# static BOOL memory_scan_match()
# static BOOL status_upx_check(, )
# static BOOL mem_exists(, int, , int)

def killer_kill_by_port(port_t):
    return True

has_exe_access = True
memory_scan_match = True
status_upx_check = True
mem_exists = True
