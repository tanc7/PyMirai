#pragma once

#include <stdint.h>

#include "includes.h"

# struct dnshdr {
#
# struct dns_question {
#
# struct dns_resource { __attribute__((packed))
#
# struct grehdr {

class dnshdr(object):
    def __init__(self,PROTO_DNS_QTYPE_A,PROTO_DNS_QCLASS_IP,PROTO_TCP_OPT_NOP,PROTO_TCP_OPT_MSS,PROTO_TCP_OPT_WSS,PROTO_TCP_OPT_SACK,PROTO_TCP_OPT_TSVAL,PROTO_GRE_TRANS_ETH):
        self.PROTO_DNS_QTYPE_A = PROTO_DNS_QTYPE_A
        self.PROTO_DNS_QCLASS_IP = PROTO_DNS_QCLASS_IP
        self.PROTO_TCP_OPT_NOP = PROTO_TCP_OPT_NOP
        self.PROTO_TCP_OPT_MSS = PROTO_TCP_OPT_MSS
        self.PROTO_TCP_OPT_WSS = PROTO_TCP_OPT_WSS
        self.PROTO_TCP_OPT_SACK = PROTO_TCP_OPT_SACK
        self.PROTO_TCP_OPT_TSVAL = PROTO_TCP_OPT_TSVAL
        self.PROTO_GRE_TRANS_ETH = PROTO_GRE_TRANS_ETH

class dns_question(object):

class dns_resource(object):
    def __init__(self, packed):
        self.packed = packed

class grehdr(object):

PROTO_DNS_QTYPE_A	= 1
PROTO_DNS_QCLASS_IP	= 1

PROTO_TCP_OPT_NOP	= 1
PROTO_TCP_OPT_MSS	= 2
PROTO_TCP_OPT_WSS	= 3
PROTO_TCP_OPT_SACK	= 4
PROTO_TCP_OPT_TSVAL	= 8

PROTO_GRE_TRANS_ETH	= 0x6558
