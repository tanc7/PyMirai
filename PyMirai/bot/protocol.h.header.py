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
