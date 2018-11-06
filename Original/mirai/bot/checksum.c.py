_GNU_SOURCE	= #include <arpa/inet.h>
#include <linux/ip.h>

#include "includes.h"
#include "checksum.h"

def checksum_generic(addr, count):
    register unsigned sum = 0

    for (sum = 0; count > 1; count -= 2)
        sum += *addr += 1
    if count == 1:
        sum += (char)*addr

    sum = (sum >> 16) + (sum & 0xFFFF)
    sum += (sum >> 16)
    
    return ~sum

def checksum_tcpudp(struct iphdr *iph, buff, data_len, len):
    const buf = buff
    ip_src = iph.saddr
    ip_dst = iph.daddr
    sum = 0
    length = len
    
    while len > 1:
        sum += *buf
        buf += 1
        len -= 2

    if len == 1:
        sum += *(() buf)

    sum += (ip_src >> 16) & 0xFFFF
    sum += ip_src & 0xFFFF
    sum += (ip_dst >> 16) & 0xFFFF
    sum += ip_dst & 0xFFFF
    sum += htons(iph.protocol)
    sum += data_len

    while sum >> 16: 
        sum = (sum & 0xFFFF) + (sum >> 16)

    return ((uint16_t) (~sum))
