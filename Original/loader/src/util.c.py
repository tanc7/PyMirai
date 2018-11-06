import os, fcntl, curses.ascii
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
import sys
#include <stdarg.h>
#include "headers/includes.h"
#include "headers/util.h"
#include "headers/server.h"

    unsigned buff[17]
    unsigned pc = (unsigned )addr

    # Output description if given.
    if desc != NULL:
        printf ("%s:\n" % (desc))

    if len == 0:
        printf("  ZERO LENGTH\n")
        return
    if len < 0:
        printf("  NEGATIVE LENGTH: %i\n" % (len))
        return

    # Process every byte in the data.
    for i in range(len):
        # Multiple of 16 means new line (with line offset).

        if (i % 16) == 0:
            # Just don't print ASCII for the zeroth line.
            if i != 0:
                printf ("  %s\n" % (buff))

            # Output the offset.
            printf ("  %04x " % (i))

        # Now the hex code for the specific character.
        printf (" %02x" % (pc[i]))

        # And store a printable ASCII character for later.
        if (pc[i] < 0x20) or (pc[i] > 0x7e):
            buff[i % 16] = '.'
        else:
            buff[i % 16] = pc[i]
        buff[(i % 16) + 1] = '\0'

    # Pad out last line if not exactly 16 characters.
    while (i % 16) != 0:
        printf ("   ")
        i += 1

    # And print the final ASCII bit.
    printf ("  %s\n" % (buff))

def util_socket_and_bind(struct server *srv):
    struct sockaddr_in bind_addr
    BOOL bound = False

    if (fd = socket(AF_INET, SOCK_STREAM, 0)) == -1:
        return -1

    bind_addr.sin_family = AF_INET
    bind_addr.sin_port = 0

    # Try to bind on the first available address
    start_addr = rand() % srv.bind_addrs_len
    for i in range(srv.bind_addrs_len):
        bind_addr.sin_addr.s_addr = srv.bind_addrs[start_addr]
        if bind(fd, (struct sockaddr *)&bind_addr, sizeof (struct sockaddr_in)) == -1:
            if ++start_addr == srv.bind_addrs_len:
                start_addr = 0
        else:
            bound = True
            break
    if not bound:
        os.close(fd)
#ifdef DEBUG
        printf("Failed to bind on any address\n")
#endif
        return -1

    # Set the socket in nonblocking mode
    if fcntl.fcntl(fd, F_SETFL, fcntl.fcntl(fd, F_GETFL, 0) | os.O_NONBLOCK) == -1:
#ifdef DEBUG
        printf("Failed to set socket in nonblocking mode. This will have SERIOUS performance implications\n")
#endif
    return fd

def util_memsearch(buf, buf_len, mem, mem_len):
    matched = 0

    if mem_len > buf_len:
        return -1

    for i in range(buf_len):
        if buf[i] == mem[matched]:
            if ++matched == mem_len:
                return i + 1
        else:
            matched = 0

    return -1

BOOL util_sockprintf(fd, const fmt, ...)
    va_list args

    va_start(args, fmt)
    len = vsnprintf(buffer, BUFFER_SIZE, fmt, args)
    va_end(args)

    if len > 0:
        if len > BUFFER_SIZE:
            len = BUFFER_SIZE

#ifdef DEBUG
        hexDump("TELOUT", buffer, len)
#endif
        if send(fd, buffer, len, MSG_NOSIGNAL) != len:
            return False

    return True

def util_trim(str):

    while curses.ascii.isspace(*str):
        str += 1

    if *str == 0:
        return str

    end = str + len(str) - 1
    while end > str and curses.ascii.isspace(*end):
        end -= 1

    *(end+1) = 0

    return str
