import os
_GNU_SOURCE	= #ifdef DEBUG
import sys
#endif
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

#include "includes.h"
#include "util.h"
#include "table.h"

def util_strlen(str):
    c = 0

    while *str++ != 0:
        c += 1
    return c


BOOL util_strncmp(str1, str2, len)
    l1 = util_strlen(str1); l2 = util_strlen(str2)

    if l1 < len or l2 < len:
        return False

    while len--:
        if *str1++ != *str2++:
            return False

    return True

BOOL util_strcmp(str1, str2)
    l1 = util_strlen(str1); l2 = util_strlen(str2)

    if l1 != l2:
        return False

    while l1--:
        if *str1++ != *str2++:
            return False

    return True

def util_strcpy(dst, src):
    l = util_strlen(src)

    util_memcpy(dst, src, l + 1)

    return l

def util_memcpy(dst, src, len):
    r_dst = ()dst
    r_src = ()src
    while len--:
        *r_dst++ = *r_src += 1

def util_zero(buf, len):
    zero = buf
    while len--:
        *zero++ = 0

def util_atoi(str, base):
	unsigned acc = 0
	unsigned cutoff
	neg = 0

	while True:
		c = *str += 1
	    if not (util_isspace(c)): break	# DO-WHILE TERMINATOR -- INDENTATION CAN BE WRONG
	if c == '-':
		neg = 1
		c = *str += 1
	} elif c == '+':
		c = *str += 1

	cutoff = neg ? -(unsigned long)LONG_MIN : LONG_MAX
	cutlim = cutoff % (unsigned long)base
	cutoff /= (unsigned long)base
	for (acc = 0, any = 0;; c = *str++) {
		if util_isdigit(c):
			c -= '0'
		elif util_isalpha(c):
			c -= util_isupper(c) ? 'A' - 10 : 'a' - 10
		else:
			break
            
		if c >= base:
			break

		if any < 0 or acc > cutoff or acc == cutoff and c > cutlim:
			any = -1
		else:
			any = 1
			acc *= base
			acc += c
	if any < 0:
		acc = neg ? LONG_MIN : LONG_MAX
	} elif neg:
		acc = -acc
	return (acc)

def util_itoa(value, radix, string):
    if string == NULL:
        return NULL

    if value != 0:
        unsigned accum

        offset = 32
        scratch[33] = 0

        if radix == 10 and value < 0:
            neg = 1
            accum = -value
        else:
            neg = 0
            accum = (unsigned int)value

        while accum:
            c = accum % radix
            if c < 10:
                c += '0'
            else:
                c += 'A' - 10

            scratch[offset] = c
            accum /= radix
            offset -= 1
        
        if neg:
            scratch[offset] = '-'
        else:
            offset += 1

        util_strcpy(string, &scratch[offset])
    else:
        string[0] = '0'
        string[1] = 0

    return string

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

def util_stristr(haystack, haystack_len, str):
    ptr = haystack
    str_len = util_strlen(str)
    match_count = 0

    while haystack_len-- > 0:
        a = *ptr += 1
        b = str[match_count]
        a = a >= 'A' and a <= 'Z' ? a | 0x60 : a
        b = b >= 'A' and b <= 'Z' ? b | 0x60 : b

        if a == b:
            if ++match_count == str_len:
                return (ptr - haystack)
        else:
            match_count = 0

    return -1

ipv4_t util_local_addr(void)
    struct sockaddr_in addr
    socklen_t addr_len = sizeof (addr)

    errno = 0
    if (fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1:
#ifdef DEBUG
        printf("[util] Failed to call socket(), errno = %d\n" % (errno))
#endif
        return 0

    addr.sin_family = AF_INET
    addr.sin_addr.s_addr = INET_ADDR(8,8,8,8)
    addr.sin_port = htons(53)

    connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in))

    getsockname(fd, (struct sockaddr *)&addr, &addr_len)
    os.close(fd)
    return addr.sin_addr.s_addr

def util_fdgets(buffer, buffer_size, fd):
    got = 0; total = 0
    while True:
        got = os.read(fd, buffer + total, 1)
        total = got == 1 ? total + 1 : total
        if not (got == 1 and total < buffer_size and *(buffer + (total - 1)) != '\n'): break	# DO-WHILE TERMINATOR -- INDENTATION CAN BE WRONG

    return total == 0 ? NULL : buffer

static inline util_isupper(c)
    return (c >= 'A' and c <= 'Z')

static inline util_isalpha(c)
    return ((c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z'))

static inline util_isspace(c)
    return (c == ' ' or c == '\t' or c == '\n' or c == '\12')

static inline util_isdigit(c)
    return (c >= '0' and c <= '9')
