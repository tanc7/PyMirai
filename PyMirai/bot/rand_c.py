import os
_GNU_SOURCE	= #include <stdint.h>
#include <unistd.h>
import time

#include "includes.h"
#include "rand.h"

static x, y, z, w

def rand_init():
    x = time.time()
    y = os.getpid() ^ os.getppid()
    z = clock()
    w = z ^ y

rand_next(void) #period 2^96-1
    t = x
    t ^= t << 11
    t ^= t >> 8
    x = y; y = z; z = w
    w ^= w >> 19
    w ^= t
    return w

rand_str(str, len) # Generate random buffer (not alphanumeric!) of length len
    while len > 0:
        if len >= 4:
            *(()str) = rand_next()
            str += sizeof (uint32_t)
            len -= sizeof (uint32_t)
        elif len >= 2:
            *(()str) = rand_next() & 0xFFFF
            str += sizeof (uint16_t)
            len -= sizeof (uint16_t)
        else:
            *str++ = rand_next() & 0xFF
            len -= 1

rand_alphastr(str, len) # Random alphanumeric string, more expensive than rand_str
    const alphaset = "abcdefghijklmnopqrstuvw012345678"

    while len > 0:
        if len >= sizeof (uint32_t):
            entropy = rand_next()

            for i in range(sizeof (uint32_t)):
                tmp = entropy & 0xff

                entropy = entropy >> 8
                tmp = tmp >> 3

                *str++ = alphaset[tmp]
            len -= sizeof (uint32_t)
        else:
            *str++ = rand_next() % (sizeof (alphaset))
            len -= 1
