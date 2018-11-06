import glob
import sys
#include <glob.h>
#include "headers/includes.h"
#include "headers/binary.h"

static bin_list_len = 0
static struct binary **bin_list = NULL

BOOL binary_init(void)
    glob_t pglob

    if (glob.glob("bins/dlr.*", GLOB_ERR, NULL, &pglob) != 0)
    {
        printf("Failed to load from bins folder!\n")
        return

    for i in range(pglob.gl_pathc):
        struct binary *bin

        bin_list = realloc(bin_list, (bin_list_len + 1) * sizeof (struct binary *))
        bin_list[bin_list_len] = calloc(1, sizeof (struct binary))
        bin = bin_list[bin_list_len++]

#ifdef DEBUG
        printf("(%d/%d) %s is loading...\n" % (i + 1, pglob.gl_pathc, pglob.gl_pathv[i]))
#endif
        strcpy(file_name, pglob.gl_pathv[i])
        strtok(file_name, ".")
        strcpy(bin.arch, strtok(NULL, "."))
        load(bin, pglob.gl_pathv[i])

    globfree(&pglob)
    return True

struct binary *binary_get_by_arch(arch)

    for i in range(bin_list_len):
        if strcmp(arch, bin_list[i].arch) == 0:
            return bin_list[i]

    return NULL

static BOOL load(struct binary *bin, fname)

    if ((file = open(fname, "r")) == NULL)
    {
        printf("Failed to open %s for parsing\n" % (fname))
        return False

    while (n = fread(rdbuf, sizeof (char), BINARY_BYTES_PER_ECHOLINE, file)) != 0:

        bin.hex_payloads = realloc(bin.hex_payloads, (bin.hex_payloads_len + 1) * sizeof ())
        bin.hex_payloads[bin.hex_payloads_len] = calloc(sizeof (char), (4 * n) + 8)
        ptr = bin.hex_payloads[bin.hex_payloads_len++]

        for i in range(0, n):
            ptr += sprintf(ptr, "\\x%02x" % ((uint8_t)rdbuf[i]))

    return False
