/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"

using namespace std;

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{
    sock_list.clear();
    bind_list.clear();
    cli_list.clear();
    reversed_cli_list.clear();
    svr_list.clear();
    estab_list.clear();
    reversed_estab_list.clear();
    listenq.clear();
    completeq.clear();
    uuid_list.clear();
    seq_list.clear();
    accept_info_list.clear();
    close_list.clear();
    timer_list.clear();
    read_info_list.clear();
    read_buffer_list.clear();
    internal_buffer_list.clear();
    blocked_packet_list.clear();
    blocked_uuid_list.clear();
}

void TCPAssignment::finalize()
{

}

/* ######################
   ## Helper Functions ##
   ######################
*/

bool TCPAssignment::is_addr_same(struct sockaddr addr_1, struct sockaddr addr_2) {
    struct sockaddr_in left = *(struct sockaddr_in *)&addr_1;
    struct sockaddr_in right = *(struct sockaddr_in *)&addr_2;
    if (left.sin_addr.s_addr == right.sin_addr.s_addr ||
        left.sin_addr.s_addr == INADDR_ANY ||
        right.sin_addr.s_addr == INADDR_ANY) {
        if (left.sin_port == right.sin_port) {
            return true;
        }
    }
    return false;
}

bool TCPAssignment::find_sock(struct PidFd pidfd) {
    bool flag = false;
    for (auto iter = sock_list.begin();iter != sock_list.end();iter++) {
        if (iter->first == pidfd) {
            flag = true;
            break;
        }
    }
    return flag;
}

bool TCPAssignment::find_bind(struct PidFd pidfd) {
    int flag = false;
    for (auto iter = bind_list.begin();iter != bind_list.end();iter++) {
        if (iter->first == pidfd) {
            flag = true;
            break;
        }
    }
    return flag;
}

bool TCPAssignment::find_cli(struct PidFd pidfd) {
    int flag = false;
    for (auto iter = cli_list.begin();iter != cli_list.end();iter++) {
        if (iter->first == pidfd) {
            flag = true;
            break;
        }
    }
    return flag;
}

bool TCPAssignment::find_reversed_cli(struct Sock sock) {
    int flag = false;
    for (auto iter = reversed_cli_list.begin();iter != reversed_cli_list.end();iter++) {
        if (iter->first == sock) {
            flag = true;
            break;
        }
    }
    return flag;
}

bool TCPAssignment::find_svr(struct PidFd pidfd) {
    int flag = false;
    for (auto iter = svr_list.begin();iter != svr_list.end();iter++) {
        if (iter->first == pidfd) {
            flag = true;
            break;
        }
    }
    return flag;
}

bool TCPAssignment::find_estab(struct PidFd pidfd) {
    int flag = false;
    for (auto iter = estab_list.begin();iter != estab_list.end();iter++) {
        if (iter->first == pidfd) {
            flag = true;
            break;
        }
    }
    return flag;
}

bool TCPAssignment::find_reversed_estab(struct Sock sock) {
    int flag = false;
    for (auto iter = reversed_estab_list.begin();iter != reversed_estab_list.end();iter++) {
        if (iter->first == sock) {
            flag = true;
            break;
        }
    }
    return flag;
}

bool TCPAssignment::find_uuid(struct PidFd pidfd) {
    int flag = false;
    for (auto iter = uuid_list.begin();iter != uuid_list.end();iter++) {
        if (iter->first == pidfd) {
            flag = true;
            break;
        }
    }
    return flag;
}

bool TCPAssignment::find_close(struct PidFd pidfd) {
    int flag = false;
    for (auto iter = close_list.begin();iter != close_list.end();iter++) {
        if (iter->first == pidfd) {
            flag = true;
            break;
        }
    }
    return flag;
}

bool TCPAssignment::find_seq(struct PidFd pidfd) {
    int flag = false;
    for (auto iter = seq_list.begin();iter != seq_list.end();iter++) {
        if (iter->first == pidfd) {
            flag = true;
            break;
        }
    }
    return flag;
}

bool TCPAssignment::find_listenq(struct PidFd pidfd) {
    bool flag = false;
    for (auto iter = listenq.begin();iter != listenq.end();iter++) {
        if (iter->first == pidfd) {
            flag = true;
            break;
        }
    }
    return flag;
}

bool TCPAssignment::find_completeq(struct PidFd pidfd) {
    bool flag = false;
    for (auto iter = completeq.begin();iter != completeq.end();iter++) {
        if (iter->first == pidfd) {
            flag = true;
            break;
        }
    }
    return flag;
}

bool TCPAssignment::find_accept_info(struct PidFd pidfd) {
    bool flag = false;
    for (auto iter = accept_info_list.begin();iter != accept_info_list.end();iter++) {
        if (iter->first == pidfd) {
            flag = true;
            break;
        }
    }
    return flag;
}

bool TCPAssignment::find_read_info(struct PidFd pidfd) {
    bool flag = false;
    for (auto iter = read_info_list.begin();iter != read_info_list.end();iter++) {
        if (iter->first == pidfd) {
            flag = true;
            break;
        }
    }
    return flag;
}

bool TCPAssignment::find_read_buffer(struct PidFd pidfd) {
    bool flag = false;
    for (auto iter = read_buffer_list.begin();iter != read_buffer_list.end();iter++) {
        if (iter->first == pidfd) {
            flag = true;
            break;
        }
    }
    return flag;
}

bool TCPAssignment::find_blocked_packet(struct PidFd pidfd) {
    bool flag = false;
    for (auto iter = blocked_packet_list.begin();iter != blocked_packet_list.end();iter++) {
        if (iter->first == pidfd) {
            flag = true;
            break;
        }
    }
    return flag;
}

bool TCPAssignment::find_internal_buffer(struct PidFd pidfd) {
    bool flag = false;
    for (auto iter = internal_buffer_list.begin();iter != internal_buffer_list.end();iter++) {
        if (iter->first == pidfd) {
            flag = true;
            break;
        }
    }
    return flag;
}

bool TCPAssignment::find_blocked_uuid(struct PidFd pidfd) {
    bool flag = false;
    for (auto iter = blocked_uuid_list.begin();iter != blocked_uuid_list.end();iter++) {
        if (iter->first == pidfd) {
            flag = true;
            break;
        }
    }
    return flag;
}

struct Sock *TCPAssignment::get_sock(struct PidFd pidfd) {
    struct Sock *sock;
    int flag = false;
    for (auto iter = sock_list.begin();iter != sock_list.end();iter++) {
        if (iter->first == pidfd) {
            sock = &iter->second;
            flag = true;
            break;
         }
    }
    assert(flag == true);
    return sock;
}

struct Sock *TCPAssignment::get_bind(struct PidFd pidfd) {
    struct Sock *sock;
    int flag = false;
    for (auto iter = bind_list.begin();iter != bind_list.end();iter++) {
        if (iter->first == pidfd) {
            sock = &iter->second;
            flag = true;
            break;
         }
    }
    assert(flag == true);
    return sock;
}

struct Sock *TCPAssignment::get_cli(struct PidFd pidfd) {
    struct Sock *sock;
    int flag = false;
    for (auto iter = cli_list.begin();iter != cli_list.end();iter++) {
        if (iter->first == pidfd) {
            sock = &iter->second;
            flag = true;
            break;
         }
    }
    assert(flag == true);
    return sock;
}

struct PidFd *TCPAssignment::get_reversed_cli(struct Sock sock) {
    struct PidFd *pidfd;
    int flag = false;
    for (auto iter = reversed_cli_list.begin();iter != reversed_cli_list.end();iter++) {
        if (iter->first == sock) {
            pidfd = &iter->second;
            flag = true;
            break;
        }
    }
    assert (flag == true);
    return pidfd;
}

deque<struct Sock> *TCPAssignment::get_svr(struct PidFd pidfd) {
    deque<struct Sock> *sock_set;
    int flag = false;
    for (auto iter = svr_list.begin();iter != svr_list.end();iter++) {
        if (iter->first == pidfd) {
            sock_set = &iter->second;
            flag = true;
            break;
        }
    }
    assert(flag == true);
    return sock_set;
}

struct Sock *TCPAssignment::get_estab(struct PidFd pidfd) {
    struct Sock *sock;
    int flag = false;
    for (auto iter = estab_list.begin();iter != estab_list.end();iter++) {
        if (iter->first == pidfd) {
            sock = &iter->second;
            flag = true;
            break;
         }
    }
    assert(flag == true);
    return sock;
}

struct PidFd *TCPAssignment::get_reversed_estab(struct Sock sock) {
    struct PidFd *pidfd;
    int flag = false;
    for (auto iter = reversed_estab_list.begin();iter != reversed_estab_list.end();iter++) {
        if (iter->first == sock) {
            pidfd = &iter->second;
            flag = true;
            break;
        }
    }
    assert (flag == true);
    return pidfd;
}

uint32_t TCPAssignment::get_seq(struct PidFd pidfd) {
    uint32_t s;
    int flag = false;
    for (auto iter = seq_list.begin();iter != seq_list.end();iter++) {
        if (iter->first == pidfd) {
            s = iter->second;
            flag = true;
            break;
        }
    }
    assert(flag == true);
    return s;
}

UUID TCPAssignment::get_uuid(struct PidFd pidfd) {
    uint32_t syscallUUID;
    int flag = false;
    for (auto iter = uuid_list.begin();iter != uuid_list.end();iter++) {
        if (iter->first == pidfd) {
            syscallUUID = iter->second;
            flag = true;
            break;
        }
    }
    assert(flag == true);
    return syscallUUID;
}

UUID TCPAssignment::get_close(struct PidFd pidfd) {
    uint32_t syscallUUID;
    int flag = false;
    for (auto iter = close_list.begin();iter != close_list.end();iter++) {
        if (iter->first == pidfd) {
            syscallUUID = iter->second;
            flag = true;
            break;
        }
    }
    assert(flag == true);
    return syscallUUID;
}

pair<int, deque<struct Sock>> *TCPAssignment::get_listenq(struct PidFd pidfd) {
    pair<int, deque<struct Sock>> *lq;
    int flag = false;
    for (auto iter = listenq.begin();iter != listenq.end();iter++) {
        if (iter->first == pidfd) {
            lq = &iter->second;
            flag = true;
            break;
         }
    }
    assert(flag == true);
    return lq;
}

set<pair<UUID, pair<struct sockaddr *, socklen_t *>>> *TCPAssignment::get_accept_info(struct PidFd pidfd) {
    set<pair<UUID, pair<struct sockaddr *, socklen_t *>>> *res_ptr;
    int flag = false;
    for (auto iter = accept_info_list.begin();iter != accept_info_list.end();iter++) {
        if (iter->first == pidfd) {
            res_ptr = &iter->second;
            flag = true;
            break;
        }
    }
    assert(flag == true);
    return res_ptr;
}
 

deque<struct Sock> *TCPAssignment::get_completeq(struct PidFd pidfd) {
    deque<struct Sock> *lq;
    int flag = false;
    for (auto iter = completeq.begin();iter != completeq.end();iter++) {
        if (iter->first == pidfd) {
            lq = &iter->second;
            flag = true;
            break;
         }
    }
    assert(flag == true);
    return lq;
}

deque<uint8_t> *TCPAssignment::get_read_buffer(struct PidFd pidfd) {
    deque<uint8_t> *lq;
    int flag = false;
    for (auto iter = read_buffer_list.begin();iter != read_buffer_list.end();iter++) {
        if (iter->first == pidfd) {
            lq = &iter->second;
            flag = true;
            break;
         }
    }
    assert(flag == true);
    return lq;
}


pair<UUID, pair<void *, size_t>> *TCPAssignment::get_read_info(struct PidFd pidfd) {
    pair<UUID, pair<void *, size_t>> *res_ptr;
    int flag = false;
    for (auto iter = read_info_list.begin();iter != read_info_list.end();iter++) {
        if (iter->first == pidfd) {
            res_ptr = &iter->second;
            flag = true;
            break;
        }
    }
    assert(flag == true);
    return res_ptr;
}

pair<size_t, map<int, Packet *>> *TCPAssignment::get_internal_buffer(struct PidFd pidfd) {
    pair<size_t, map<int, Packet *>> *res_ptr;
    int flag = false;
    for (auto iter = internal_buffer_list.begin();iter != internal_buffer_list.end();iter++) {
        if (iter->first == pidfd) {
            res_ptr = &iter->second;
            flag = true;
            break;
        }
    }
    assert(flag == true);
    return res_ptr;
}

map<UUID, deque<pair<int, Packet *>>> *TCPAssignment::get_blocked_packet(struct PidFd pidfd) {
    map<UUID, deque<pair<int, Packet *>>> *res_ptr;
    int flag = false;
    for (auto iter = blocked_packet_list.begin();iter != blocked_packet_list.end();iter++) {
        if (iter->first == pidfd) {
            res_ptr = &iter->second;
            flag = true;
            break;
        }
    }
    assert(flag == true);
    return res_ptr;
}

deque<pair<UUID, size_t>> *TCPAssignment::get_blocked_uuid(struct PidFd pidfd) {
    deque<pair<UUID, size_t>> *res_ptr;
    int flag = false;
    for (auto iter = blocked_uuid_list.begin();iter != blocked_uuid_list.end();iter++) {
        if (iter->first == pidfd) {
            res_ptr = &iter->second;
            flag = true;
            break;
        }
    }
    assert(flag == true);
    return res_ptr;
}

void TCPAssignment::remove_sock(struct PidFd pidfd) {
    for (auto iter = sock_list.begin();iter != sock_list.end();iter++) {
        if (iter->first == pidfd) {
            sock_list.erase(iter);
            break;
         }
    }
    return;
}

void TCPAssignment::remove_bind(struct PidFd pidfd) {
    for (auto iter = bind_list.begin();iter != bind_list.end();iter++) {
        if (iter->first == pidfd) {
            bind_list.erase(iter);
            break;
         }
    }
    return;
}

void TCPAssignment::remove_cli(struct PidFd pidfd) {
    for (auto iter = cli_list.begin();iter != cli_list.end();iter++) {
        if (iter->first == pidfd) {
            cli_list.erase(iter);
            break;
         }
    }
    return;
}

void TCPAssignment::remove_reversed_cli(struct Sock sock) {
    for (auto iter = reversed_cli_list.begin();iter != reversed_cli_list.end();iter++) {
        if (iter->first == sock) {
            reversed_cli_list.erase(iter);
            break;
        }
    }
    return;
}

void TCPAssignment::remove_svr(struct PidFd pidfd) {
    for (auto iter = svr_list.begin();iter != svr_list.end();iter++) {
        if (iter->first == pidfd) {
            svr_list.erase(iter);
            break;
         }
    }
    return;
}

void TCPAssignment::remove_estab(struct PidFd pidfd) {
    for (auto iter = estab_list.begin();iter != estab_list.end();iter++) {
        if (iter->first == pidfd) {
            estab_list.erase(iter);
            break;
         }
    }
    return;
}

void TCPAssignment::remove_uuid(struct PidFd pidfd) {
    for (auto iter = uuid_list.begin();iter != uuid_list.end();iter++) {
        if (iter->first == pidfd) {
            uuid_list.erase(iter);
            break;
         }
    }
    return;
}

void TCPAssignment::remove_close(struct PidFd pidfd) {
    for (auto iter = close_list.begin();iter != close_list.end();iter++) {
        if (iter->first == pidfd) {
            close_list.erase(iter);
            break;
         }
    }
    return;
}

void TCPAssignment::remove_seq(struct PidFd pidfd) {
    for (auto iter = seq_list.begin();iter != seq_list.end();iter++) {
        if (iter->first == pidfd) {
            seq_list.erase(iter);
            break;
         }
    }
    return;
}

void TCPAssignment::remove_listenq(struct PidFd pidfd) {
    for (auto iter = listenq.begin();iter != listenq.end();iter++) {
        if (iter->first == pidfd) {
            listenq.erase(iter);
            break;
         }
    }
    return;
}

void TCPAssignment::remove_completeq(struct PidFd pidfd) {
    for (auto iter = completeq.begin();iter != completeq.end();iter++) {
        if (iter->first == pidfd) {
            completeq.erase(iter);
            break;
         }
    }
    return;
}

void TCPAssignment::remove_reversed_estab(struct Sock sock) {
    for (auto iter = reversed_estab_list.begin();iter != reversed_estab_list.end();iter++) {
        if (iter->first == sock) {
            reversed_estab_list.erase(iter);
            break;
        }
    }
    return;
}

void TCPAssignment::remove_accept_info(struct PidFd pidfd) {
    for (auto iter = accept_info_list.begin();iter != accept_info_list.end();iter++) {
        if (iter->first == pidfd) {
            accept_info_list.erase(iter);
            break;
         }
    }
    return;
}

/* ####################
   ## Order          ##
   ## 1. socket      ##
   ## 2. close       ##
   ## 3. bind        ##
   ## 4. getsockname ##
   ## 5. connect     ##
   ## 6. listen      ##
   ## 7. accept      ##
   ## 8. getpeername ##
   ####################
*/

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int type, int protocol) {
    //printf("CALL SOCKET\n");
    int new_fd = createFileDescriptor(pid);

    struct PidFd pidfd = PidFd(pid, new_fd);
    struct Sock sock = Sock();

    sock_list.insert(make_pair(pidfd, sock));

    returnSystemCall(syscallUUID, new_fd);
    return;
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd) {
    printf("CALL CLOSE\n");
    struct PidFd pidfd = PidFd(pid, fd);

    if (!find_sock(pidfd)) {
        returnSystemCall(syscallUUID, -1);
        return;
    }

    struct Sock *estab_sock;
    if (find_estab(pidfd)) {
        estab_sock = get_estab(pidfd);
        string s = estab_sock->state;
        if (s.compare("ESTAB") == 0) {
            estab_sock->state = "FIN_W1";
        } else if (s.compare("CLOSE_W") == 0) {
            estab_sock->state = "LAST_ACK";
        } else {
            returnSystemCall(syscallUUID, -1);
            return;
        }
    
        // create a new packet
        Packet *packet = allocatePacket(54);
        // write src/dst address to packet
        packet->writeData(14 + 12, &estab_sock->src_addr.sin_addr.s_addr, 4);
        packet->writeData(14 + 16, &estab_sock->dst_addr.sin_addr.s_addr, 4);
        packet->writeData(14 + 20 + 0, &estab_sock->src_addr.sin_port, 2);
        packet->writeData(14 + 20 + 2, &estab_sock->dst_addr.sin_port, 2);
    
        // write sequence number
        uint32_t seq_num = 0;
        if (find_seq(pidfd)) {
            seq_num = htonl(get_seq(pidfd));
        } else {
            seq_num = htonl(estab_sock->seq);
            if (s.compare("ESTAB") == 0) {
                estab_sock->seq = estab_sock->seq + 1;
            }
        }
        packet->writeData(14 + 20 + 4, &seq_num, 4);

        // fill in extra data
        uint32_t zero_4b = 0;
        uint8_t offset = 80;
        uint16_t window = htons((uint16_t)51200);
        uint32_t fin = fin_flag;
        packet->writeData(14 + 20 + 8, &zero_4b, 4);
        packet->writeData(14 + 20 + 12, &offset, 1);
        packet->writeData(14 + 20 + 13, &fin, 1);
        packet->writeData(14 + 20 + 14, &window, 2);
        packet->writeData(14 + 20 + 16, &zero_4b, 4);

        // calculate checksum
        uint8_t *tcp_header = (uint8_t *)malloc(20);
        packet->readData(14 + 20, tcp_header, 20);
   
        uint16_t checksum = ~(NetworkUtil::tcp_sum(estab_sock->src_addr.sin_addr.s_addr, estab_sock->dst_addr.sin_addr.s_addr, tcp_header, 20));
        checksum = htons(checksum);
        packet->writeData(14 + 20 + 16, &checksum, 2);

        close_list.insert(make_pair(pidfd, syscallUUID));
        this->sendPacket("IPv4", packet);
        returnSystemCall(syscallUUID, 0);
        //printf("SEND FIN\n");
        return;
    } else {
            if (find_listenq(pidfd)) {
                int tmp_port = get_bind(pidfd)->src_addr.sin_port;
                used_port[tmp_port] = 0;
            }

            remove_sock(pidfd);
            remove_bind(pidfd);
            remove_cli(pidfd);
            if (find_cli(pidfd)) {
                struct Sock cli_sock = *get_cli(pidfd);
                remove_reversed_cli(cli_sock);
            }
            remove_svr(pidfd);
            remove_estab(pidfd);
            if (find_estab(pidfd)) {
                struct Sock estab_sock = *get_estab(pidfd);
                remove_reversed_estab(estab_sock);
            }
            remove_uuid(pidfd);
            remove_seq(pidfd);
            remove_listenq(pidfd);
            remove_completeq(pidfd);
            remove_accept_info(pidfd);

            removeFileDescriptor(pid, fd);
            returnSystemCall(syscallUUID, 0);
            return;
    }
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t addrlen) {
    //printf("CALL BIND\n");
    struct PidFd pidfd = PidFd(pid, fd);

    if (!find_sock(pidfd)) {
        returnSystemCall(syscallUUID, -1);
        return;
    }

    if (find_bind(pidfd)) {
        returnSystemCall(syscallUUID, -1);
        return;
    }

    for (auto iter = bind_list.begin();iter != bind_list.end();iter++) {
        if (is_addr_same(*addr, *(struct sockaddr *)&iter->second.src_addr)) {
            returnSystemCall(syscallUUID, -1);
            return;
        }
    }

    struct Sock *sock = get_sock(pidfd);
    sock->src_addr = *(struct sockaddr_in *)addr;

    bind_list.insert(make_pair(pidfd, *sock));

    returnSystemCall(syscallUUID, 0);
    return;
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t*addrlen) {
    //printf("CALL GETSOCKNAME\n");
    struct PidFd pidfd = PidFd(pid, fd);

    int in_bind = false;
    int in_estab = false;
    if (!find_bind(pidfd)) {
        if (!find_estab(pidfd)) {
            returnSystemCall(syscallUUID, -1);
            return;
        } else {
            in_estab = true;
        }
    } else {
        in_bind = true;
        if (find_estab(pidfd)) {
            in_estab = true;
        }
    }

    struct Sock *sock;
    if (!in_estab && in_bind) {
        sock = get_bind(pidfd);
    } else if (in_estab) {
        sock = get_estab(pidfd);
    }
    sock->src_addr.sin_family = AF_INET;
    memcpy(addr, (struct sockaddr *)&sock->src_addr, sizeof(sockaddr));

    returnSystemCall(syscallUUID, 0);
    return;
}

    /* ##################################
       ## Header structure             ##
       ## 00 - 13(14): Ethernet Header ##
       ## 14 - 33(20): IP Header       ##
       ## 33 - 53(20): TCP Header      ##
       ##################################
    */


    /*  syscall_connect
        Specification
        1. If already bound, use that address.
        2. Else, automatically bind the socket with random port and local address(implicit bind)
        3. Get local address from its local routing information
        4. If there are multiple interfaces, source IP addresses are dependent on the destination
        5. Store remote address
        6. Send SYN
        7. Receive SYN+ACK then send ACK
        8. Returns 0 if connection/binding is successful, -1 if not.
        9. Make a function to map income packets to opened TCP sockets (use 4 field above)
        
        To-Do
        1. get source address and port
        2. create packet
        3. change socket in sock_list state to syn_sent
        4. add dst_addr to socket in sock_list
        5. add copied socket to cli_list and uuid_list
    */


void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t addrlen) {
    //printf("CALL CONNECT\n");

    // make pidfd and sockaddr_in structure
    struct PidFd pidfd = PidFd(pid, fd);
    struct sockaddr_in *svr_addr_in = (sockaddr_in *)addr;

    // check if the socket is valid and has closed state
    if ((!find_sock(pidfd)) ||
        (get_sock(pidfd)->state.compare("CLOSED") != 0)) {
        returnSystemCall(syscallUUID, -1);
        return;
    }

    // ip address and port should be in network order
    // save destination address
    uint32_t dst_ip = svr_addr_in->sin_addr.s_addr;
    uint16_t dst_port = svr_addr_in->sin_port;
    
    // get source address from the host
    uint32_t src_ip;
    uint16_t src_port;
    
    getHost()->getIPAddr(((uint8_t *)(&src_ip)),
                        getHost()->getRoutingTable((uint8_t *)(&dst_ip)));
    
    // get source port randomly and if occured, handling simultaneous open
    if (find_bind(pidfd)) {
        src_port = get_bind(pidfd)->src_addr.sin_port;
    } else {
        srand((unsigned int)time(NULL));
        int rand_port = rand() % (65536 - 1024);
        used_port[rand_port] = 1;
        src_port = rand_port + 1024;
        src_port = htons(src_port);
    }
    
    // create a new packet
    Packet *packet = allocatePacket(54);
    // write src/dst address to packet
    packet->writeData(14 + 12, &src_ip, 4);
    packet->writeData(14 + 16, &dst_ip, 4);
    packet->writeData(14 + 20 + 0, &src_port, 2);
    packet->writeData(14 + 20 + 2, &dst_port, 2);
    
    // write sequence number
    uint32_t seq_num = htonl(rand());
    packet->writeData(14 + 20 + 4, &seq_num, 4);
    seq_list.insert(make_pair(pidfd, ntohl(seq_num)));

    // fill in extra data
    uint32_t zero_4b = 0;
    uint8_t offset = 80;
    uint16_t window = htons((uint16_t)51200);
    uint32_t syn = syn_flag;
    packet->writeData(14 + 20 + 8, &zero_4b, 4);
    packet->writeData(14 + 20 + 12, &offset, 1);
    packet->writeData(14 + 20 + 13, &syn, 1);
    packet->writeData(14 + 20 + 14, &window, 2);
    packet->writeData(14 + 20 + 16, &zero_4b, 4);

    // calculate checksum
    uint8_t *tcp_header = (uint8_t *)malloc(20);
    packet->readData(14 + 20, tcp_header, 20);
   
    uint16_t checksum = ~(NetworkUtil::tcp_sum(src_ip, dst_ip, tcp_header, 20));
    checksum = htons(checksum);
    packet->writeData(14 + 20 + 16, &checksum, 2);

    struct sockaddr_in tmp_addr_in;
    tmp_addr_in.sin_addr.s_addr = src_ip;
    tmp_addr_in.sin_port = src_port;
    struct Sock *sock = get_sock(pidfd);

    sock->state = "SYN_SENT";
    sock->src_addr = tmp_addr_in;
    sock->dst_addr = *svr_addr_in;

    struct Sock *new_sock_cli = (struct Sock *)malloc(sizeof(struct Sock));
    struct Sock *new_sock_bind = (struct Sock *)malloc(sizeof(struct Sock));
    memcpy(new_sock_cli, sock, sizeof(struct Sock));
    memcpy(new_sock_bind, sock, sizeof(struct Sock));
    bind_list[pidfd] = *new_sock_bind;
    cli_list.insert(make_pair(pidfd, *new_sock_cli));
    reversed_cli_list.insert(make_pair(*new_sock_cli, pidfd));
    uuid_list.insert(make_pair(pidfd, syscallUUID));

    this->sendPacket("IPv4", packet);
    //printf("SEND SYN\n");
    return;
}

/* connection handling mechanism
    0. listen
        (1) initialize listenq with backlog size
        (2) initialize completeq
    1. connect before accept
        (1) Get SYN, add to listenq
        (2) GET ACK, remove from listenq, add to completeq
        (3) Accept called, consume from completeq, add to estab_list, remove from svr_list and reversed_svr_list, and return
    2. connect after accept
        (1) Accept is blocked, saving uuid, addr, addrlen, new fd
        (2) GET ACK, handle the block accept, handle sock list  and return here
*/

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd, int backlog) {
    //printf("CALL LISTEN\n");
    struct PidFd pidfd = PidFd(pid, fd);

    if (!find_sock(pidfd)) {
        returnSystemCall(syscallUUID, -1);
        return;
    }
    
    struct Sock *sock = get_sock(pidfd);

    if (sock->state.compare("CLOSED") != 0) {
        returnSystemCall(syscallUUID, -1);
        return;
    }
    
    if (!find_bind(pidfd)) {
        returnSystemCall(syscallUUID, -1);
        return;
    }

    sock->state = "LISTEN";
    struct Sock *sock2 = get_bind(pidfd);
    sock2->state = "LISTEN";

    int b_log = backlog;
    deque<struct Sock> this_listenq;
    deque<struct Sock> this_completeq;

    listenq.insert(make_pair(pidfd, make_pair(b_log, this_listenq)));
    completeq.insert(make_pair(pidfd, this_completeq));

    returnSystemCall(syscallUUID, 0);
    return;
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t *addrlen) {
    //printf("CALL ACCEPT\n");
    struct PidFd pidfd = PidFd(pid, fd);
    struct sockaddr_in *addr_in = (sockaddr_in *)addr;

    if (!find_listenq(pidfd)) {
        returnSystemCall(syscallUUID, -1);
    }

    if (!find_completeq(pidfd)) {
        returnSystemCall(syscallUUID, -1);
    }

    auto *cq = get_completeq(pidfd);

    if (cq->empty()) { // block accept()
        if (find_accept_info(pidfd)) {
            auto *accept_info = get_accept_info(pidfd);
            accept_info->insert(make_pair(syscallUUID, make_pair(addr, addrlen)));
        } else {
            set<pair<UUID, pair<struct sockaddr *, socklen_t *>>> new_set;
            new_set.insert(make_pair(syscallUUID, make_pair(addr, addrlen)));
            accept_info_list.insert(make_pair(pidfd, new_set));
        }
    } else { // consume one connnection
        struct Sock consumed_sock = cq->front();
        cq->pop_front();

        int new_fd = createFileDescriptor(pid);
        struct PidFd new_pidfd = PidFd(pid, new_fd);

        struct Sock new_sock = consumed_sock;
        new_sock.state = "ESTAB";
        
        sock_list.insert(make_pair(new_pidfd, new_sock));
        estab_list.insert(make_pair(new_pidfd, new_sock));
        reversed_estab_list.insert(make_pair(new_sock, new_pidfd));

        memcpy(addr_in, &consumed_sock.dst_addr, sizeof(struct sockaddr_in));
        //*addrlen = sizeof(sockaddr_in);
        returnSystemCall(syscallUUID, new_fd);
    }
    return;

    /*
    Returns a nonnegative integer that is a file descriptor for the accepted socket

    If there is no completed connection
    Accept is blocked and waiting for connection
    
    If there are some completed connections
    Accept consumes one and returns immediately
    
    Create a new file descriptor for the incoming connection
    */
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t *addrlen) {
    //printf("CALL GETPEERNAME\n");
   /*
    Returns 0 on success, -1 on error
    Example from test case code:
    Obtains the address of the peer connected to the socket
    */
    struct PidFd pidfd = PidFd(pid, fd);

    if (!find_estab(pidfd)) {
        returnSystemCall(syscallUUID, -1);
        return;
    }

    struct Sock *sock = get_estab(pidfd);
    sock->dst_addr.sin_family = AF_INET;

    struct sockaddr_in *svr_addr_in = (struct sockaddr_in *)addr;
    memcpy(svr_addr_in, &sock->dst_addr, sizeof(struct sockaddr_in));
    
    returnSystemCall(syscallUUID, 0);
    return;
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int fd, void *buf, size_t count)
{
    //printf("CALL READ\n");
    struct PidFd pidfd = PidFd(pid, fd);
    
    if (!find_estab(pidfd)) {
        returnSystemCall(syscallUUID, -1);
        return;
    }

    uint8_t *buffer = (uint8_t *)buf;

    if (!find_read_buffer(pidfd)) {
        read_info_list[pidfd] = make_pair(syscallUUID, make_pair(buf, count));
        return;
    } else if (find_read_buffer(pidfd) && get_read_buffer(pidfd)->empty()) {
        read_info_list[pidfd] = make_pair(syscallUUID, make_pair(buf, count));
        return;
    } else {
        size_t read_b = 0;
        deque<uint8_t> *read_buffer = get_read_buffer(pidfd);
        while ((read_b < count) &&
                (!read_buffer->empty())) {
            memcpy(buffer, &read_buffer->front(), sizeof(uint8_t));
            read_buffer->pop_front();
            buffer++;
            read_b++;
        }
        returnSystemCall(syscallUUID, read_b);
        return;
    }
}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int fd, void *buf, size_t count)
{
    //printf("CALL WRITE\n");
    struct PidFd pidfd = PidFd(pid, fd);

    if (!find_estab(pidfd)) {
        returnSystemCall(syscallUUID, -1);
        return;
    }

    struct Sock *sock = get_estab(pidfd);//(struct Sock *)malloc(sizeof(struct Sock));
    //memcpy(sock, get_estab(pidfd), sizeof(struct Sock));
    size_t total_cnt = count;
    uint8_t *buffer = (uint8_t *)buf;
    size_t max_s = max_size;

    while (total_cnt > 0) {
        size_t current_cnt;
        bool last_flag = false;
        
        current_cnt = min(total_cnt, max_s);
        total_cnt = total_cnt - current_cnt;
        if (total_cnt == 0) {
            last_flag = true;
        }
        
        uint16_t packet_size = 54 + current_cnt;
        uint32_t src_ip = sock->src_addr.sin_addr.s_addr;
        uint32_t dst_ip = sock->dst_addr.sin_addr.s_addr;
        uint16_t src_port = sock->src_addr.sin_port;
        uint16_t dst_port = sock->dst_addr.sin_port;
        
        Packet *packet = allocatePacket(packet_size);
        
        packet->writeData(14 + 2, &packet_size, 2);
        packet->writeData(14 + 12, &src_ip, 4);
        packet->writeData(14 + 16, &dst_ip, 4);
        packet->writeData(14 + 20 + 0, &src_port, 2);
        packet->writeData(14 + 20 + 2, &dst_port, 2);
 
        uint32_t seq_num = 0;
    
        if (find_seq(pidfd)) {
            uint32_t cli_seq = get_seq(pidfd);
            seq_num = htonl(cli_seq);
            seq_list[pidfd] = cli_seq + current_cnt;
       } else {
            uint32_t svr_seq = sock->seq;
            seq_num = htonl(svr_seq);
            sock->seq = svr_seq + current_cnt;
        }

        packet->writeData(14 + 20 + 4, &seq_num, 4);

        uint32_t ack_num = htonl(sock->ack); // handle ack number
        packet->writeData(14 + 20 + 8, &ack_num, 4);
        
        // fill in extra data
        uint32_t zero_4b = 0;
        uint8_t offset = 80;
        uint16_t window = htons((uint16_t)51200);
        uint32_t ack = ack_flag;
        packet->writeData(14 + 20 + 12, &offset, 1);
        packet->writeData(14 + 20 + 13, &ack, 1);
        packet->writeData(14 + 20 + 14, &window, 2);
        packet->writeData(14 + 20 + 16, &zero_4b, 4);

        // write data
        packet->writeData(14 + 20 + 20, buffer, current_cnt);
    
        // calculate checksum
        uint8_t *tcp_header = (uint8_t *)malloc(20 + max_s);
        packet->readData(14 + 20, tcp_header, 20 + current_cnt);
   
        uint16_t checksum = ~(NetworkUtil::tcp_sum(src_ip, dst_ip, tcp_header, 20 + current_cnt));
        checksum = htons(checksum);
        packet->writeData(14 + 20 + 16, &checksum, 2);

        if (!find_internal_buffer(pidfd)) {
            size_t init_zero = 0;
            map<int, Packet *> new_map;
            new_map.clear();
            internal_buffer_list[pidfd] = make_pair(init_zero, new_map);
        }

        auto *ib = get_internal_buffer(pidfd);
        if (ib->first + current_cnt <= ntohs(window)) {
            this->sendPacket("IPv4", packet);
            ib->first = ib->first + current_cnt;
            Packet *internal_packet = this->clonePacket(packet);
            int ack_expected;
            if (find_seq(pidfd)) {
                ack_expected = get_seq(pidfd);
            } else {
                ack_expected = sock->seq;
            }        
            ib->second[ack_expected] = internal_packet;
            if (last_flag) {
                returnSystemCall(syscallUUID, count);
            }
        } else {
            if (!find_blocked_packet(pidfd)) {
                map<UUID, deque<pair<int, Packet *>>> new_map;
                new_map.clear();
                blocked_packet_list[pidfd] = new_map;
            }

            if (!find_blocked_uuid(pidfd)) {
                deque<pair<UUID, size_t>> new_deque;
                new_deque.clear();
                blocked_uuid_list[pidfd] = new_deque;
            }
            
            auto *bu = get_blocked_uuid(pidfd);
            if (bu->back().first != syscallUUID) {
                bu->push_back(make_pair(syscallUUID, count));
            }

            int ack_expected;
            if (find_seq(pidfd)) {
                ack_expected = get_seq(pidfd);
            } else {
                ack_expected = sock->seq;
            }        

            auto *bp = get_blocked_packet(pidfd);
            if (bp->find(syscallUUID) == bp->end()) {
                deque<pair<int, Packet *>> new_deque;
                new_deque.push_back(make_pair(ack_expected, packet));
                bp->insert(make_pair(syscallUUID, new_deque));
            } else {
                bp->find(syscallUUID)->second.push_back(make_pair(ack_expected, packet));
            }
        }
        buffer = buffer + current_cnt;
    }
    return;
}
            
void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET: // Project1
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case CLOSE: // Project1, 2-2, 3-1
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ: // Project3-1
		this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE: // Project3-1
		this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT: // Project2-1
		this->syscall_connect(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN: // Project2-1
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT: // Project2-1
		this->syscall_accept(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND: // Project1
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME: // Project1
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME: // Project2-1
		this->syscall_getpeername(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(string fromModule, Packet* packet)
{
    // read data from packet
    uint32_t src_ip;
    uint32_t dst_ip;
    packet->readData(14 + 12, &dst_ip, 4);
    packet->readData(14 + 16, &src_ip, 4);
    uint16_t src_port;
    uint16_t dst_port;
    packet->readData(14 + 20 + 0, &dst_port, 2);
    packet->readData(14 + 20 + 2, &src_port, 2);
    uint32_t seq_num;
    packet->readData(14 + 20 + 4, &seq_num, 4); 
    uint32_t ack_num;
    packet->readData(14 + 20 + 8, &ack_num, 4);
    uint8_t offset;
    packet->readData(14 + 20 + 12, &offset, 1);
    uint8_t flag;
    packet->readData(14 + 20 + 13, &flag, 1);
    uint16_t window;
    packet->readData(14 + 20 + 14, &window, 2);

    // construct sock structure
    struct sockaddr_in src_addr;
    struct sockaddr_in dst_addr;
    src_addr.sin_addr.s_addr = src_ip;
    src_addr.sin_port = src_port;
    dst_addr.sin_addr.s_addr = dst_ip;
    dst_addr.sin_port = dst_port;
    struct Sock sock = Sock(src_addr, dst_addr);

    // change order
    src_ip = ntohl(src_ip);
    dst_ip = ntohl(dst_ip);
    src_port = ntohs(src_port);
    dst_port = ntohs(dst_port);
    seq_num = ntohl(seq_num);
    ack_num = ntohl(ack_num);

    // create packet from cloned packet, for each case of flag
    Packet *send = this->clonePacket(packet);

    switch (flag) {
    case synack_flag: {
        //printf("GET SYNACK\n");
        // if corresponding pidfd does not exist, return
        if (!find_reversed_cli(sock)) {
            this->freePacket(packet);
            this->freePacket(send);
            return;
        }

        // construct pidfd struct for list searching
        struct PidFd *pidfd = (struct PidFd *)malloc(sizeof(struct PidFd));
   
        // copy pidfd from reversed_cli_list
        memcpy(pidfd, get_reversed_cli(sock), sizeof(struct PidFd));
        
        // find seq with pidfd, if not exist, return
        if (!find_seq(*pidfd)) {
            this->freePacket(packet);
            this->freePacket(send);
            return;
        }

        // if seq + 1 != ack, meaning that ack inappropriate, return
        if (get_seq(*pidfd) + 1 != ack_num) {
            this->freePacket(packet);
            this->freePacket(send);
            return;
        }

        // if corresponding sock not found, return
        if (!find_cli(*pidfd)) {
            this->freePacket(packet);
            this->freePacket(send);
            return; 
        }

        // if corresponding sock does not have syn_sent, return
        if (get_cli(*pidfd)->state.compare("SYN_SENT") != 0) {
            this->freePacket(packet);
            this->freePacket(send);
            return;
        }
        
        // set ack to seq_num + 1
        ack_num = seq_num + 1;
        if (find_seq(*pidfd)) {
            seq_list[*pidfd] = seq_list[*pidfd] + 1;
            seq_num = get_seq(*pidfd) ;
        }
        
        // get ack flag
        uint8_t ack = ack_flag;

        // change order to network order
        src_ip = htonl(src_ip);
        dst_ip = htonl(dst_ip);
        src_port = htons(src_port);
        dst_port = htons(dst_port);
        seq_num = htonl(seq_num);
        ack_num = htonl(ack_num);

        // write data to packet
        send->writeData(14 + 12, &src_ip, 4);
        send->writeData(14 + 16, &dst_ip, 4);
        send->writeData(14 + 20 + 0, &src_port, 2);
        send->writeData(14 + 20 + 2, &dst_port, 2);
        send->writeData(14 + 20 + 4, &seq_num, 4);
        send->writeData(14 + 20 + 8, &ack_num, 4);
        send->writeData(14 + 20 + 12, &offset, 1);
        send->writeData(14 + 20 + 13, &ack, 1);
        send->writeData(14 + 20 + 14, &window, 2);
         
        // calculate checksum
        uint16_t zero_2b = 0;
        send->writeData(14 + 20 + 16, &zero_2b, 2);
        uint8_t *tcp_header = (uint8_t *)malloc(20);
        send->readData(14 + 20, tcp_header, 20);
        uint16_t checksum = htons(~NetworkUtil::tcp_sum(src_ip, dst_ip, tcp_header, 20));
        send->writeData(14 + 20 + 16, &checksum, 2);
    
        /* handle list
            1. update sock_list state
            2. remove from cli and reversed_cli
            3. add to estab and reversed_estab
        */
        struct Sock *the_sock = get_sock(*pidfd);
        the_sock->state = "ESTAB";
        the_sock->src_addr = src_addr;
        the_sock->dst_addr = dst_addr;
        the_sock->ack = ntohl(ack_num);
        remove_cli(*pidfd);
        remove_reversed_cli(*the_sock);
        struct Sock *new_sock = (struct Sock *)malloc(sizeof(struct Sock));
        memcpy(new_sock, the_sock, sizeof(struct Sock));
        estab_list.insert(make_pair(*pidfd, *new_sock));
        reversed_estab_list.insert(make_pair(*new_sock, *pidfd));
 
        UUID syscallUUID = get_uuid(*pidfd);
        returnSystemCall(syscallUUID, 0);
        this->sendPacket("IPv4", send);
        //printf("SEND ACK\n");
        break;
        }

    case syn_flag: {
        //printf("GET SYN\n");
        // server get syn from client connect
        
        struct Sock temp_sock;
        struct PidFd temp_pidfd;

        bool flag = false;

        /* #########################################
           ## CHANGE FROM BIND LIST TO LISTEN LIST##
           ######################################### */

        for (auto iter = bind_list.begin();iter != bind_list.end();iter++) {
            if (((iter->second.src_addr.sin_addr.s_addr == htonl(src_ip)) ||
                (iter->second.src_addr.sin_addr.s_addr == 0)) &&
                (iter->second.src_addr.sin_port == htons(src_port))) {
                    temp_pidfd = iter->first;
                    temp_sock = iter->second;
                    flag = true;
                    break;
            }
        }

        if (!flag) {
            this->freePacket(packet);
            this->freePacket(send);
            return;
        }

        bool simul_case = false;
        if (temp_sock.state.compare("LISTEN") != 0) {
            if (temp_sock.state.compare("SYN_SENT") != 0) {
                this->freePacket(packet);
                this->freePacket(send);
                return;
            } else {
                simul_case = true;
            }
        }

        if (simul_case) { // simultaneous case
            ack_num = seq_num + 1;
            seq_num = get_seq(temp_pidfd);
            uint8_t synack = synack_flag;
            send->writeData(14 + 20 + 13, &synack, 1);
        } else {

            if (!find_listenq(temp_pidfd)) {
                this->freePacket(packet);
                this->freePacket(send);
                return;
            }

            auto *lq = get_listenq(temp_pidfd);
            int backlog_size = lq->first;
            auto *this_lq = &lq->second;

            if ((int)this_lq->size() >= backlog_size) {
                this->freePacket(packet);
                this->freePacket(send);
                return;
            } else {
                lq->second.push_back(sock);
            }

            // construct packet to send
            ack_num = seq_num + 1;
            seq_num = rand();

            uint8_t synack = synack_flag;
            send->writeData(14 + 20 + 13, &synack, 1);
            if (!find_svr(temp_pidfd)) {
                deque<struct Sock> new_set;
                sock.seq = seq_num + 1;
                sock.ack = ack_num;
                sock.state = "SYN_RCVD";
                new_set.push_back(sock);
                svr_list.insert(make_pair(temp_pidfd, new_set));
            } else {
                deque<struct Sock> *the_set = get_svr(temp_pidfd);
                sock.seq = seq_num + 1;
                sock.ack = ack_num;
                sock.state = "SYN_RCVD";
                the_set->push_back(sock);
            }
        }

        // change order to network order
        src_ip = htonl(src_ip);
        dst_ip = htonl(dst_ip);
        src_port = htons(src_port);
        dst_port = htons(dst_port);
        seq_num = htonl(seq_num);
        ack_num = htonl(ack_num);

        // write data to packet
        send->writeData(14 + 12, &src_ip, 4);
        send->writeData(14 + 16, &dst_ip, 4);
        send->writeData(14 + 20 + 0, &src_port, 2);
        send->writeData(14 + 20 + 2, &dst_port, 2);
        send->writeData(14 + 20 + 4, &seq_num, 4);
        send->writeData(14 + 20 + 8, &ack_num, 4);
        send->writeData(14 + 20 + 12, &offset, 1); 
        send->writeData(14 + 20 + 14, &window, 2);

        // calculate checksum
        uint16_t zero_2b = 0;
        send->writeData(14 + 20 + 16, &zero_2b, 2);
        uint8_t *tcp_header = (uint8_t *)malloc(20);
        send->readData(14 + 20, tcp_header, 20);
        uint16_t checksum = htons(~NetworkUtil::tcp_sum(src_ip, dst_ip, tcp_header, 20));
        send->writeData(14 + 20 + 16, &checksum, 2);

        this->sendPacket("IPv4", send);
        if (simul_case) {
            //printf("SEND ACK\n");
        } else {
            //printf("SEND SYNACK\n");
        }
        break;
        }
    case ack_flag: {
        //printf("GET ACK\n");
        if (find_reversed_estab(sock)) { // Comment: Receive ACK from established connection during data transfer and connection teardown
            struct PidFd *estab_pidfd = (struct PidFd *)malloc(sizeof(struct PidFd));
            memcpy(estab_pidfd, get_reversed_estab(sock), sizeof(struct PidFd));
            
            if (!find_estab(*estab_pidfd)) {
                this->freePacket(send);
                this->freePacket(packet);
                return;
            }

            struct Sock *estab_sock = get_estab(*estab_pidfd);

            string estab_state = estab_sock->state;
            if (estab_state.compare("ESTAB") == 0) { /* ||
                (estab_state.compare("FIN_W1") &&
                () */
                size_t data_len = packet->getSize() - 54;
                if (find_internal_buffer(*estab_pidfd)) {
                    int ack_received = ack_num;
                    auto *ib = get_internal_buffer(*estab_pidfd);
                    Packet *tmp_p = ib->second.find(ack_received)->second;
                    size_t tmp_size = tmp_p->getSize() - 54;
                    ib->second.erase(ack_received);
                    ib->first = ib->first - tmp_size;
                    if (find_blocked_uuid(*estab_pidfd)) {
                        auto *bu = get_blocked_uuid(*estab_pidfd);
                        auto *bp = get_blocked_packet(*estab_pidfd);
                        if (!bu->empty()) {
                            UUID cur_uuid = bu->front().first;
                            Packet *cur_packet = bp->find(cur_uuid)->second.front().second;
                            int expected_ack = bp->find(cur_uuid)->second.front().first;
                            size_t cur_size = cur_packet->getSize() - 54;
                            while (ib->first + cur_size <= 51200) { // handle this to window size
                                bp->find(cur_uuid)->second.pop_front();
                                Packet *ib_packet = this->clonePacket(cur_packet);
                                this->sendPacket("IPv4", cur_packet);
                                ib->second.insert(make_pair(expected_ack, ib_packet));
                                ib->first = ib->first + cur_size;
                                if (bp->find(cur_uuid)->second.empty()) {
                                    size_t return_size = bu->front().second;
                                    returnSystemCall(cur_uuid, return_size);
                                    bu->pop_front();
                                    bp->erase(cur_uuid);
                                }
                                if (bu->empty()) {
                                    break;
                                }
                                cur_uuid = bu->front().first;
                                cur_packet = bp->find(cur_uuid)->second.front().second;
                                expected_ack = bp->find(cur_uuid)->second.front().first;
                                cur_size = cur_packet->getSize() - 54;
                            }
                        }
                    }
                }
                if (data_len > 0) {
                    for (unsigned int i = 0;i < data_len;i++) {
                        uint8_t data;
                        packet->readData(54 + i, &data, 1);
                        if (!find_read_buffer(*estab_pidfd)) {
                            deque<uint8_t> new_read_buffer;
                            new_read_buffer.clear();
                            read_buffer_list[*estab_pidfd] = new_read_buffer;
                        }
                        get_read_buffer(*estab_pidfd)->push_back(data);
                    }

                    if (find_read_info(*estab_pidfd)) {
                        pair<UUID, pair<void *, size_t>> *read_info = get_read_info(*estab_pidfd);
                        UUID read_uuid = read_info->first;
                        uint8_t *buffer = (uint8_t *)read_info->second.first;
                        size_t read_len = read_info->second.second;

                        size_t read_b = 0;
                        deque<uint8_t> *read_buffer = get_read_buffer(*estab_pidfd);
                        while (read_b < read_len) {
                            if (read_buffer->empty()) {
                                break;
                            }
                            memcpy(buffer, &read_buffer->front(), sizeof(uint8_t));
                            read_buffer->pop_front();
                            buffer++;
                            read_b++;
                        }
                        read_info_list.erase(*estab_pidfd);
                        returnSystemCall(read_uuid, read_b);
                    }

                    send = this->allocatePacket(54);

                    src_ip = htonl(src_ip);
                    dst_ip = htonl(dst_ip);
                    src_port = htons(src_port);
                    dst_port = htons(dst_port);
                    ack_num = htonl(seq_num + data_len);
                    if (find_seq(*estab_pidfd)) {
                        seq_num = htonl(get_seq(*estab_pidfd)); // handle seq number later
                    } else {
                        seq_num = htonl(estab_sock->seq);
                    }
                    // write data to packet
                    send->writeData(14 + 12, &src_ip, 4);
                    send->writeData(14 + 16, &dst_ip, 4);
                    send->writeData(14 + 20 + 0, &src_port, 2);
                    send->writeData(14 + 20 + 2, &dst_port, 2);
                    send->writeData(14 + 20 + 4, &seq_num, 4);
                    send->writeData(14 + 20 + 8, &ack_num, 4);
                    send->writeData(14 + 20 + 12, &offset, 1);
                    uint8_t ack = ack_flag;
                    send->writeData(14 + 20 + 13, &ack, 1);
                    send->writeData(14 + 20 + 14, &window, 2); // handle window size after

                    // calculate checksum
                    uint16_t zero_2b = 0;
                    send->writeData(14 + 20 + 16, &zero_2b, 2);
                    uint8_t *tcp_header = (uint8_t *)malloc(20);
                    send->readData(14 + 20, tcp_header, 20);
                    uint16_t checksum = htons(~NetworkUtil::tcp_sum(src_ip, dst_ip, tcp_header, 20));
                    send->writeData(14 + 20 + 16, &checksum, 2);
                    this->freePacket(packet);
                    this->sendPacket("IPv4", send);
                    //printf("SEND ACK\n");
                }
            } else if (estab_state.compare("FIN_W1") == 0) {
                estab_sock->state = "FIN_W2";
            } else if (estab_state.compare("LAST_ACK") == 0) {
                if (!find_close(*estab_pidfd)) {
                    this->freePacket(send);
                    this->freePacket(packet);
                    return;
                }
           
                UUID close_uuid = get_close(*estab_pidfd);

                remove_close(*estab_pidfd);
                remove_sock(*estab_pidfd);
                remove_bind(*estab_pidfd);
                remove_cli(*estab_pidfd);
                if (find_cli(*estab_pidfd)) {
                    struct Sock cli_sock = *get_cli(*estab_pidfd);
                    remove_reversed_cli(cli_sock);
                }
                remove_svr(*estab_pidfd);
                remove_estab(*estab_pidfd);
                if (find_estab(*estab_pidfd)) {
                    struct Sock est_sock = *get_estab(*estab_pidfd);
                    remove_reversed_estab(est_sock);
                }
                remove_uuid(*estab_pidfd);
                remove_seq(*estab_pidfd);
                remove_listenq(*estab_pidfd);
                remove_completeq(*estab_pidfd);
                remove_accept_info(*estab_pidfd);

                removeFileDescriptor(estab_pidfd->pid, estab_pidfd->fd);
                returnSystemCall(close_uuid, 0);
            } else if (estab_state.compare("SIMUL_C") == 0) {
                struct PidFd *tmp_ptr = (struct PidFd *)malloc(sizeof(struct PidFd));
                memcpy(tmp_ptr, &estab_pidfd, sizeof(struct PidFd));
                //timer_list.insert(make_pair(*estab_pidfd, tmp_ptr));
                this->addTimer(tmp_ptr, 3);
                estab_sock->state = "TIME_W";
            } else {
                this->freePacket(send);
                this->freePacket(packet);
                return;
            }
        } else { // Comment: Receive ACK from unestablished connection during connection setup
            struct PidFd temp_pidfd;

            bool flag = false;

            /* #########################################
               ## CHANGE FROM BIND LIST TO LISTEN LIST##
               ######################################### */

            // get the pid with src_addr of received packet
            for (auto iter = bind_list.begin();iter != bind_list.end();iter++) {
                if (((iter->second.src_addr.sin_addr.s_addr == htonl(src_ip)) ||
                     (iter->second.src_addr.sin_addr.s_addr == 0)) &&
                    (iter->second.src_addr.sin_port == htons(src_port))) {
                    temp_pidfd = iter->first;
                    flag = true;
                    break;
                }
            }

            // if corresponding pidfd not found, return immediately
            if (!flag) {
                this->freePacket(packet);
                this->freePacket(send);
                return;
            }
            // create new socket and find unestablished socket from svr_list with the pidfd get from upper lines
            struct Sock *unestab_sock = (struct Sock *)malloc(sizeof(struct Sock));

            flag = false;
            for (auto iter = svr_list.begin();iter != svr_list.end();iter++) {
                if (iter->first == temp_pidfd) {
                    auto *set_ptr = &iter->second;
                    for (auto iter2 = set_ptr->begin();iter2 != set_ptr->end();iter2++) {
                        if (*iter2 == sock) {
                            struct Sock *tmp_sock_ptr = (struct Sock *)&(*iter2);
                            memcpy(unestab_sock, tmp_sock_ptr, sizeof(struct Sock));
                            set_ptr->erase(iter2);
                            flag = true;
                            break;
                        }
                    }
                    if (flag) {
                        break;
                    }
                }
            }

            // if not found, return immediately
            if (!flag) {
                this->freePacket(packet);
                this->freePacket(send);
                return;
            }
            this->freePacket(send);

            if (find_cli(temp_pidfd)) { // simultaneous case
                if (*unestab_sock == *get_cli(temp_pidfd)) {
                    struct Sock *cli_sock = (struct Sock *)malloc(sizeof(struct Sock));
                    memcpy(cli_sock, get_cli(temp_pidfd), sizeof(struct Sock));
                    UUID uuid = get_uuid(temp_pidfd);
                    remove_cli(temp_pidfd);
                    cli_sock->state = "ESTAB";
                    estab_list.insert(make_pair(temp_pidfd, *cli_sock));
                    reversed_estab_list.insert(make_pair(*cli_sock, temp_pidfd));
                    get_sock(temp_pidfd)->state = "ESTAB";
                    returnSystemCall(uuid, 0);
                    this->freePacket(packet);
                    return;
                }
            } else { // not simultaneous case (server received ack from client)
                // check the validity of ack number
                if (unestab_sock->seq != ack_num) {
                    this->freePacket(packet);
                    return;
                }

                if (find_accept_info(temp_pidfd)) { // if accept is already called so that accept_info_list with temp_pidfd is initialized.
                    auto *accept_info = get_accept_info(temp_pidfd);
                    if (!accept_info->empty()) { // some blocked accept call
                        UUID uuid = accept_info->begin()->first;
                        struct sockaddr_in *addr_in = (struct sockaddr_in *)accept_info->begin()->second.first;
                        memcpy(addr_in, &unestab_sock->dst_addr, sizeof(struct sockaddr_in));
                        //socklen_t *len_t = accept_info->begin()->second.second;
                        //*len_t = (socklen_t)sizeof(sockaddr_in);

                        accept_info->erase(accept_info->begin());

                        int new_fd = createFileDescriptor(temp_pidfd.pid);
                        struct PidFd new_pidfd = PidFd(temp_pidfd.pid, new_fd);

                        unestab_sock->state = "ESTAB";
                        estab_list.insert(make_pair(new_pidfd, *unestab_sock));
                        reversed_estab_list.insert(make_pair(*unestab_sock, new_pidfd));
 
                        struct Sock *brand_new_sock = (struct Sock *)malloc(sizeof(struct Sock));
                        memcpy(brand_new_sock, unestab_sock, sizeof(struct Sock));
                        sock_list.insert(make_pair(new_pidfd, *brand_new_sock));
                        

                        auto *lq = &get_listenq(temp_pidfd)->second;
                        for (auto iter = lq->begin();iter != lq->end();iter++) {
                            if (*iter == *unestab_sock) {
                                lq->erase(iter);
                                break;
                            }
                        }

                        returnSystemCall(uuid, new_fd);
                    } else { // no blocked accept call
                        unestab_sock->state = "ESTAB";

                        auto *lq = &get_listenq(temp_pidfd)->second;
                        auto *cq = get_completeq(temp_pidfd);

                        for (auto iter = lq->begin();iter != lq->end();iter++) {
                            if (*iter == *unestab_sock) {
                                lq->erase(iter);
                                break;
                            }
                        }

                        cq->push_back(*unestab_sock);
                    }
                } else { // if accept is not called yet, accept_info_list with temp_pidfd should be initialized with empty set first
                    set<pair<UUID, pair<struct sockaddr *, socklen_t *>>> new_set;
                    accept_info_list.insert(make_pair(temp_pidfd, new_set));

                    unestab_sock->state = "ESTAB";

                    auto *lq = &get_listenq(temp_pidfd)->second;
                    auto *cq = get_completeq(temp_pidfd);

                    for (auto iter = lq->begin();iter != lq->end();iter++) {
                        if (*iter == *unestab_sock) {
                            lq->erase(iter);
                            break;
                        }
                    }

                    cq->push_back(*unestab_sock);
                }
            }
        }       
        break;
        }
    case fin_flag: {
        //printf("GET FIN\n");
        struct PidFd temp_pidfd;
        struct Sock *cq_sock = (struct Sock *)malloc(sizeof(struct Sock));

        bool flag = false;
        // get the pid with src_addr of received packet
        for (auto iter = estab_list.begin();iter != estab_list.end();iter++) {
            if (iter->second == sock) {
                temp_pidfd = iter->first;
                flag = true;
                break;
            }
        }

        bool in_cq = false;

        if (!flag) {
            for (auto iter = completeq.begin();iter != completeq.end();iter++) {
                auto *cq = &iter->second;
                bool found = false;
                for (auto iter2 = cq->begin();iter2 != cq->end();iter2++) {
                    if (*iter2 == sock) {
                        iter2->state = "CLOSE_W";
                        flag = true;
                        found = true;
                        in_cq = true;
                        memcpy(cq_sock, (struct Sock *)&(*iter2), sizeof(struct Sock));
                        temp_pidfd = iter->first;
                        break;
                    }
                }
                if (found) {
                    break;
                }
            }
        }

        // if corresponding pidfd not found, return immediately
        if (!flag) {
            this->freePacket(packet);
            this->freePacket(send);
            return;
        }

        if (in_cq) { // if sock in completeq matches
            ack_num = seq_num + 1;
            cq_sock->seq = cq_sock->seq; //+ 1;
            seq_num = cq_sock->seq;
 
            // change order to network order
            src_ip = htonl(src_ip);
            dst_ip = htonl(dst_ip);
            src_port = htons(src_port);
            dst_port = htons(dst_port);
            seq_num = htonl(seq_num);
            ack_num = htonl(ack_num);

            // write data to packet
            send->writeData(14 + 12, &src_ip, 4);
            send->writeData(14 + 16, &dst_ip, 4);
            send->writeData(14 + 20 + 0, &src_port, 2);
            send->writeData(14 + 20 + 2, &dst_port, 2);
            send->writeData(14 + 20 + 4, &seq_num, 4);
            send->writeData(14 + 20 + 8, &ack_num, 4);
            send->writeData(14 + 20 + 12, &offset, 1); 
            uint8_t ack = ack_flag;
            send->writeData(14 + 20 + 13, &ack, 1);
            send->writeData(14 + 20 + 14, &window, 2);

            // calculate checksum
            uint16_t zero_2b = 0;
            send->writeData(14 + 20 + 16, &zero_2b, 2);
            uint8_t *tcp_header = (uint8_t *)malloc(20);
            send->readData(14 + 20, tcp_header, 20);
            uint16_t checksum = htons(~NetworkUtil::tcp_sum(src_ip, dst_ip, tcp_header, 20));
            send->writeData(14 + 20 + 16, &checksum, 2);
            this->freePacket(packet);
            this->sendPacket("IPv4", send);
            //printf("SEND ACK\n");
            return;
        } else {
            if (!find_estab(temp_pidfd)) {
                this->freePacket(packet);
                this->freePacket(send);
                return;
            }
            struct Sock *svr_sock = get_estab(temp_pidfd);
            ack_num = seq_num + 1;
            if (find_seq(temp_pidfd)) {
                if (svr_sock->state.compare("ESTAB") != 0) {
                    seq_list[temp_pidfd] = seq_list[temp_pidfd] + 1;
                }
                seq_num = get_seq(temp_pidfd);
            } else {
                svr_sock->seq = svr_sock->seq;// + 1;
                seq_num = svr_sock->seq;
            }

            // change order to network order
            src_ip = htonl(src_ip);
            dst_ip = htonl(dst_ip);
            src_port = htons(src_port);
            dst_port = htons(dst_port);
            seq_num = htonl(seq_num);
            ack_num = htonl(ack_num);

            // write data to packet
            send->writeData(14 + 12, &src_ip, 4);
            send->writeData(14 + 16, &dst_ip, 4);
            send->writeData(14 + 20 + 0, &src_port, 2);
            send->writeData(14 + 20 + 2, &dst_port, 2);
            send->writeData(14 + 20 + 4, &seq_num, 4);
            send->writeData(14 + 20 + 8, &ack_num, 4);
            send->writeData(14 + 20 + 12, &offset, 1); 
            uint8_t ack = ack_flag;
            send->writeData(14 + 20 + 13, &ack, 1);
            send->writeData(14 + 20 + 14, &window, 2);

            // calculate checksum
            uint16_t zero_2b = 0;
            send->writeData(14 + 20 + 16, &zero_2b, 2);
            uint8_t *tcp_header = (uint8_t *)malloc(20);
            send->readData(14 + 20, tcp_header, 20);
            uint16_t checksum = htons(~NetworkUtil::tcp_sum(src_ip, dst_ip, tcp_header, 20));
            send->writeData(14 + 20 + 16, &checksum, 2);

            string tmp_state = svr_sock->state;

            if (tmp_state.compare("FIN_W2") == 0) {
                svr_sock->state = "TIME_W";
                struct PidFd *tmp_ptr = (struct PidFd *)malloc(sizeof(struct PidFd));
                memcpy(tmp_ptr, &temp_pidfd, sizeof(struct PidFd));
                //timer_list.insert(make_pair(temp_pidfd, tmp_ptr));
                this->addTimer(tmp_ptr, 3);
                this->sendPacket("IPv4", send);
                //printf("SEND ACK\n");
            } else if (tmp_state.compare("ESTAB") == 0) {
                svr_sock->state = "CLOSE_W";
                this->sendPacket("IPv4", send);
                //printf("SEND ACK\n");
            } else if (tmp_state.compare("FIN_W1") == 0) {
                svr_sock->state = "SIMUL_C";
                this->sendPacket("IPv4", send);
                //printf("SEND ACK\n");
            } else {
                this->freePacket(packet);
                this->freePacket(send);
                return;
            }
        }
        break;
        }
    default: {
        this->freePacket(packet);
        this->freePacket(send);
        break;
        }
    }
}

void TCPAssignment::timerCallback(void* payload)
{
    struct PidFd *pidfd = (struct PidFd *)payload;

    removeFileDescriptor(pidfd->pid, pidfd->fd);

    if (!find_close(*pidfd)) {
        return;
    }

    remove_close(*pidfd);
    remove_sock(*pidfd);
    remove_bind(*pidfd);
    remove_cli(*pidfd);
    if (find_cli(*pidfd)) {
        struct Sock cli_sock = *get_cli(*pidfd);
        remove_reversed_cli(cli_sock);
    }
    remove_svr(*pidfd);
    remove_estab(*pidfd);
    if (find_estab(*pidfd)) {
        struct Sock est_sock = *get_estab(*pidfd);
        remove_reversed_estab(est_sock);
    }
    remove_uuid(*pidfd);
    remove_seq(*pidfd);
    remove_listenq(*pidfd);
    remove_completeq(*pidfd);
    remove_accept_info(*pidfd);
}

}
