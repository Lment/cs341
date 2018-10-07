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


// Should be used after checking if find_* returns true
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

// Should be used after checking if find_* returns true
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

// Should be used after checking if find_* returns true
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

// Shohuld be used after checking if find_* returns true
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

// Should be used after checking if find_* returns true
set<struct Sock> *TCPAssignment::get_svr(struct PidFd pidfd) {
    set<struct Sock> *sock_set;
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

// Should be used after checking if find_* returns true
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

// Should be used after checking if find_* returns true
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

// Should be used after checking if find_* returns true
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

// Should be used after checking if find_* returns true
pair<int, set<struct Sock>> *TCPAssignment::get_listenq(struct PidFd pidfd) {
    pair<int, set<struct Sock>> *lq;
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
 

// Should be used after checking if find_* returns true
queue<struct Sock> *TCPAssignment::get_completeq(struct PidFd pidfd) {
    queue<struct Sock> *lq;
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
    int new_fd = createFileDescriptor(pid);

    struct PidFd pidfd = PidFd(pid, new_fd);
    struct Sock sock = Sock();

    sock_list.insert(make_pair(pidfd, sock));

    returnSystemCall(syscallUUID, new_fd);
    return;
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd) {
    removeFileDescriptor(pid, fd);
    
    struct PidFd pidfd = PidFd(pid, fd);

    remove_sock(pidfd);
    remove_bind(pidfd);
    remove_cli(pidfd);
    remove_svr(pidfd);
    remove_estab(pidfd);
    remove_uuid(pidfd);
    remove_seq(pidfd);
    remove_listenq(pidfd);

    returnSystemCall(syscallUUID, 0);
    return;
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t addrlen) {
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

    struct Sock *sock;//get_bind(pidfd);
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
    //////printf("Does connect called\n");

    // make pidfd and sockaddr_in structure
    struct PidFd pidfd = PidFd(pid, fd);
    struct sockaddr_in *svr_addr_in = (sockaddr_in *)addr;

    //////printf("connect part 1\n");
    // check if the socket is valid and has closed state
    if ((!find_sock(pidfd)) ||
        (get_sock(pidfd)->state.compare("CLOSED") != 0)) {
        returnSystemCall(syscallUUID, -1);
        return;
    }
    //////printf("connect part 2\n");

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
    uint8_t offset = 5;
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
    memcpy(new_sock_cli, sock, sizeof(struct Sock));
    bind_list.insert(make_pair(pidfd, *new_sock_cli));
    cli_list.insert(make_pair(pidfd, *new_sock_cli));
    reversed_cli_list.insert(make_pair(*new_sock_cli, pidfd));
    uuid_list.insert(make_pair(pidfd, syscallUUID));
    this->sendPacket("IPv4", packet);
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
    /* TODO
        1v. check sock_list, return -1 if not exists
        2v. check socket status, return -1 if not closed
        3v. check bind_list, return -1 if not exists
        4v. change socket state to Listen
        5 . handle backlog
    */
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
    set<struct Sock> this_listenq;
    queue<struct Sock> this_completeq;
    listenq.insert(make_pair(pidfd, make_pair(b_log, this_listenq)));
    completeq.insert(make_pair(pidfd, this_completeq));

    returnSystemCall(syscallUUID, 0);
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

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t *addrlen) {
    ////printf("Does accept called\n");
    struct PidFd pidfd = PidFd(pid, fd);
    struct sockaddr_in *addr_in = (sockaddr_in *)addr;
    //////printf("Accept part 1\n");
    if (!find_listenq(pidfd)) {
        returnSystemCall(syscallUUID, -1);
    }
    ////printf("Edge case 1 pass\n");
    //////printf("Accept part 2\n");
    if (!find_completeq(pidfd)) {
        returnSystemCall(syscallUUID, -1);
    }
    ////printf("Edge case 2 pass\n");
    //////printf("Accept part3\n");
    auto *cq = get_completeq(pidfd);
 

    ////printf("cq size before accept is %d\n", cq->size());
    if (cq->empty()) { // block accept()
        ////printf("Accept case1\n");
        auto iter = accept_info_list.find(pidfd);
        ////printf("accept info list size is %d\n", iter->second.size());
        if (iter != accept_info_list.end()) {
            //printf("accept 1-1 before %d %d, blocked size is %d\n", pidfd.pid, pidfd.fd, iter->second.size());
            iter->second.insert(make_pair(syscallUUID, make_pair(addr, addrlen)));
            //printf("accept 1-1 after %d %d, blocked size is %d\n", pidfd.pid, pidfd.fd, iter->second.size());
        } else {
            set<pair<UUID, pair<struct sockaddr *, socklen_t *>>> new_set;
            new_set.insert(make_pair(syscallUUID, make_pair(addr, addrlen)));
            accept_info_list.insert(make_pair(pidfd, new_set));
            //auto iter2 = accept_info_list.find(pidfd);
            //printf("accept 1-2 after %d %d, blocked size is %d\n", pidfd.pid, pidfd.fd, iter2->second.size());
        }
    } else { // consume one connnection
        ////printf("Accept case2\n");
        struct Sock consumed_sock = cq->front();
        cq->pop();

        int new_fd = createFileDescriptor(pid);
        struct PidFd new_pidfd = PidFd(pid, new_fd);

        struct Sock *to_get_sock_addr = get_bind(pidfd);
        struct Sock new_sock = Sock(to_get_sock_addr->src_addr);

        new_sock.state = "ESTAB";
        new_sock.dst_addr = consumed_sock.dst_addr;
        
        sock_list.insert(make_pair(new_pidfd, new_sock));
        estab_list.insert(make_pair(new_pidfd, new_sock));

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

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET: // Project1
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case CLOSE: // Project1
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
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
    //////printf("src is %d, dst is %d\n", src_ip, dst_ip);
    uint16_t src_port;
    uint16_t dst_port;
    packet->readData(14 + 20 + 0, &dst_port, 2);
    packet->readData(14 + 20 + 2, &src_port, 2);
    uint32_t seq_num;
    packet->readData(14 + 20 + 4, &seq_num, 4); 
    uint32_t ack_num;
    packet->readData(14 + 20 + 8, &ack_num, 4);
    uint16_t window;
    packet->readData(14 + 20 + 14, &window, 2);
    uint8_t flag;
    packet->readData(14 + 20 + 13, &flag, 1);

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
    //////printf("now src is %d, dst is %d\n", src_ip, dst_ip);
    src_port = ntohs(src_port);
    dst_port = ntohs(dst_port);
    seq_num = ntohl(seq_num);
    ack_num = ntohl(ack_num);
    //window = ntohs(window);

    // create packet from cloned packet, for each case of flag
    Packet *send = this->clonePacket(packet);

    switch (flag) {
    case synack_flag: {
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

        // get ack flag
        uint8_t ack = ack_flag;

        // change order to network order
        src_ip = htonl(src_ip);
        dst_ip = htonl(dst_ip);
        src_port = htons(src_port);
        dst_port = htons(dst_port);
        ack_num = htonl(ack_num);

        // write data to packet
        send->writeData(14 + 12, &src_ip, 4);
        send->writeData(14 + 16, &dst_ip, 4);
        send->writeData(14 + 20 + 0, &src_port, 2);
        send->writeData(14 + 20 + 2, &dst_port, 2);
        send->writeData(14 + 20 + 8, &ack_num, 4);
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
        remove_cli(*pidfd);
        remove_reversed_cli(*the_sock);
        struct Sock *new_sock = (struct Sock *)malloc(sizeof(struct Sock));
        memcpy(new_sock, the_sock, sizeof(struct Sock));
        estab_list.insert(make_pair(*pidfd, *new_sock));
        reversed_estab_list.insert(make_pair(*new_sock, *pidfd));
 
        UUID syscallUUID = get_uuid(*pidfd);
        returnSystemCall(syscallUUID, 0);
        this->sendPacket("IPv4", send);
        break;
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
            (2) GET SYN, add to listenq
            (3) GET ACK, handle the block accept, handle sock list  and return here
    */
    case syn_flag: {
        // server get syn from client connect
        // //printf("SYN!\n");
        
        struct Sock temp_sock;
        struct PidFd temp_pidfd;
        bool flag = false;
    
        //////printf("sock list size is %d\n", sock_list.size());
        //////printf("bind list size is %d\n", bind_list.size());
        //if (sock_list.empty()) {
        //    ////printf("sock list is empty\n");
        //}
        //!!!!!!!!!CHANGE FROM BIND TO LISTEN!!!!!!!!!!!!
        for (auto iter = bind_list.begin();iter != bind_list.end();iter++) {
            //////printf("%d %d %d %d\n", iter->second.src_addr.sin_addr.s_addr, iter->second.src_addr.sin_port, htonl(src_ip), htons(src_port));
            if (((iter->second.src_addr.sin_addr.s_addr == htonl(src_ip)) ||
                (iter->second.src_addr.sin_addr.s_addr == 0)) &&
                (iter->second.src_addr.sin_port == htons(src_port))) {
                    //////printf("IN IF\n");
                    temp_pidfd = iter->first;
                    temp_sock = iter->second;
                    flag = true;
                    break;
            }
        }
        ////printf("SYN part1\n");

        if (!flag) {
            this->freePacket(packet);
            this->freePacket(send);
            return;
        }

        bool simul_case = false;
        ////printf("SYN part2\n");
        if (temp_sock.state.compare("LISTEN") != 0) {
            if (temp_sock.state.compare("SYN_SENT") != 0) {
                this->freePacket(packet);
                this->freePacket(send);
                return;
            } else {
                simul_case = true;
            }
        }

        ////printf("SYN part3\n");

        if (simul_case) { // simultaneous case
            // ////printf("simultaneous cae\n");
            seq_num = 0;
            uint8_t ack = ack_flag;
            send->writeData(14 + 20 + 13, &ack, 1);
        } else {
            // ////printf("not simul case\n");

            if (!find_listenq(temp_pidfd)) {
                ////printf("candidate 1\n");
                this->freePacket(packet);
                this->freePacket(send);
                return;
            }

            auto *lq = get_listenq(temp_pidfd);
            int backlog_size = lq->first;
            auto *this_lq = &lq->second;
            ////printf("listenq size is %d backlog limit is %d\n", (int)this_lq->size(), backlog_size);
            if ((int)this_lq->size() >= backlog_size) {
                ////printf("candidate 2\n");
                // ////printf("OVER BACKLOG\n");
                this->freePacket(packet);
                this->freePacket(send);
                return;
            } else {
                lq->second.insert(sock);
            }

            // construct packet to send
            ack_num = seq_num + 1;
            seq_num = rand();

            uint8_t synack = synack_flag;
            send->writeData(14 + 20 + 13, &synack, 1);
 
            if (!find_svr(temp_pidfd)) {
                set<struct Sock> new_set;
                sock.seq = seq_num;
                new_set.insert(sock);
                svr_list.insert(make_pair(temp_pidfd, new_set));
            } else {
                set<struct Sock> *the_set = get_svr(temp_pidfd);
                sock.seq = seq_num;
                the_set->insert(sock);
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
        send->writeData(14 + 20 + 14, &window, 2);

        // calculate checksum
        uint16_t zero_2b = 0;
        send->writeData(14 + 20 + 16, &zero_2b, 2);
        uint8_t *tcp_header = (uint8_t *)malloc(20);
        send->readData(14 + 20, tcp_header, 20);
        uint16_t checksum = htons(~NetworkUtil::tcp_sum(src_ip, dst_ip, tcp_header, 20));
        send->writeData(14 + 20 + 16, &checksum, 2);

        this->sendPacket("IPv4", send);
        //////printf("packet sent\n");
        break;
        }
    case ack_flag: {
        // //printf("ACK!\n");
        //struct Sock *temp_sock = (struct Sock *)malloc(sizeof(struct Sock));
        struct PidFd temp_pidfd;
        bool flag = false;
    
        //////printf("sock list size is %d\n", sock_list.size());
        //////printf("bind list size is %d\n", bind_list.size());
        //if (sock_list.empty()) {
        //    ////printf("sock list is empty\n");
        //}

        //!!!!!!!!!CHANGE FROM BIND TO LISTEN!!!!!!!!!!!!
        for (auto iter = bind_list.begin();iter != bind_list.end();iter++) {
            // //printf("%d %d %d %d\n", iter->second.src_addr.sin_addr.s_addr, iter->second.src_addr.sin_port, htonl(src_ip), htons(src_port));
            if (((iter->second.src_addr.sin_addr.s_addr == htonl(src_ip)) ||
                (iter->second.src_addr.sin_addr.s_addr == 0)) &&
                (iter->second.src_addr.sin_port == htons(src_port))) {
                    ////printf("IN IF\n");
                    temp_pidfd = iter->first;
                    //memcpy(temp_sock, find_bind(temp_pidfd), sizeof(struct Sock));
                    //temp_sock = iter->second;
                    flag = true;
                    break;
            }
        }
        ////printf("ACK part1\n");

        if (!flag) {
            this->freePacket(packet);
            this->freePacket(send);
            return;
        }

        struct Sock *unestab_sock = (struct Sock *)malloc(sizeof(struct Sock));
    

        for (auto iter = svr_list.begin();iter != svr_list.end();iter++) {
            if (iter->first == temp_pidfd) {
                auto *set_ptr = &iter->second;
                auto iter = set_ptr->find(sock);
                struct Sock *tmp_sock_ptr = (struct Sock *)&(*set_ptr->find(sock));
                memcpy(unestab_sock, tmp_sock_ptr, sizeof(struct Sock));
                set_ptr->erase(iter);
                break;
/*                for (auto iter2 = set_ptr->begin();iter2 != set_ptr->end();iter2++) {
                    if (iter2 == sock) {
                        struct Sock *tmp_sock_ptr = (struct Sock *)iter2;
                        memcpy(unestab_sock, tmp_sock_ptr, sizeof(struct Sock));
                        set_ptr->erase(iter2);
                        break;
                    }
                }*/
            }
        }

        this->freePacket(send);
        
        if (find_cli(temp_pidfd)) {
            if (*unestab_sock == *get_cli(temp_pidfd)) {
                struct Sock *cli_sock = (struct Sock *)malloc(sizeof(struct Sock));
                memcpy(cli_sock, get_cli(temp_pidfd), sizeof(struct Sock));
                UUID uuid = get_uuid(temp_pidfd);
                remove_cli(temp_pidfd);
                cli_sock->state = "ESTAB";
                estab_list.insert(make_pair(temp_pidfd, *cli_sock));
                get_sock(temp_pidfd)->state = "ESTAB";
                returnSystemCall(uuid, 0);
                this->freePacket(packet);
                return;
            }
        } else {
            if (unestab_sock->seq + 1 != ack_num) {
                this->freePacket(packet);
                return;
            }

            if (find_accept_info(temp_pidfd)) {
                ////printf("ACK part 2\n");
                auto *accept_info = get_accept_info(temp_pidfd);
                if (!accept_info->empty()) { // some blocked accept call
                    // //printf("ACK part 2-2\n");
                    UUID uuid = accept_info->begin()->first;
                    struct sockaddr_in *addr_in = (struct sockaddr_in *)accept_info->begin()->second.first;
                    memcpy(addr_in, &unestab_sock->dst_addr, sizeof(struct sockaddr_in));
                    //socklen_t *len_t = accept_info->begin()->second.second;
                    //*len_t = (socklen_t)sizeof(sockaddr_in);
                    //printf("2-2(before): blocked accept number is %d\n", accept_info->size());
                    accept_info->erase(accept_info->begin());
                    //printf("2-2(after): blocked accept number is %d\n", accept_info->size());
                    ////printf("blocked number is now %d\n", accept_info->size());
                    int new_fd = createFileDescriptor(temp_pidfd.pid);
                    struct PidFd new_pidfd = PidFd(temp_pidfd.pid, new_fd);
                    unestab_sock->state = "ESTAB";
                    estab_list.insert(make_pair(new_pidfd, *unestab_sock));
                    struct Sock *brand_new_sock = (struct Sock *)malloc(sizeof(struct Sock));
                    memcpy(brand_new_sock, unestab_sock, sizeof(struct Sock));
                    sock_list.insert(make_pair(new_pidfd, *brand_new_sock));
                    auto *lq = &get_listenq(temp_pidfd)->second;
                    for (auto iter = lq->begin();iter != lq->end();iter++) {
                        ////printf("removing listenq\n");
                        if (*iter == *unestab_sock) {
                            ////printf("IN IF\n");
                            lq->erase(iter);
                            break;
                        }
                    }
                    returnSystemCall(uuid, new_fd);
                } else { // no blocked accept call
                    //printf("2-3: blocked accept number is %d\n", accept_info->size());
                    auto *lq = &get_listenq(temp_pidfd)->second;
                    auto *cq = get_completeq(temp_pidfd);
                    unestab_sock->state = "ESTAB";
                    for (auto iter = lq->begin();iter != lq->end();iter++) {
                        ////printf("IN listenq\n");
                        if (*iter == *unestab_sock) {
                            ////printf("FOUND\n");
                            lq->erase(iter);
                            break;
                        }
                    }
                    //printf("size of cq before %d\n", cq->size());
                    cq->push(*unestab_sock);
                    //printf("size of cq after  %d\n", cq->size());
                }
            } else {
                // //printf("ACK part 3\n");
                set<pair<UUID, pair<struct sockaddr *, socklen_t *>>> new_set;
                accept_info_list.insert(make_pair(temp_pidfd, new_set));

                auto *lq = &get_listenq(temp_pidfd)->second;
                auto *cq = get_completeq(temp_pidfd);
                unestab_sock->state = "ESTAB";
                for (auto iter = lq->begin();iter != lq->end();iter++) {
                    if (*iter == *unestab_sock) {
                        lq->erase(iter);
                        break;
                    }
                }
                cq->push(*unestab_sock);
            }
        }       
        break;
        }
    case fin_flag: {
        break;
        }
    default: {
        break;
        }
    }
}

void TCPAssignment::timerCallback(void* payload)
{

}


}
