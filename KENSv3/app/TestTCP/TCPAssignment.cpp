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
    uuid_list.clear();
    seq_list.clear();
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
queue<struct Sock> *TCPAssignment::get_listenq(struct PidFd pidfd) {
    queue<struct Sock> *lq;
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

    if (!find_bind(pidfd)) {
        returnSystemCall(syscallUUID, -1);
        return;
    }

    struct Sock *sock = get_bind(pidfd);
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

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd, int backlog) {
    /* TODO
        1v. check sock_list, return -1 if not exists
        2v. check socket status, return -1 if not closed
        3v. check bind_list, return -1 if not exists
        4v. change socket state to Listen
        5 . handle backlog
    */
/*
    struct PidFd pidfd = PidFd(pid, fd);

    if (!find_sock(pidfd)) {
        returnSystemCall(syscallUUID, -1);
        return;
    }
    
    struct Sock sock = get_sock(pidfd);

    if (sock.state.compare("CLOSED") != 0) {
        returnSystemCall(syscallUUID, -1);
        return;
    }
    
    if (!find_bind(pidfd)) {
        returnSystemCall(syscallUUID, -1);
        return;
    }

    sock.state = "LISTEN";
    struct Sock sock2 = get_bind(pidfd);
    sock2.state = "LISTEN";

    returnSystemCall(syscallUUID, 0);
    return;
*/
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t *addrlen) {
    /* TODO
    */
/*    struct PidFd pidfd = PidFd(pid, fd);
    struct sockaddr_in *addr_in = (sockaddr_in *)addr;

    if (!find_listenq(pidfd)) {
        returnSystemCall(syscallUUID, -1);
    }

    auto lq = get_listenq(pidfd);
    if (lq.empty()) { // block accept()
        uuid_list.insert(make_pair(pidfd, syscallUUID));
    } else { // consume one connnection
        int new_fd = createFileDescriptor(pid);
        
        struct PidFd new_pidfd = PidFd(pid, new_fd);
        
        struct Sock svr_sock = get_sock(pidfd);
        struct Sock new_sock = Sock(svr_sock.src_addr);
        
        sock_list.insert(make_pair(new_pidfd, new_sock));
        estab_list.insert(make_pair(new_pidfd, new_sock));

        struct Sock cli_sock = lq.front();
        lq.pop();
        memcpy(addr_in, &cli_sock, sizeof(struct sockaddr_in));
        *addrlen = sizeof(sockaddr_in);
        returnSystemCall(syscallUUID, new_fd);

    } */
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
    src_port = ntohs(src_port);
    dst_port = ntohs(dst_port);
    seq_num = ntohl(seq_num);
    ack_num = ntohl(ack_num);
    window = ntohs(window);

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
        uint16_t checksum = NetworkUtil::tcp_sum(src_ip, dst_ip, tcp_header, 20);
        checksum = htons(~checksum);
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
    case syn_flag: {
        break;
        }
    case ack_flag: {
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
