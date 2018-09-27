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

}

void TCPAssignment::finalize()
{

}

bool TCPAssignment::is_addr_same(struct sockaddr addr_1, struct sockaddr addr_2) {
    // if same return true, else return false
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

bool TCPAssignment::sock_find_sock(struct PidFd pidfd) {
    bool flag = false;
    for (auto iter = sock_list.begin();iter != sock_list.end();iter++) {
        if (iter->first == pidfd) {
            flag = true;
            break;
        }
    }
    return flag;
}

bool TCPAssignment::bind_find_sock(struct PidFd pidfd) {
    int flag = false;
    for (auto iter = bind_list.begin();iter != bind_list.end();iter++) {
        if (iter->first == pidfd) {
            flag = true;
            break;
        }
    }
    return flag;
}

struct Sock TCPAssignment::sock_get_sock(struct PidFd pidfd) {
    auto iter = sock_list.find(pidfd);
    return iter->second;
}

struct Sock TCPAssignment::bind_get_sock(struct PidFd pidfd) {
    auto iter = bind_list.find(pidfd);
    return iter->second;
}

void TCPAssignment::sock_remove_sock(struct PidFd pidfd) {
    auto iter = sock_list.find(pidfd);
    if (iter != sock_list.end()) {
        sock_list.erase(iter);
    }
    return;
}

void TCPAssignment::bind_remove_sock(struct PidFd pidfd) {
    auto iter = bind_list.find(pidfd);
    if (iter != bind_list.end()) {
        bind_list.erase(iter);
    }
    return;
}

bool TCPAssignment::find_listen_q(struct PidFd pidfd) {
    bool flag = false;
    for (auto iter = listen_q.begin();iter != listen_q.end();iter++) {
        if (iter->first == pidfd) {
            flag = true;
            break;
        }
    }
    return flag;
}

std::queue<struct Sock> TCPAssignment::get_listen_q(struct PidFd pidfd) {
    auto iter = listen_q.find(pidfd);
    return iter->second;
}
        

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int type, int protocol) {
    int new_fd = createFileDescriptor(pid);
    struct PidFd pidfd = PidFd(pid, new_fd);
    struct Sock sock = Sock();
    sock_list.insert(std::make_pair(pidfd, sock));
    returnSystemCall(syscallUUID, new_fd);
    return;
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd) {
    removeFileDescriptor(pid, fd);
    
    struct PidFd pidfd = PidFd(pid, fd);
 
    bind_remove_sock(pidfd);
    sock_remove_sock(pidfd);

    returnSystemCall(syscallUUID, 0);
    return;
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t addrlen) {
    struct PidFd pidfd = PidFd(pid, fd);
    if (!sock_find_sock(pidfd)) {
        returnSystemCall(syscallUUID, -1);
        return;
    }

    if (bind_find_sock(pidfd)) {
        returnSystemCall(syscallUUID, -1);
        return;
    }

    // iterate through map and check if bind rules are violated
    for (auto iter = bind_list.begin();iter != bind_list.end();iter++) {
        if (is_addr_same(*addr, *(struct sockaddr *)&iter->second.src_addr)) {
            returnSystemCall(syscallUUID, -1);
            return;
        }
    }
    struct Sock sock = sock_get_sock(pidfd);
    sock.src_addr = *(struct sockaddr_in *)addr;

    bind_list.insert(std::make_pair(pidfd, sock));
    returnSystemCall(syscallUUID, 0);
    return;
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t*addrlen) {
    struct PidFd pidfd = PidFd(pid, fd);

    if (!bind_find_sock(pidfd)) {
        returnSystemCall(syscallUUID, -1);
        return;
    }

    struct Sock sock = bind_get_sock(pidfd);

    memcpy(addr, (struct sockaddr *)&sock.src_addr, sizeof(sockaddr));
    returnSystemCall(syscallUUID, 0);
    return;
}

/*
    // all created sockets
    std::map<struct PidFd, struct Sock> sock_list;
    // all bound sockets
    std::map<struct PidFd, struct Sock> bind_list;
    // unestablished connection(client pidfd - client sock)
    std::map<struct PidFd, struct Sock> unest_list_1;
    // unestablished connection(server pidfd - client socks)
    std::map<struct PidFd, std::set<std::pair<struct PidFd, struct Sock>>> unest_list_2;
    // established connection(server pidfd - client sock)
    std::map<struct PidFd, std::pair<struct PidFd, struct Sock>> estab_list;
    // map server pidfd  and client side established connections
    std::map<struct PidFd, std::set<std::pair<struct PidFd, struct Sock>>> listen_q;
    // map pidfd and UUID for unblocking
    std::map<struct PidFd, UUID> block_list;
 
*/

    /*
        14: Ethernet Header
        20: IP Header
        20: TCP Header
    */

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t addrlen) {
    /* TODO
        1v. check sock_list, return -1 if not exists
        2v. check socket status is not closed, return -1
        3 . [?]: could it be listen state?
        4 . handle packet
    */
    struct PidFd pidfd = PidFd(pid, fd);
    struct sockaddr_in *addr_in = (sockaddr_in *)addr;


    if (!sock_find_sock(pidfd)) {
        returnSystemCall(syscallUUID, -1);
        return;
    }

    if (sock_get_sock(pidfd).state.compare("CLOSED") != 0) {
        returnSystemCall(syscallUUID, -1);
        return;
    }

    Packet *p = allocatePacket(60);

    uint32_t dst_ip = addr_in->sin_addr.s_addr;
    uint16_t dst_port = addr_in->sin_port;

    uint32_t src_ip;
    uint16_t src_port;
 
    getHost()->getIPAddr(((uint8_t *)(&src_ip)), getHost()->getRoutingTable((uint8_t *)&dst_ip));

    if (bind_find_sock(pidfd)) {
        src_port = bind_get_sock(pidfd).src_addr.sin_port;
    } else {
        srand((unsigned int)time(NULL));
        int rand_port = rand() % 64512;
        used_port[rand_port] = 1;
        src_port = rand_port + 1024;
        src_port = htons(src_port); 
    }
 
    p->writeData(14 + 12, &src_ip, 4);
    p->writeData(14 + 16, &dst_ip, 4);
    p->writeData(14 + 20 + 0, &src_port, 2);
    p->writeData(14 + 20 + 2, &dst_port, 2);

    uint32_t seq = htonl(rand());
    p->writeData(14 + 20 + 4, &seq, 4);
    seq_list.insert(make_pair(pidfd, ntohl(seq)));

    uint32_t zero4 = 0;
    p->writeData(14 + 20 + 8, &zero4, 4);

    uint8_t offset = 5;
    p->writeData(14 + 20 + 12, &offset, 1);

    p->writeData(14 + 20 + 13, &syn, 1);

    uint16_t window = 50000;
    window = htons(window);
    p->writeData(14 + 20 + 14, &window, 2);

    p->writeData(14 + 20 + 16, &zero4, 4);

    uint8_t *tcp_header = (uint8_t *)malloc(20);
    p->readData(34, tcp_header, 20);

    uint16_t checksum = ~(NetworkUtil::tcp_sum(src_ip, dst_ip, tcp_header, 20));
    checksum = htons(checksum);
    p->writeData(14 + 20 + 16, &checksum, 2);

    struct Sock sock = sock_get_sock(pidfd);
    sock.dst_addr = *addr_in;
    sock.state = "SYN_SENT";

    cli_list.insert(make_pair(pidfd, sock)); // Do I have to create new same socket? or just use it?, if I juse use it should change bind to use sock_list's sock
    uuid_list.insert(make_pair(pidfd, syscallUUID));
    this->sendPacket("IPv4", p);
    return;
    
    
    /*
    1. implicit binding (get local address from its local routing information)
    2. Store remote address
    3. Send SYN
    4. Receive SYN+ACK then send ACK
    
    Returns 0 if connection/binding is successful, -1 if not.

    Socket determined by: Source IP Source Port Destination IP Destination Port Suggestions:

    Make a function to map income packets to opened TCP sockets (use 4 field above)

    Send SYN on connect

    Implement it as a state machine (ST_CLOSED, ST_SYN_SENT, ST_ESTABLISHED, ...)

    If already bound, use that address.

    Else, automatically bind the socket with random port and local address(implicit bind)

    Get local address from its local routing information

    If there are multiple interfaces, source IP addresses are dependent on the destination
    */
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd, int backlog) {
    /* TODO
        1v. check sock_list, return -1 if not exists
        2v. check socket status, return -1 if not closed
        3v. check bind_list, return -1 if not exists
        4v. change socket state to Listen
        5 . handle backlog
    */

    struct PidFd pidfd = PidFd(pid, fd);

    if (!sock_find_sock(pidfd)) {
        returnSystemCall(syscallUUID, -1);
        return;
    }
    
    struct Sock sock = sock_get_sock(pidfd);

    if (sock.state.compare("CLOSED") != 0) {
        returnSystemCall(syscallUUID, -1);
        return;
    }
    
    if (!bind_find_sock(pidfd)) {
        returnSystemCall(syscallUUID, -1);
        return;
    }

    sock.state = "LISTEN";
    struct Sock sock2 = bind_get_sock(pidfd);
    sock2.state = "LISTEN";

    returnSystemCall(syscallUUID, 0);
    return;
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t *addrlen) {
    /* TODO
    */
    struct PidFd pidfd = PidFd(pid, fd);
    struct sockaddr_in *addr_in = (sockaddr_in *)addr;

    if (!find_listen_q(pidfd)) {
        returnSystemCall(syscallUUID, -1);
    }

    auto lq = get_listen_q(pidfd);
    if (lq.empty()) { // block accept()
        uuid_list.insert(std::make_pair(pidfd, syscallUUID));
    } else { // consume one connnection
        int new_fd = createFileDescriptor(pid);
        
        struct PidFd new_pidfd = PidFd(pid, new_fd);
        
        struct Sock svr_sock = sock_get_sock(pidfd);
        struct Sock new_sock = Sock(svr_sock.src_addr);
        
        sock_list.insert(make_pair(new_pidfd, new_sock));
        estab_list.insert(make_pair(new_pidfd, new_sock));

        struct Sock cli_sock = lq.front();
        lq.pop();
        memcpy(addr_in, &cli_sock, sizeof(struct sockaddr_in));
        *addrlen = sizeof(sockaddr_in);
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

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
    //Simple L3 forwarding
    //extract address
    uint8_t src_ip[4];
    uint8_t dest_ip[4]; packet->readData(14+12, src_ip, 4); packet->readData(14+16, dest_ip, 4);
    Packet* myPacket = this->clonePacket(packet); //prepare to send
    //swap src and dest
    myPacket->writeData(14+12, dest_ip, 4); myPacket->writeData(14+16, src_ip, 4);
    //IP module will fill rest of IP header, //send it to correct network interface this->sendPacket("IPv4", myPacket);
    //given packet is my responsibility
    this->freePacket(packet);
}

void TCPAssignment::timerCallback(void* payload)
{

}


}
