/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>


#include <E/E_TimerModule.hpp>

using namespace std;

struct PidFd {
    int pid;
    int fd;
    PidFd(){}
    PidFd(int pid, int fd) {
        this->pid = pid;
        this->fd = fd;
    }
    bool operator<(const PidFd& pidfd) const{
        return ((this->pid != pidfd.pid) || (this->fd != pidfd.fd));
    }
    bool operator==(const PidFd& pidfd) const{
        return ((this->pid == pidfd.pid) && (this->fd == pidfd.fd));
    } 
};

struct Sock {
    struct sockaddr_in src_addr;
    struct sockaddr_in dst_addr;
    string state = "CLOSED";
    Sock(){}
    Sock(struct sockaddr_in src_addr) {
        this->src_addr = src_addr;
    }
    Sock(struct sockaddr_in src_addr, struct sockaddr_in dst_addr) {
        this->src_addr = src_addr;
        this->dst_addr = dst_addr;
    }
};

namespace E
{

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:

private:
	virtual void timerCallback(void* payload) final;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
    // all created sockets
    std::map<struct PidFd, struct Sock> sock_list;
    // all bound sockets
    std::map<struct PidFd, struct Sock> bind_list;
    // unestablished connection(client pidfd - client sock)
    std::map<struct PidFd, struct Sock> cli_list;
    // unestablished connection(server pidfd - client socks)
    std::map<struct PidFd, std::set<struct Sock>> svr_list;
    // established connection(each pidfd - sock for server and client)
    std::map<struct PidFd, struct Sock> estab_list;
    // map server pidfd  and client side established connections
    std::map<struct PidFd, std::queue<struct Sock>> listen_q;
    // map pidfd and UUID for unblocking
    std::map<struct PidFd, UUID> uuid_list;
    // map pidfd and seq number for handshaking
    std::map<struct PidFd, int> seq_list;
    // all closed sockets
    // std::map<struct PidFd, struct Sock> close_list; // all closed sockets(connections)

    int used_port[64512] = {0};
    uint8_t fin = 0b00000001;
    uint8_t syn = 0b00000010;
    uint8_t ack = 0b00010000;

	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;

    virtual bool is_addr_same(struct sockaddr addr_1, struct sockaddr addr_2);
    virtual bool sock_find_sock(struct PidFd pidfd);
    virtual bool bind_find_sock(struct PidFd pidfd);
    virtual struct Sock sock_get_sock(struct PidFd pidfd);
    virtual struct Sock bind_get_sock(struct PidFd pidfd);
    virtual void sock_remove_sock(struct PidFd pidfd);
    virtual void bind_remove_sock(struct PidFd pidfd);
    virtual bool find_listen_q(struct PidFd pidfd);
    virtual std::queue<struct Sock> get_listen_q(struct PidFd pidfd);
    
    virtual void syscall_socket(UUID syscallUUID, int pid, int type, int protocol);
    virtual void syscall_close(UUID syscallUUID, int pid, int fd);
    virtual void syscall_bind(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t addrlen);
    virtual void syscall_getsockname(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t *addrlen);
    virtual void syscall_connect(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t addrlen);
    virtual void syscall_listen(UUID syscallUUID, int pid, int fd, int backlog);
    virtual void syscall_accept(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t *addrlen);
    virtual void syscall_getpeername(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t *addrlen);
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
