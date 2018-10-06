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
    Sock(struct sockaddr_in src_addr, struct sockaddr_in dst_addr, string state) {
        this->src_addr = src_addr;
        this->dst_addr = dst_addr;
        this->state = state;
    }
    bool operator<(const Sock& sock) const{
        return !((this->src_addr.sin_addr.s_addr == sock.src_addr.sin_addr.s_addr) &&
                (this->src_addr.sin_port == sock.src_addr.sin_port) &&
                (this->dst_addr.sin_addr.s_addr == sock.dst_addr.sin_addr.s_addr) &&
                (this->dst_addr.sin_port == sock.dst_addr.sin_port));
    }       
    bool operator==(const Sock& sock) const{
        return ((this->src_addr.sin_addr.s_addr == sock.src_addr.sin_addr.s_addr) &&
                (this->src_addr.sin_port == sock.src_addr.sin_port) &&
                (this->dst_addr.sin_addr.s_addr == sock.dst_addr.sin_addr.s_addr) &&
                (this->dst_addr.sin_port == sock.dst_addr.sin_port));
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
    map<struct PidFd, struct Sock> sock_list;
    // all bound sockets
    map<struct PidFd, struct Sock> bind_list;
    // unestablished connection(client pidfd - client sock)
    map<struct PidFd, struct Sock> cli_list;
    // unestablished connection(client sock - client pidfd)
    map<struct Sock, struct PidFd> reversed_cli_list;
    // unestablished connection(server pidfd - client socks)
    map<struct PidFd, set<struct Sock>> svr_list;
    // established connection(each pidfd - sock for server and client)
    map<struct PidFd, struct Sock> estab_list;
    // established connection(each sock - pidfd for server and client)
    map<struct Sock, struct PidFd> reversed_estab_list;
    // map server pidfd and client side established connections
    map<struct PidFd, queue<struct Sock>> listenq;
    // map pidfd and UUID for unblocking(accept, connect)
    map<struct PidFd, UUID> uuid_list;
    // map pidfd and seq number for handshaking
    map<struct PidFd, uint32_t> seq_list;
    // all closed sockets
    // map<struct PidFd, struct Sock> close_list; // all closed sockets(connections)

    int used_port[65536 - 1024] = {0};
    static const uint8_t fin_flag = 0b00000001;
    static const uint8_t syn_flag = 0b00000010;
    static const uint8_t ack_flag = 0b00010000;
    static const uint8_t synack_flag = syn_flag + ack_flag;

	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(string fromModule, Packet* packet) final;

    virtual bool is_addr_same(struct sockaddr addr_1, struct sockaddr addr_2);
    virtual bool find_sock(struct PidFd pidfd);
    virtual bool find_bind(struct PidFd pidfd);
    virtual bool find_cli(struct PidFd pidfd);
    virtual bool find_reversed_cli(struct Sock sock);
    virtual bool find_svr(struct PidFd pidfd);
    virtual bool find_estab(struct PidFd pidfd);
    virtual bool find_uuid(struct PidFd pidfd);
    virtual bool find_seq(struct PidFd pidfd);
    virtual bool find_listenq(struct PidFd pidfd);

    virtual struct Sock *get_sock(struct PidFd pidfd);
    virtual struct Sock *get_bind(struct PidFd pidfd);
    virtual struct Sock *get_cli(struct PidFd pidfd);
    virtual struct PidFd *get_reversed_cli(struct Sock sock);
    virtual struct Sock *get_estab(struct PidFd pidfd);
    virtual uint32_t get_seq(struct PidFd pidfd);
    virtual UUID get_uuid(struct PidFd pidfd);
    virtual queue<struct Sock> *get_listenq(struct PidFd pidfd);

    virtual void remove_sock(struct PidFd pidfd);
    virtual void remove_bind(struct PidFd pidfd);
    virtual void remove_cli(struct PidFd pidfd);
    virtual void remove_reversed_cli(struct Sock sock);
    virtual void remove_svr(struct PidFd pidfd);
    virtual void remove_estab(struct PidFd pidfd);
    virtual void remove_uuid(struct PidFd pidfd);
    virtual void remove_seq(struct PidFd pidfd);
    virtual void remove_listenq(struct PidFd pidfd);
    
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
