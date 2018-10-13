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
    uint32_t seq;
    Sock(){
        this->src_addr.sin_family = AF_INET;
        this->dst_addr.sin_family = AF_INET;
    }
    Sock(struct sockaddr_in src_addr) {
        this->src_addr = src_addr;
        this->src_addr.sin_family = AF_INET;
        this->dst_addr.sin_family = AF_INET;
        //this->dst_addr.sin_port = 0;
        //this->dst_addr.sin_addr.s_addr = 0;
    }
    Sock(struct sockaddr_in src_addr, struct sockaddr_in dst_addr) {
        this->src_addr = src_addr;
        this->dst_addr = dst_addr;
        this->src_addr.sin_family = AF_INET;
        this->dst_addr.sin_family = AF_INET;
    }
    Sock(struct sockaddr_in src_addr, struct sockaddr_in dst_addr, string state) {
        this->src_addr = src_addr;
        this->dst_addr = dst_addr;
        this->state = state;
        this->src_addr.sin_family = AF_INET;
        this->dst_addr.sin_family = AF_INET;
    }
    bool operator<(const Sock& sock) const{
        return !((this->src_addr.sin_addr.s_addr == sock.src_addr.sin_addr.s_addr ||
                this->src_addr.sin_addr.s_addr == 0||
                sock.src_addr.sin_addr.s_addr == 0) &&
                (this->src_addr.sin_port == sock.src_addr.sin_port) &&
                (this->dst_addr.sin_addr.s_addr == sock.dst_addr.sin_addr.s_addr ||
                this->dst_addr.sin_addr.s_addr == 0 ||
                sock.dst_addr.sin_addr.s_addr == 0) &&
                (this->dst_addr.sin_port == sock.dst_addr.sin_port));
    }       
    bool operator==(const Sock& sock) const{
        return ((this->src_addr.sin_addr.s_addr == sock.src_addr.sin_addr.s_addr ||
                this->src_addr.sin_addr.s_addr == 0||
                sock.src_addr.sin_addr.s_addr == 0) &&
                (this->src_addr.sin_port == sock.src_addr.sin_port) &&
                (this->dst_addr.sin_addr.s_addr == sock.dst_addr.sin_addr.s_addr ||
                this->dst_addr.sin_addr.s_addr == 0 ||
                sock.dst_addr.sin_addr.s_addr == 0) &&
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
    map<struct PidFd, struct Sock> sock_list; // created socket list
    map<struct PidFd, struct Sock> bind_list; // bound socket list
    map<struct PidFd, struct Sock> cli_list; // client unestablished connection having sent SYN
    map<struct Sock, struct PidFd> reversed_cli_list; // reversed cli_list
    map<struct PidFd, set<struct Sock>> svr_list; // server unestablished connection having received SYN sent SYNACK
    //map<struct Sock, struct PidFd> reversed_svr_list; // reversed svr_list
    map<struct PidFd, struct Sock> estab_list; // established connection, if server, having received ACK, if client, having received SYNACK and sent ACK
    map<struct Sock, struct PidFd> reversed_estab_list; // reversed estab_list
    map<struct PidFd, pair<int, set<struct Sock>>> listenq; // map server pidfd and pair of (backlog and set of unestablished socket)
    map<struct PidFd, deque<struct Sock>> completeq; // map server pidfd and set of established socket
    map<struct PidFd, UUID> uuid_list; // map client pidfd and uuid for connect function call
    map<struct PidFd, uint32_t> seq_list; // map pidfd and seq number sent by packet
    map<struct PidFd, set<pair<UUID, pair<struct sockaddr *, socklen_t *>>>> accept_info_list; // map server pidfd and set of (UUID, (*, *)) for accept function call
    // all closed sockets
    map<struct PidFd, UUID> close_list; // all closed sockets(connections)

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
    virtual bool find_reversed_estab(struct Sock sock);
    virtual bool find_listenq(struct PidFd pidfd);
    virtual bool find_completeq(struct PidFd pidfd);
    virtual bool find_uuid(struct PidFd pidfd);
    virtual bool find_close(struct PidFd pidfd);
    virtual bool find_seq(struct PidFd pidfd);
    virtual bool find_accept_info(struct PidFd pidfd);

    virtual struct Sock *get_sock(struct PidFd pidfd);
    virtual struct Sock *get_bind(struct PidFd pidfd);
    virtual struct Sock *get_cli(struct PidFd pidfd);
    virtual struct PidFd *get_reversed_cli(struct Sock sock);
    virtual set<struct Sock> *get_svr(struct PidFd pifd);
    virtual struct Sock *get_estab(struct PidFd pidfd);
    virtual struct PidFd *get_reversed_estab(struct Sock sock);
    virtual pair<int, set<struct Sock>> *get_listenq(struct PidFd pidfd);
    virtual deque<struct Sock> *get_completeq(struct PidFd pidfd);
    virtual uint32_t get_seq(struct PidFd pidfd);
    virtual UUID get_uuid(struct PidFd pidfd);
    virtual UUID get_close(struct PidFd pidfd);
    virtual set<pair<UUID, pair<struct sockaddr *, socklen_t *>>> *get_accept_info(struct PidFd pidfd);
 
    virtual void remove_sock(struct PidFd pidfd);
    virtual void remove_bind(struct PidFd pidfd);
    virtual void remove_cli(struct PidFd pidfd);
    virtual void remove_reversed_cli(struct Sock sock);
    virtual void remove_svr(struct PidFd pidfd);
    virtual void remove_estab(struct PidFd pidfd);
    virtual void remove_uuid(struct PidFd pidfd);
    virtual void remove_close(struct PidFd pidfd);
    virtual void remove_seq(struct PidFd pidfd);
    virtual void remove_listenq(struct PidFd pidfd);
    virtual void remove_completeq(struct PidFd pidfd);
    virtual void remove_reversed_estab(struct Sock sock);
    virtual void remove_accept_info(struct PidFd pidfd);
    
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
