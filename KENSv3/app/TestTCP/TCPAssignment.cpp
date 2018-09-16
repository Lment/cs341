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
    // if same return 1 (true)
    // else return 0 (false)
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

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int type, int protocol) {
    int new_fd = createFileDescriptor(pid);
    returnSystemCall(syscallUUID, new_fd);
    return;
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd) {
    removeFileDescriptor(pid, fd);

    struct PidFd pidfd;
    pidfd.pid = pid;
    pidfd.fd = fd;

    auto iter = bind_list.find(pidfd);

    if (iter == bind_list.end()) {
        returnSystemCall(syscallUUID, -1);
        return;
    } else {
        bind_list.erase(iter);
        returnSystemCall(syscallUUID, 0);
    }

    return;
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t addrlen) {
    struct PidFd pidfd;
    pidfd.pid = pid;
    pidfd.fd = fd;
    
    auto iter = bind_list.find(pidfd);

    // check if the fd is already in the bind_list
     if (iter != bind_list.end()) {
        returnSystemCall(syscallUUID, -1);
        return;
     }

    for (auto iter = bind_list.begin();iter != bind_list.end();iter++) {
        if (is_addr_same(*addr, (struct sockaddr)iter->second)) {
            returnSystemCall(syscallUUID, -1);
            return;
        }
    }
    bind_list.insert(std::make_pair(pidfd, *addr));
    returnSystemCall(syscallUUID, 0);
    return;
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t*addrlen) {
    struct PidFd pidfd;
    pidfd.pid = pid;
    pidfd.fd = fd;

    auto iter = bind_list.find(pidfd);

    if (iter == bind_list.end()) {
        returnSystemCall(syscallUUID, -1);
        return;
    }

    memcpy(addr, &iter->second, sizeof(sockaddr));
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
	case CONNECT:
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
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
	case GETPEERNAME:
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

}

void TCPAssignment::timerCallback(void* payload)
{

}


}
