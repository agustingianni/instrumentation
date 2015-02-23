/*
 * TaintOriginHandlersUnix.h
 *
 *  Created on: Dec 11, 2014
 *      Author: anon
 */

#ifndef TAINTORIGINHANDLERSUNIX_H_
#define TAINTORIGINHANDLERSUNIX_H_

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "pin.H"

#define HANDLER(x) AFUNPTR(TaintOriginHandlers::x##_entry), AFUNPTR(TaintOriginHandlers::x##_exit)

namespace TaintOriginHandlers {
void accept_entry(THREADID tid, int socket, struct sockaddr *address, socklen_t *address_len);
void accept_exit(THREADID tid, int ret_val);
void bind_entry(THREADID tid, int socket, struct sockaddr *address, socklen_t address_len);
void bind_exit(THREADID tid, int ret_val);
void close_entry(THREADID tid, int fd);
void close_exit(THREADID tid, int ret_val);
void connect_entry(THREADID tid, int socket, struct sockaddr *address, socklen_t address_len);
void connect_exit(THREADID tid, int ret_val);
void dup2_entry(THREADID tid, int fildes, int fildes2);
void dup2_exit(THREADID tid, int ret_val);
void dup3_entry(THREADID tid, int oldfd, int newfd, int flags);
void dup3_exit(THREADID tid, int ret_val);
void dup_entry(THREADID tid, int fildes);
void dup_exit(THREADID tid, int ret_val);
void mmap_entry(THREADID tid, void *addr, size_t len, int prot, int flags, int fd, off_t offset);
void mmap_exit(THREADID tid, void *ret_val);
void munmap_entry(THREADID tid, void *addr, size_t len);
void munmap_exit(THREADID tid, int ret_val);
void open_entry(THREADID tid, char *path, int oflag);
void open_exit(THREADID tid, int ret_val);
void openat_entry(THREADID tid, int fd, char *path, int oflag);
void openat_exit(THREADID tid, int ret_val);
void pread_entry(THREADID tid, int d, void *buf, size_t nbyte, off_t offset);
void pread_exit(THREADID tid, ssize_t ret_val);
void read_entry(THREADID tid, int fildes, void *buf, size_t nbyte);
void read_exit(THREADID tid, ssize_t ret_val);
void readv_entry(THREADID tid, int d, struct iovec *iov, int iovcnt);
void readv_exit(THREADID tid, ssize_t ret_val);
void recvfrom_entry(THREADID tid, int socket, void *buffer, size_t length, int flags, struct sockaddr *addr, socklen_t *addr_len);
void recvfrom_exit(THREADID tid, ssize_t ret_val);
void recvmsg_entry(THREADID tid, int socket, void *buffer, size_t length, int flags);
void recvmsg_exit(THREADID tid, ssize_t ret_val);
void socket_entry(THREADID tid, int domain, int type, int protocol);
void socket_exit(THREADID tid, int ret_val);
void socketcall_entry(THREADID tid, int call, unsigned long *args);
void socketcall_exit(THREADID tid, int ret_val);

struct SyscallData_t {
	ADDRINT pc;
	ADDRINT sysno;

	union {
		struct sys_accept {
			int socket;
			struct sockaddr *address;
			socklen_t *address_len;
		} accept;

		struct sys_bind {
			int socket;
			struct sockaddr *address;
			socklen_t address_len;
		} bind;

		struct sys_close {
			int fd;
		} close;

		struct sys_connect {
			int socket;
			struct sockaddr *address;
			socklen_t address_len;
		} connect;

		struct sys_dup {
			int fildes;
		} dup;

		struct sys_dup2 {
			int fildes;
			int fildes2;
		} dup2;

		struct sys_dup3 {
			int oldfd;
			int newfd;
			int flags;
		} dup3;

		struct sys_mmap {
			void *addr;
			size_t len;
			int prot;
			int flags;
			int fd;
			off_t offset;
		} mmap;

		struct sys_munmap {
			void *addr;
			size_t len;
		} munmap;

		struct sys_open {
			char *path;
			int oflag;
		} open;

		struct sys_openat {
			int fd;
			char *path;
			int oflag;
		} openat;

		struct sys_pread {
			int d;
			void *buf;
			size_t nbyte;
			off_t offset;
		} pread;

		struct sys_read {
			int fildes;
			void *buf;
			size_t nbyte;
		} read;

		struct sys_readv {
			int d;
			struct iovec *iov;
			int iovcnt;
		} readv;

		struct sys_recvfrom {
			int socket;
			void *buffer;
			size_t length;
			int flags;
			struct sockaddr *addr;
			socklen_t *addr_len;
		} recvfrom;

		struct sys_recvmsg {
			int socket;
			void *buffer;
			size_t length;
			int flags;
		} recvmsg;

		struct sys_socket {
			int domain;
			int type;
			int protocol;
		} socket;

		struct sys_socketcall {
			int call;
			unsigned long *args;
		} socketcall;
	} u;
};

}

#endif /* TAINTORIGINHANDLERSUNIX_H_ */
