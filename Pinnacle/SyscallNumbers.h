/*
 * SyscallNumbers.h
 *
 *  Created on: Dec 12, 2014
 *      Author: anon
 */

#ifndef SYSCALLNUMBERS_H_
#define SYSCALLNUMBERS_H_

#if defined(TARGET_MAC)
#include <sys/syscall.h>
#define APPLE_OFFSET 0x2000000

enum Syscall : unsigned {
	sys_accept = SYS_accept + APPLE_OFFSET,
	sys_bind = SYS_bind + APPLE_OFFSET,
	sys_close = SYS_close + APPLE_OFFSET,
	sys_connect = SYS_connect + APPLE_OFFSET,
	sys_creat = (unsigned) -1,
	sys_dup = SYS_dup + APPLE_OFFSET,
	sys_dup2 = SYS_dup2 + APPLE_OFFSET,
	sys_dup3 = (unsigned) -1,
	sys_mmap = SYS_mmap + APPLE_OFFSET,
	sys_munmap = SYS_munmap + APPLE_OFFSET,
	sys_open = SYS_open + APPLE_OFFSET,
	sys_openat = SYS_openat + APPLE_OFFSET,
	sys_pread = SYS_pread + APPLE_OFFSET,
	sys_read = SYS_read + APPLE_OFFSET,
	sys_readv = SYS_readv + APPLE_OFFSET,
	sys_recvfrom = SYS_recvfrom + APPLE_OFFSET,
	sys_recvmsg = SYS_recvmsg + APPLE_OFFSET,
	sys_socket = SYS_socket + APPLE_OFFSET,
	sys_socketcall = (unsigned) -1
};
#elif defined(TARGET_LINUX)
#include <sys/syscall.h>
enum Syscall : unsigned {
	sys_accept = SYS_accept,
	sys_bind = SYS_bind,
	sys_close = SYS_close,
	sys_connect = SYS_connect,
	sys_creat = SYS_creat,
	sys_dup = SYS_dup,
	sys_dup2 = SYS_dup2,
	sys_dup3 = SYS_dup3,
	sys_mmap = SYS_mmap,
	sys_munmap = SYS_munmap,
	sys_open = SYS_open,
	sys_openat = SYS_openat,
	sys_pread = (unsigned) -1,
	sys_read = SYS_read,
	sys_readv = SYS_readv,
	sys_recvfrom = SYS_recvfrom,
	sys_recvmsg = SYS_recvmsg,
	sys_socket = SYS_socket,
	sys_socketcall = (unsigned) -1
};
#elif defined(TARGET_WINDOWS)
enum Syscall : unsigned {
};
#endif

#endif /* SYSCALLNUMBERS_H_ */
