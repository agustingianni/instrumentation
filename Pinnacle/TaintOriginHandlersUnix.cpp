/*
 * TaintOriginHandlersUnix.cpp
 *
 *  Created on: Dec 11, 2014
 *      Author: anon
 */

#include <unistd.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <memory>

#include "dbg.h"
#include "Pinnacle.h"
#include "TaintManager.h"
#include "WhiteListManager.h"
#include "DescriptorManager.h"
#include "TaintOriginHandlers.h"

extern Pinnacle *pinnacle;

#define NDEBUG 1

namespace TaintOriginHandlers {

void accept_entry(THREADID tid, int fd, struct sockaddr *address, socklen_t *address_len) {
	DEBUG("fd=%d", fd);
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	tls_data->u.accept.socket = fd;
	tls_data->u.accept.address = address;
	tls_data->u.accept.address_len = address_len;
}

void accept_exit(THREADID tid, int ret_val) {
	DEBUG("ret_val=%d", ret_val);
	if (ret_val < 0)
		return;

	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	if (auto ds = pinnacle->descriptor_manager->createDescriptorState(ret_val)) {
		ds->origin = Utilities::GetIpString(tls_data->u.accept.address);
	}
}

void bind_entry(THREADID tid, int fd, struct sockaddr *address, socklen_t address_len) {
	DEBUG("fd=%d", fd);
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	tls_data->u.bind.socket = fd;
	tls_data->u.bind.address = address;
	tls_data->u.bind.address_len = address_len;
}

void bind_exit(THREADID tid, int ret_val) {
	DEBUG("ret_val=%d", ret_val);
	if (ret_val < 0)
		return;

	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	if (auto ds = pinnacle->descriptor_manager->getDescriptorState(tls_data->u.bind.socket)) {
		ds->origin = Utilities::GetIpString(tls_data->u.bind.address);
	}
}

void close_entry(THREADID tid, int fd) {
	DEBUG("fd=%d", fd);
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	tls_data->u.close.fd = fd;
}

void close_exit(THREADID tid, int ret_val) {
	DEBUG("ret_val=%d", ret_val);
	if (ret_val < 0)
		return;

	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	pinnacle->descriptor_manager->removeDescriporState(tls_data->u.close.fd);
}

void connect_entry(THREADID tid, int fd, struct sockaddr *address, socklen_t address_len) {
	DEBUG("fd=%d", fd);
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	tls_data->u.connect.socket = fd;
	tls_data->u.connect.address = address;
	tls_data->u.connect.address_len = address_len;
}

void connect_exit(THREADID tid, int ret_val) {
	DEBUG("ret_val=%d", ret_val);
	if (ret_val < 0)
		return;

	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	if (auto ds = pinnacle->descriptor_manager->getDescriptorState(tls_data->u.connect.socket)) {
		ds->origin = string(Utilities::GetIpString(tls_data->u.connect.address));
	}
}

void dup_entry(THREADID tid, int fildes) {
	DEBUG("fildes=%d", fildes);
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	tls_data->u.dup.fildes = fildes;
}

void dup_exit(THREADID tid, int ret_val) {
	DEBUG("ret_val=%d", ret_val);
	if (ret_val < 0)
		return;

	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	if (auto ds = pinnacle->descriptor_manager->getDescriptorState(tls_data->u.dup.fildes)) {
		pinnacle->descriptor_manager->dupDescriptorState(ret_val, ds);
	}
}

void dup2_entry(THREADID tid, int fildes, int fildes2) {
	DEBUG("fildes=%d fildes2=%d", fildes, fildes2);
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	tls_data->u.dup2.fildes = fildes;
	tls_data->u.dup2.fildes2 = fildes2;
}

void dup2_exit(THREADID tid, int ret_val) {
	DEBUG("ret_val=%d", ret_val);
	if (ret_val < 0)
		return;

	// If 'fildes2' exists it will be closed.
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	pinnacle->descriptor_manager->removeDescriporState(tls_data->u.dup2.fildes2);

	// Duplicate the original descriptor.
	if (auto ds = pinnacle->descriptor_manager->getDescriptorState(tls_data->u.dup.fildes)) {
		pinnacle->descriptor_manager->dupDescriptorState(tls_data->u.dup2.fildes2, ds);
	}
}

void dup3_entry(THREADID tid, int oldfd, int newfd, int flags) {
	DEBUG("oldfd=%d newfd=%d", oldfd, newfd);
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	tls_data->u.dup3.oldfd = oldfd;
	tls_data->u.dup3.newfd = newfd;
	tls_data->u.dup3.flags = flags;
}

void dup3_exit(THREADID tid, int ret_val) {
	DEBUG("ret_val=%d", ret_val);
	if (ret_val < 0)
		return;

	// If 'fildes2' exists it will be closed.
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	pinnacle->descriptor_manager->removeDescriporState(tls_data->u.dup3.newfd);

	// Duplicate the original descriptor.
	if (auto ds = pinnacle->descriptor_manager->getDescriptorState(tls_data->u.dup3.oldfd)) {
		pinnacle->descriptor_manager->dupDescriptorState(tls_data->u.dup3.newfd, ds);
	}
}

void mmap_entry(THREADID tid, void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
	DEBUG("addr=%p len=%zu prot=%d flags=%d fd=%d", addr, len, prot, flags, fd);
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	tls_data->u.mmap.addr = addr;
	tls_data->u.mmap.len = len;
	tls_data->u.mmap.prot = prot;
	tls_data->u.mmap.flags = flags;
	tls_data->u.mmap.fd = fd;
	tls_data->u.mmap.offset = offset;
}

void mmap_exit(THREADID tid, void *ret_val) {
	DEBUG("ret_val=%p", ret_val);
	if (ret_val == MAP_FAILED)
		return;

	// Check if the file to be mmaped is one that we track and mark is as tainted.
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	if (pinnacle->descriptor_manager->checkDescriptor(tls_data->u.mmap.fd)) {
		auto ti = std::make_shared<ReadTaintInformation>(tls_data->pc, tls_data->u.mmap.fd, tls_data->u.mmap.offset);
		pinnacle->taint_manager->taint(tid, tls_data->pc, (ADDRINT) ret_val, tls_data->u.mmap.len, ti);

		LOG_INFO("mmap tainted %p-%p at IP %p", (void * ) ret_val, (void* ) ((ADDRINT ) ret_val + tls_data->u.mmap.len),
			(void * ) tls_data->pc);

	} else {
		// Remove the taint status if the descriptor was not tainted
		pinnacle->taint_manager->untaint(tid, (ADDRINT) ret_val, tls_data->u.mmap.len);
	}
}

void munmap_entry(THREADID tid, void *addr, size_t len) {
	DEBUG("addr=%p len=%zu", addr, len);
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	tls_data->u.munmap.addr = addr;
	tls_data->u.munmap.len = len;
}

void munmap_exit(THREADID tid, int ret_val) {
	DEBUG("ret_val=%d", ret_val);
	if (ret_val < 0)
		return;

	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	pinnacle->taint_manager->untaint(tid, (ADDRINT) tls_data->u.munmap.addr, tls_data->u.munmap.len);
}

void open_entry(THREADID tid, char *path, int oflag) {
	DEBUG("path=%s", path);

	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	tls_data->u.open.path = path;
	tls_data->u.open.oflag = oflag;
}

void open_exit(THREADID tid, int ret_val) {
	DEBUG("ret_val=%d", ret_val);
	if (ret_val < 0)
		return;

	// If the file is whitelisted create a descriptor state.
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	if (pinnacle->whitelist_manager->check(tls_data->u.open.path)) {
		auto ds = pinnacle->descriptor_manager->createDescriptorState(ret_val);
		ds->origin = string(tls_data->u.open.path);
	}
}

void openat_entry(THREADID tid, int fd, char *path, int oflag) {
	DEBUG("fd=%d path=%s", fd, path);
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	tls_data->u.openat.fd = fd;
	tls_data->u.openat.path = path;
	tls_data->u.openat.oflag = oflag;
}

void openat_exit(THREADID tid, int ret_val) {
	DEBUG("ret_val=%d", ret_val);
	if (ret_val < 0)
		return;

	// If the file is whitelisted create a descriptor state.
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	if (pinnacle->whitelist_manager->check(tls_data->u.openat.path)) {
		auto ds = pinnacle->descriptor_manager->createDescriptorState(ret_val);
		ds->origin = string(tls_data->u.openat.path);
	}
}

void pread_entry(THREADID tid, int d, void *buf, size_t nbyte, off_t offset) {
	DEBUG("d=%d buf=%p nbyte=%zu", d, buf, nbyte);
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	tls_data->u.pread.d = d;
	tls_data->u.pread.buf = buf;
	tls_data->u.pread.nbyte = nbyte;
	tls_data->u.pread.offset = offset;
}

void pread_exit(THREADID tid, ssize_t ret_val) {
	DEBUG("ret_val=%zd", ret_val);
	if (ret_val < 0)
		return;

	// Here we do not advance the offset.
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	if (auto ds = pinnacle->descriptor_manager->getDescriptorState(tls_data->u.pread.d)) {
		auto ti = std::make_shared<ReadTaintInformation>(tls_data->pc, tls_data->u.pread.d, ds->r_off);
		pinnacle->taint_manager->taint(tid, tls_data->pc, (ADDRINT) tls_data->u.pread.buf, ret_val, ti);

		LOG_INFO("pread tainted %p-%p at IP %p", tls_data->u.pread.buf,
			(void* ) ((ADDRINT ) tls_data->u.pread.buf + ret_val), (void * ) tls_data->pc);

	} else {
		// Remove the taint status if the descriptor was not tainted
		pinnacle->taint_manager->untaint(tid, (ADDRINT) tls_data->u.pread.buf, ret_val);
	}
}

void read_entry(THREADID tid, int fildes, void *buf, size_t nbyte) {
	DEBUG("fildes=%d buf=%p nbyte=%zu", fildes, buf, nbyte);
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	tls_data->u.read.fildes = fildes;
	tls_data->u.read.buf = buf;
	tls_data->u.read.nbyte = nbyte;
}

void read_exit(THREADID tid, ssize_t ret_val) {
	DEBUG("ret_val=%zd", ret_val);
	if (ret_val < 0)
		return;

	// Advance the descriptor state 'ret' bytes
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	if (auto ds = pinnacle->descriptor_manager->getDescriptorState(tls_data->u.read.fildes)) {
		auto ti = std::make_shared<ReadTaintInformation>(tls_data->pc, tls_data->u.read.fildes, ds->r_off);
		pinnacle->taint_manager->taint(tid, tls_data->pc, (ADDRINT) tls_data->u.read.buf, ret_val, ti);
		ds->r_off += ret_val;

		LOG_INFO("read tainted %p-%p at IP %p", tls_data->u.read.buf,
			(void* ) ((ADDRINT ) tls_data->u.read.buf + ret_val), (void * ) tls_data->pc);

	} else {
		// Remove the taint status if the descriptor was not tainted
		pinnacle->taint_manager->untaint(tid, (ADDRINT) tls_data->u.read.buf, ret_val);
	}
}

void readv_entry(THREADID tid, int d, struct iovec *iov, int iovcnt) {
	DEBUG("d=%d iov=%p iovcnt=%d", d, iov, iovcnt);
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	tls_data->u.readv.d = d;
	tls_data->u.readv.iov = iov;
	tls_data->u.readv.iovcnt = iovcnt;
}

void readv_exit(THREADID tid, ssize_t ret_val) {
	DEBUG("ret_val=%zd", ret_val);
	if (ret_val < 0)
		return;

	// Advance the descriptor state 'ret' bytes
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	if (auto ds = pinnacle->descriptor_manager->getDescriptorState(tls_data->u.readv.d)) {
		auto ti = std::make_shared<ReadTaintInformation>(tls_data->pc, tls_data->u.readv.d, ds->r_off);
		for (auto i = 0; i < tls_data->u.readv.iovcnt; i++) {
			pinnacle->taint_manager->taint(tid, tls_data->pc, (ADDRINT) tls_data->u.readv.iov[i].iov_base, ret_val, ti);

			LOG_INFO("readv tainted %p-%p at IP %p", tls_data->u.pread.buf,
				(void* ) ((ADDRINT ) tls_data->u.readv.iov[i].iov_base + ret_val), (void * ) tls_data->pc);
		}

		ds->r_off += ret_val;
	} else {
		// Remove the taint status if the descriptor was not tainted
		for (auto i = 0; i < tls_data->u.readv.iovcnt; i++) {
			pinnacle->taint_manager->untaint(tid, (ADDRINT) tls_data->u.readv.iov[i].iov_base, ret_val);
		}
	}
}

void recvfrom_entry(THREADID tid, int fd, void *buffer, size_t length, int flags, struct sockaddr *addr,
	socklen_t *addr_len) {
	DEBUG("fd=%d buffer=%p length=%zu flags=%d", fd, buffer, length, flags);
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	tls_data->u.recvfrom.socket = fd;
	tls_data->u.recvfrom.buffer = buffer;
	tls_data->u.recvfrom.length = length;
	tls_data->u.recvfrom.flags = flags;
	tls_data->u.recvfrom.addr = addr;
}

void recvfrom_exit(THREADID tid, ssize_t ret_val) {
	DEBUG("ret_val=%zd", ret_val);
	if (ret_val < 0)
		return;

	// Advance the descriptor state 'ret' bytes
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	if (auto ds = pinnacle->descriptor_manager->getDescriptorState(tls_data->u.recvfrom.socket)) {
		auto ti = std::make_shared<ReadTaintInformation>(tls_data->pc, tls_data->u.recvfrom.socket, ds->r_off);
		pinnacle->taint_manager->taint(tid, tls_data->pc, (ADDRINT) tls_data->u.recvfrom.buffer, ret_val, ti);
		ds->r_off += ret_val;

		LOG_INFO("recvfrom tainted %p-%p at IP %p", tls_data->u.pread.buf,
			(void* ) ((ADDRINT ) tls_data->u.recvfrom.buffer + ret_val), (void * ) tls_data->pc);

	} else {
		// Remove the taint status if the descriptor was not tainted
		pinnacle->taint_manager->untaint(tid, (ADDRINT) tls_data->u.recvfrom.buffer, ret_val);
	}
}

void recvmsg_entry(THREADID tid, int fd, void *buffer, size_t length, int flags) {
	DEBUG("fd=%d buffer=%p length=%zu flags=%d", fd, buffer, length, flags);
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	tls_data->u.recvmsg.socket = fd;
	tls_data->u.recvmsg.buffer = buffer;
	tls_data->u.recvmsg.length = length;
	tls_data->u.recvmsg.flags = flags;
}

void recvmsg_exit(THREADID tid, ssize_t ret_val) {
	DEBUG("ret_val=%zd", ret_val);
	if (ret_val < 0)
		return;

	// Advance the descriptor state 'ret' bytes
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	if (auto ds = pinnacle->descriptor_manager->getDescriptorState(tls_data->u.recvmsg.socket)) {
		auto ti = std::make_shared<ReadTaintInformation>(tls_data->pc, tls_data->u.recvmsg.socket, ds->r_off);
		pinnacle->taint_manager->taint(tid, tls_data->pc, (ADDRINT) tls_data->u.recvmsg.buffer, ret_val, ti);
		ds->r_off += ret_val;

		LOG_INFO("recvfrom tainted %p-%p at IP %p", tls_data->u.pread.buf,
			(void* ) ((ADDRINT ) tls_data->u.recvmsg.buffer + ret_val), (void * ) tls_data->pc);

	} else {
		// Remove the taint status if the descriptor was not tainted
		pinnacle->taint_manager->untaint(tid, (ADDRINT) tls_data->u.recvmsg.buffer, ret_val);
	}
}

void socket_entry(THREADID tid, int domain, int type, int protocol) {
	DEBUG("domain=%d type=%d protocol=%d", domain, type, protocol);
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	tls_data->u.socket.domain = domain;
	tls_data->u.socket.type = type;
	tls_data->u.socket.protocol = protocol;
}

void socket_exit(THREADID tid, int ret_val) {
	DEBUG("ret_val=%d", ret_val);
	if (ret_val < 0)
		return;

	pinnacle->descriptor_manager->createDescriptorState(ret_val);
}

void socketcall_entry(THREADID tid, int call, unsigned long *args) {
	DEBUG("call=%d args=%p", call, args);
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	tls_data->u.socketcall.call = call;
	tls_data->u.socketcall.args = args;
}

void socketcall_exit(THREADID tid, int ret_val) {
	DEBUG("ret_val=%d", ret_val);
	if (ret_val < 0)
		return;
}

}
