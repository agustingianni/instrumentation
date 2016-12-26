/*
 * TaintOriginHandlersWindows.cpp
 *
 *  Created on: Dec 11, 2014
 *      Author: anon
 */

#include <sys/types.h>
#include <memory>

#include "dbg.h"
#include "Pinnacle.h"
#include "TaintManager.h"
#include "WhitelistManager.h"
#include "DescriptorManager.h"
#include "TaintOriginHandlersWindows.h"

extern Pinnacle *pinnacle;

namespace TaintOriginHandlers {

void recv_entry(THREADID tid, WIN::SOCKET s, char *buf, int len, int flags) {
	DEBUG("s=%d buf=%p len=%d flags=%d", s, buf, len, flags);

	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	tls_data->u.func_recv.s = s;
	tls_data->u.func_recv.buf = buf;
	tls_data->u.func_recv.len = len;
	tls_data->u.func_recv.flags = flags;
}

void recv_exit(THREADID tid, int ret_val) {
	DEBUG("ret_val=%d", ret_val);

	if (ret_val < 0)
		return;

	// Advance the descriptor state 'ret' bytes
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	auto ds = pinnacle->descriptor_manager->getDescriptorState((DescriptorType) tls_data->u.func_recv.s);
	if (ds) {
		auto ti = std::make_shared<ReadTaintInformation>(tls_data->pc, (DescriptorType) tls_data->u.func_recv.s, ds->r_off);
		pinnacle->taint_manager->taint(tid, tls_data->pc, (ADDRINT) tls_data->u.func_recv.buf, ret_val, ti);
		ds->r_off += ret_val;
	}
}

void recvfrom_entry(THREADID tid, WIN::SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen) {
	DEBUG("s=%d buf=%p len=%d flags=%d", s, buf, len, flags);

	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	tls_data->u.func_recvfrom.s = s;
	tls_data->u.func_recvfrom.buf = buf;
	tls_data->u.func_recvfrom.len = len;
	tls_data->u.func_recvfrom.flags = flags;
	tls_data->u.func_recvfrom.from = from;
}

void recvfrom_exit(THREADID tid, int ret_val) {
	DEBUG("ret_val=%d", ret_val);

	if (ret_val < 0)
		return;

	// Advance the descriptor state 'ret' bytes
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	auto ds = pinnacle->descriptor_manager->getDescriptorState((DescriptorType) tls_data->u.func_recvfrom.s);
	if (ds) {
		auto ti = std::make_shared<ReadTaintInformation>(tls_data->pc, (DescriptorType) tls_data->u.func_recvfrom.s, ds->r_off);
		pinnacle->taint_manager->taint(tid, tls_data->pc, (ADDRINT) tls_data->u.func_recvfrom.buf, ret_val, ti);
		ds->r_off += ret_val;
	}
}

void ReadFile_entry(THREADID tid, WIN::HANDLE hFile, WIN::LPVOID lpBuffer, WIN::DWORD nNumberOfBytesToRead,
	WIN::LPDWORD lpNumberOfBytesRead, WIN::LPOVERLAPPED lpOverlapped) {
	DEBUG("hFile=%p lpBuffer=%p nNumberOfBytesToRead=%d", hFile, lpBuffer, nNumberOfBytesToRead);

	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	tls_data->u.func_ReadFile.hFile = hFile;
	tls_data->u.func_ReadFile.lpBuffer = lpBuffer;
	tls_data->u.func_ReadFile.nNumberOfBytesToRead = nNumberOfBytesToRead;
	tls_data->u.func_ReadFile.lpNumberOfBytesRead = lpNumberOfBytesRead;
	tls_data->u.func_ReadFile.lpOverlapped = lpOverlapped;
}

void ReadFile_exit(THREADID tid, BOOL ret_val) {
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	auto args = tls_data->u.func_ReadFile;

	string origin;
	if (!Utilities::GetFileNameFromHandle(args.hFile, origin)) {
		LOG_ERR("Could not get the filename from hFile=%p", args.hFile);
		return;
	}

	if (!pinnacle->whitelist_manager->check(origin)) {
		LOG_INFO("Source (%s) _NOT_ whitelisted", origin.c_str());
		return;
	}

	auto ds = pinnacle->descriptor_manager->getDescriptorState((DescriptorType) args.hFile);
	if (!ds) {
		LOG_INFO("Creating new DescriptorState for hFile=%p origin=%s", args.hFile, origin.c_str());
		ds = pinnacle->descriptor_manager->createDescriptorState((DescriptorType) args.hFile);
		ds->origin = origin;
	}

	WIN::DWORD numberOfBytesRead;
	if (!PIN_SafeCopy(&numberOfBytesRead, args.lpNumberOfBytesRead, sizeof(numberOfBytesRead))) {
		LOG_ERR("Failed to get the lpNumberOfBytesRead");
		return;
	}

	LOG_INFO("Tainting from %p to %p", args.lpBuffer, args.lpBuffer);

	auto ti = std::make_shared<ReadTaintInformation>(tls_data->pc, (DescriptorType) args.hFile, ds->r_off);
	pinnacle->taint_manager->taint(tid, tls_data->pc, reinterpret_cast<ADDRINT>(args.lpBuffer), numberOfBytesRead, ti);
	ds->r_off += numberOfBytesRead;
}

}
