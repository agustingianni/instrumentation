/*
 * TaintOriginHandlersWindows.h
 *
 *  Created on: Dec 11, 2014
 *      Author: anon
 */

#ifndef TAINTORIGINHANDLERSWINDOWS_H_
#define TAINTORIGINHANDLERSWINDOWS_H_

#include "pin.H"
#include "PinWindows.h"

#define HANDLER(x) AFUNPTR(TaintOriginHandlers::x##_entry), AFUNPTR(TaintOriginHandlers::x##_exit)

namespace TaintOriginHandlers {
void recv_entry(THREADID tid, WIN::SOCKET s, char *buf, int len, int flags);
void recv_exit(THREADID tid, int ret_val);

void recvfrom_entry(THREADID tid, WIN::SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen);
void recvfrom_exit(THREADID tid, int ret_val);

void ReadFile_entry(THREADID tid, WIN::HANDLE hFile, WIN::LPVOID lpBuffer, WIN::DWORD nNumberOfBytesToRead, WIN::LPDWORD lpNumberOfBytesRead, WIN::LPOVERLAPPED lpOverlapped);
void ReadFile_exit(THREADID tid, BOOL ret_val);

struct SyscallData_t {
	ADDRINT pc;
	ADDRINT sysno;

	union {
		struct recv_t {
			WIN::SOCKET s;
			char *buf;
			int len;
			int flags;
		} func_recv;

		struct recvfrom_t {
			WIN::SOCKET s;
			char *buf;
			int len;
			int flags;
			struct sockaddr *from;
			int *fromlen;
		} func_recvfrom;

		struct ReadFile_t {
			WIN::HANDLE hFile;
			WIN::LPVOID lpBuffer;
			WIN::DWORD nNumberOfBytesToRead;
			WIN::LPDWORD lpNumberOfBytesRead;
			WIN::LPOVERLAPPED lpOverlapped;
		} func_ReadFile;
	} u;
};

}

#endif /* TAINTORIGINHANDLERSWINDOWS_H_ */
