/*
 * File:   Utilities.h
 * Author: Agustin Gianni (agustingianni@gmail.com)
 *
 * Created on March 19, 2011, 3:29 PM
 */

#ifndef UTILITIES_H
#define UTILITIES_H

#include <string>

#include "pin.H"

#if defined(TARGET_WINDOWS)
#include "PinWindows.h"
#endif

// We need to define this namespace in order not to collide with
// pin's definitions of some fundamental types wich are also defined by sub include
// files includes in winsock2.h and others.

#if defined(TARGET_WINDOWS)
#define ntohs WIN::ntohs
#define PATH_SEPARATOR "\\"
#else
#define PATH_SEPARATOR "/"
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

namespace Utilities {
void dumpContext(CONTEXT *ctxt);

std::string Disassemble(const void *ip);
std::string GetImageBaseName(const std::string &image_name);
void PrintInstructionDetails(const INS &ins);

UINT32 INS_RealOperandCount(const INS &ins);

#if defined(TARGET_WINDOWS)
std::string GetIpString(struct WIN::sockaddr *sa);
bool GetFileNameFromHandle(WIN::HANDLE hFile, string &fName);
#else
std::string GetIpString(struct sockaddr *sa);
#endif

class Lock {
private:
	PIN_LOCK lock_;

public:
	Lock() {
		PIN_InitLock(&lock_);
	}

	void get(int val) {
		PIN_GetLock(&lock_, val);
	}

	void release() {
		PIN_ReleaseLock(&lock_);
	}
};

}

#endif // UTILITIES_H
