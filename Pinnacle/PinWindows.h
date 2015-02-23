#ifndef PINWINDOWS_H_
#define PINWINDOWS_H_

#define WIN32_LEAN_AND_MEAN

namespace WIN {
#include <Windows.h>
#include <WinNT.h>
#include <Winternl.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <string.h>
#include <tchar.h>
#include <Psapi.h>
#include <Strsafe.h>
#define STATUS_SUCCESS 0
}

#endif
