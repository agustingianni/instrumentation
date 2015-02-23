/*
 * File:   Utilities.cpp
 * Author: Agustin Gianni (agustingianni@gmail.com)
 *
 * Created on March 19, 2011, 3:29 PM
 */

#include <stdlib.h>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>

#include "pin.H"
#include "Utilities.h"

#if defined(TARGET_WINDOWS)
#include "PinWindows.h"
#endif

extern "C" {
#include "xed-interface.h"
}

using namespace std;

#ifdef BOOST_NO_EXCEPTIONS
// We have redefine boost exceptions because we cannot use exceptions in the pintool
// because that would potentially interfere with our instrumented process.
// So in case of a boost exception we go fuck ourselves.
namespace boost {
	void throw_exception(std::exception const & e) {
		LOG("[!] An exception was thrown. This should not happen\n");
		exit(-1);
	}
}
#endif

UINT32 Utilities::INS_RealOperandCount(const INS &ins) {
	UINT32 count = INS_OperandCount(ins);
	UINT32 count_copy = count;
	for (UINT32 i = 0; i < count; ++i) {
		if (INS_OperandIsImplicit(ins, i))
			count_copy--;
	}

	return count_copy;
}

void Utilities::PrintInstructionDetails(const INS &ins) {
	printf("+ Instruction:\n");

	PIN_SetSyntaxXED();
	printf("| XED    %s\n", INS_Disassemble(ins).c_str());

	PIN_SetSyntaxIntel();
	printf("| INTEL  %s\n", INS_Disassemble(ins).c_str());

	for (UINT32 i = 0; i < INS_MaxNumRRegs(ins); i++) {
		printf("| REG RD %s\n", REG_StringShort(INS_RegR(ins, i)).c_str());
	}

	for (UINT32 i = 0; i < INS_MaxNumWRegs(ins); i++) {
		printf("| REG WR %s\n", REG_StringShort(INS_RegW(ins, i)).c_str());
	}

	if (INS_IsMemoryRead(ins)) {
		printf("| MEM RD %u\n", INS_MemoryReadSize(ins));
	}

	if (INS_IsMemoryWrite(ins)) {
		printf("| MEM WR %u\n", INS_MemoryWriteSize(ins));
	}
}

void Utilities::dumpContext(CONTEXT *ctxt) {
	printf("%s = %p %s = %p %s = %p\n", REG_StringShort(REG_INST_PTR).c_str(),
		(void *) PIN_GetContextReg(ctxt, REG_INST_PTR), REG_StringShort(REG_GAX).c_str(),
		(void *) PIN_GetContextReg(ctxt, REG_GAX), REG_StringShort(REG_GBX).c_str(),
		(void *) PIN_GetContextReg(ctxt, REG_GBX));

	printf("%s = %p %s = %p %s = %p\n", REG_StringShort(REG_GCX).c_str(), (void *) PIN_GetContextReg(ctxt, REG_GCX),
		REG_StringShort(REG_GDX).c_str(), (void *) PIN_GetContextReg(ctxt, REG_GDX), REG_StringShort(REG_GSI).c_str(),
		(void *) PIN_GetContextReg(ctxt, REG_GSI));

	printf("%s = %p %s = %p %s = %p\n", REG_StringShort(REG_GDI).c_str(), (void *) PIN_GetContextReg(ctxt, REG_GDI),
		REG_StringShort(REG_GBP).c_str(), (void *) PIN_GetContextReg(ctxt, REG_GBP),
		REG_StringShort(REG_STACK_PTR).c_str(), (void *) PIN_GetContextReg(ctxt, REG_STACK_PTR));

#ifdef TARGET_IA32E
	printf("%s = %p %s = %p %s = %p\n", REG_StringShort(REG_R8).c_str(), (void *) PIN_GetContextReg(ctxt, REG_R8),
		REG_StringShort(REG_R9).c_str(), (void *) PIN_GetContextReg(ctxt, REG_R9), REG_StringShort(REG_R10).c_str(),
		(void *) PIN_GetContextReg(ctxt, REG_R10));

	printf("%s = %p %s = %p %s = %p\n", REG_StringShort(REG_R11).c_str(), (void *) PIN_GetContextReg(ctxt, REG_R11),
		REG_StringShort(REG_R12).c_str(), (void *) PIN_GetContextReg(ctxt, REG_R12), REG_StringShort(REG_R13).c_str(),
		(void *) PIN_GetContextReg(ctxt, REG_R13));

	printf("%s = %p %s = %p\n", REG_StringShort(REG_R14).c_str(), (void *) PIN_GetContextReg(ctxt, REG_R14),
		REG_StringShort(REG_R15).c_str(), (void *) PIN_GetContextReg(ctxt, REG_R15));
#endif
}

string Utilities::GetImageBaseName(const string &path) {
	string::size_type idx = path.rfind("/");
	string name = (idx == string::npos) ? path : path.substr(idx + 1);
	return name;
}

string Utilities::Disassemble(const void *ip) {
	stringstream ss;

	ADDRINT pc = reinterpret_cast<ADDRINT>(ip);
#if defined(TARGET_IA32E)
	static const xed_state_t dstate = { XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b };
#else
	static const xed_state_t dstate = {XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b};
#endif
	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd, &dstate);

	const unsigned int max_inst_len = 15;

	xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(pc), max_inst_len);
	BOOL xed_ok = (xed_code == XED_ERROR_NONE);
	if (xed_ok) {
		ss << hex << std::setw(8) << pc << " ";
		char buf[2048];
		xed_decoded_inst_dump(&xedd, buf, 2048);
		ss << buf;
	}

	return ss.str();
}

#if defined(TARGET_WINDOWS)
string Utilities::GetIpString(struct WIN::sockaddr *sa)
{
	stringstream ss;

	char *s;

	switch (sa->sa_family)
	{
		case AF_INET:
		if (!(s = (char *) malloc(INET_ADDRSTRLEN)))
		{
			ss << "[error_alloc_failed]";
			return ss.str();
		}

		WIN::inet_ntop(AF_INET, &(((struct WIN::sockaddr_in *) sa)->sin_addr), s,
			INET_ADDRSTRLEN);

		ss << s << ":" << ntohs(((struct WIN::sockaddr_in *)sa)->sin_port);

		break;
		case AF_INET6:
		if (!(s = (char *) malloc(INET6_ADDRSTRLEN)))
		{
			ss << "[error_alloc_failed]";
			return ss.str();
		}

		WIN::inet_ntop(AF_INET6, &(((struct WIN::sockaddr_in6 *) sa)->sin6_addr), s,
			INET6_ADDRSTRLEN);

		ss << s << ":" << ntohs(((struct WIN::sockaddr_in6 *)sa)->sin6_port);

		break;
		default:
		ss << "[error_unknown_family]";
		return ss.str();
	}

	free(s);

	return ss.str();
}

bool Utilities::GetFileNameFromHandle(WIN::HANDLE hFile, string &fName)
{
	BOOL bSuccess = FALSE;
	WIN::TCHAR pszFilename[MAX_PATH+1];
	WIN::HANDLE hFileMap;

	// Get the file size.
	WIN::DWORD dwFileSizeHi = 0;
	WIN::DWORD dwFileSizeLo = WIN::GetFileSize(hFile, &dwFileSizeHi);

	if( dwFileSizeLo == 0 && dwFileSizeHi == 0 )
	{
		fName = "UnknownFile";
		return false;
	}

	// Create a file mapping object.
	hFileMap = WIN::CreateFileMapping(hFile,
		NULL,
		PAGE_READONLY,
		0,
		1,
		NULL);

	if (hFileMap)
	{
		// Create a file mapping to get the file name.
		void* pMem = WIN::MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);

		if (pMem)
		{
			if (WIN::GetMappedFileName (WIN::GetCurrentProcess(),
					pMem,
					pszFilename,
					MAX_PATH))
			{

				// Translate path with device name to drive letters.
				WIN::TCHAR szTemp[512];
				szTemp[0] = '\0';

				if (WIN::GetLogicalDriveStrings(512-1, szTemp))
				{
					WIN::TCHAR szName[MAX_PATH];
					WIN::TCHAR szDrive[3] = TEXT(" :");
					BOOL bFound = FALSE;
					WIN::TCHAR* p = szTemp;

					do
					{
						// Copy the drive letter to the template string
						*szDrive = *p;

						// Look up each device name
						if (WIN::QueryDosDevice(szDrive, szName, MAX_PATH))
						{
							size_t uNameLen = _tcslen(szName);

							if (uNameLen < MAX_PATH)
							{
								bFound = _tcsnicmp(pszFilename, szName, uNameLen) == 0
								&& *(pszFilename + uNameLen) == _T('\\');

								if (bFound)
								{
									// Reconstruct pszFilename using szTempFile
									// Replace device path with DOS path
									WIN::TCHAR szTempFile[MAX_PATH];
									WIN::StringCchPrintf(szTempFile,
										MAX_PATH,
										TEXT("%s%s"),
										szDrive,
										pszFilename+uNameLen);
									WIN::StringCchCopyN(pszFilename, MAX_PATH+1, szTempFile, _tcslen(szTempFile));
								}
							}
						}

						// Go to the next NULL character.
						while (*p++);
					}while (!bFound && *p); // end of string
				}
			}
			bSuccess = TRUE;
			WIN::UnmapViewOfFile(pMem);
		}

		CloseHandle(hFileMap);
	}

	if (bSuccess)
	{
		fName = string(pszFilename);
		return true;
	}
	else
	{
		fName = "UnknownFile";
		return false;
	}
}
#else
string Utilities::GetIpString(struct sockaddr *sa) {
	stringstream ss;

	char *s;

	switch (sa->sa_family) {
	case AF_INET:
		if (!(s = (char *) malloc(INET_ADDRSTRLEN))) {
			ss << "[error_alloc_failed]";
			return ss.str();
		}

		inet_ntop(AF_INET, &(((struct sockaddr_in *) sa)->sin_addr), s,
		INET_ADDRSTRLEN);

		ss << s << ":" << ntohs(((struct sockaddr_in * )sa)->sin_port);

		break;
	case AF_INET6:
		if (!(s = (char *) malloc(INET6_ADDRSTRLEN))) {
			ss << "[error_alloc_failed]";
			return ss.str();
		}

		inet_ntop(AF_INET6, &(((struct sockaddr_in6 *) sa)->sin6_addr), s,
		INET6_ADDRSTRLEN);

		ss << s << ":" << ntohs(((struct sockaddr_in6 * )sa)->sin6_port);

		break;
	default:
		ss << "[error_unknown_family]";
		return ss.str();
	}

	free(s);

	return ss.str();
}
#endif