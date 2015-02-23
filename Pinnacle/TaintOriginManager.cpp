/*
 * TaintOriginManager.cpp
 *
 *  Created on: Dec 11, 2014
 *      Author: anon
 */

#include <string>
#include <cassert>
#include <utility>
#include <iostream>

#include "Pinnacle.h"
#include "Utilities.h"
#include "TaintManager.h"
#include "TaintOriginManager.h"

extern Pinnacle *pinnacle;

using namespace std;

TaintOriginManager::TaintOriginManager() {

}

void TaintOriginManager::add_function(const string &img_name, const string &fn_name, unsigned nargs,
	AFUNPTR handler_entry, AFUNPTR handler_exit) {
	printf("LOG: Adding syscall taint origin at %16s@%-16s\n", img_name.c_str(), fn_name.c_str());
	m_images[img_name].push_back(new TaintOrigin(fn_name, nargs, handler_entry, handler_exit));
}

void TaintOriginManager::add_syscall(const string &sys_name, unsigned sys_no, unsigned nargs, AFUNPTR handler_entry,
	AFUNPTR handler_exit) {
	printf("LOG: Adding syscall taint origin at %-16s with number 0x%.8x\n", sys_name.c_str(), sys_no);
	m_syscalls[sys_no] = new TaintOrigin(sys_name, nargs, handler_entry, handler_exit);
}

// Handle syscall's entry. This routine dispatches the syscall to its handler.
void TaintOriginManager::on_syscall_entry(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std) {
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	tls_data->pc = PIN_GetContextReg(ctxt, REG_INST_PTR);
	tls_data->sysno = PIN_GetSyscallNumber(ctxt, std);

	auto it = m_syscalls.find(tls_data->sysno);
	if (it != m_syscalls.end()) {
		switch (it->second->m_nargs) {
		case 1:
			SYSCALL_1_HANDLE(tid, ctxt, std, it->second->m_handler_entry);
			break;
		case 2:
			SYSCALL_2_HANDLE(tid, ctxt, std, it->second->m_handler_entry);
			break;
		case 3:
			SYSCALL_3_HANDLE(tid, ctxt, std, it->second->m_handler_entry);
			break;
		case 4:
			SYSCALL_4_HANDLE(tid, ctxt, std, it->second->m_handler_entry);
			break;
		case 5:
			SYSCALL_5_HANDLE(tid, ctxt, std, it->second->m_handler_entry);
			break;
		case 6:
			SYSCALL_6_HANDLE(tid, ctxt, std, it->second->m_handler_entry);
			break;
		default:
			assert(0 && "We don't handle syscalls with more than 6 arguments");
			break;
		}
	}
}

// Handle syscall's exit. This routine dispatches the syscall to its handler.
void TaintOriginManager::on_syscall_exit(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std) {
	auto tls_data = pinnacle->taint_manager->getSyscallData(tid);
	auto it = m_syscalls.find(tls_data->sysno);
	if (it != m_syscalls.end()) {
		auto handler = (void (*)(THREADID, ADDRINT)) it->second->m_handler_exit;handler(tid, PIN_GetSyscallReturn(ctxt, std));
	}
}

void TaintOriginManager::on_library_loaded(const IMG &image) {
	// Remove the path to the function.
	string base_name = Utilities::GetImageBaseName(IMG_Name(image));

	printf("LOG: Loaded %-20s\n", base_name.c_str());

	// Check if the recently loaded image has hooks.
	auto it = m_images.find(base_name);
	if (it == m_images.end()) {
		return;
	}

	// For each function name.
	for (const auto &el : it->second) {
		RTN rtn = RTN_FindByName(image, el->m_name.c_str());
		if (RTN_Valid(rtn)) {
			RTN_Open(rtn);

			printf("LOG: Instrumenting %-20s on image %s\n", el->m_name.c_str(), it->first.c_str());

			// The handlers can have a different number of arguments.
			switch (el->m_nargs) {
			case 1:
				RTN_InsertCall(rtn,						// Hooked routine
					IPOINT_BEFORE, 						// Instrumentation point
					AFUNPTR(el->m_handler_entry), 		// Handler
					IARG_THREAD_ID, 					// TID
					IARG_RETURN_IP, 					// Instruction pointer
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 	// Argument 1
					IARG_END);

				break;
			case 2:
				RTN_InsertCall(rtn,						// Hooked routine
					IPOINT_BEFORE, 						// Instrumentation point
					AFUNPTR(el->m_handler_entry), 		// Handler
					IARG_THREAD_ID, 					// TID
					IARG_RETURN_IP, 					// Instruction pointer
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 	// Argument 1
					IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 	// Argument 2
					IARG_END);

				break;
			case 3:
				RTN_InsertCall(rtn,						// Hooked routine
					IPOINT_BEFORE, 						// Instrumentation point
					AFUNPTR(el->m_handler_entry), 		// Handler
					IARG_THREAD_ID, 					// TID
					IARG_RETURN_IP, 					// Instruction pointer
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 	// Argument 1
					IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 	// Argument 2
					IARG_FUNCARG_ENTRYPOINT_VALUE, 2, 	// Argument 3
					IARG_END);

				break;
			case 4:
				RTN_InsertCall(rtn,						// Hooked routine
					IPOINT_BEFORE, 						// Instrumentation point
					AFUNPTR(el->m_handler_entry), 		// Handler
					IARG_THREAD_ID, 					// TID
					IARG_RETURN_IP, 					// Instruction pointer
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 	// Argument 1
					IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 	// Argument 2
					IARG_FUNCARG_ENTRYPOINT_VALUE, 2, 	// Argument 3
					IARG_FUNCARG_ENTRYPOINT_VALUE, 3, 	// Argument 4
					IARG_END);

				break;
			case 5:
				RTN_InsertCall(rtn,						// Hooked routine
					IPOINT_BEFORE, 						// Instrumentation point
					AFUNPTR(el->m_handler_entry), 		// Handler
					IARG_THREAD_ID, 					// TID
					IARG_RETURN_IP, 					// Instruction pointer
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 	// Argument 1
					IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 	// Argument 2
					IARG_FUNCARG_ENTRYPOINT_VALUE, 2, 	// Argument 3
					IARG_FUNCARG_ENTRYPOINT_VALUE, 3, 	// Argument 4
					IARG_FUNCARG_ENTRYPOINT_VALUE, 4, 	// Argument 5
					IARG_END);

				break;
			case 6:
				RTN_InsertCall(rtn,						// Hooked routine
					IPOINT_BEFORE, 						// Instrumentation point
					AFUNPTR(el->m_handler_entry), 		// Handler
					IARG_THREAD_ID, 					// TID
					IARG_RETURN_IP, 					// Instruction pointer
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 	// Argument 1
					IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 	// Argument 2
					IARG_FUNCARG_ENTRYPOINT_VALUE, 2, 	// Argument 3
					IARG_FUNCARG_ENTRYPOINT_VALUE, 3, 	// Argument 4
					IARG_FUNCARG_ENTRYPOINT_VALUE, 4, 	// Argument 5
					IARG_FUNCARG_ENTRYPOINT_VALUE, 5, 	// Argument 6
					IARG_END);

				break;
			case 7:
				RTN_InsertCall(rtn,						// Hooked routine
					IPOINT_BEFORE, 						// Instrumentation point
					AFUNPTR(el->m_handler_entry), 		// Handler
					IARG_THREAD_ID, 					// TID
					IARG_RETURN_IP, 					// Instruction pointer
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 	// Argument 1
					IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 	// Argument 2
					IARG_FUNCARG_ENTRYPOINT_VALUE, 2, 	// Argument 3
					IARG_FUNCARG_ENTRYPOINT_VALUE, 3, 	// Argument 4
					IARG_FUNCARG_ENTRYPOINT_VALUE, 4, 	// Argument 5
					IARG_FUNCARG_ENTRYPOINT_VALUE, 5, 	// Argument 6
					IARG_FUNCARG_ENTRYPOINT_VALUE, 6, 	// Argument 7
					IARG_END);

				break;
			default:
				assert(false && "ERROR: Cannot handle hooks with more than 7 arguments, modify the sources!\n");
				break;
			}

			// Instrument the return of the function
			RTN_InsertCall(rtn, 				// Hooked routine
				IPOINT_AFTER, 					// Instrumentation point
				AFUNPTR(el->m_handler_exit),  	// Handler
				IARG_THREAD_ID,  				// TID
				IARG_FUNCRET_EXITPOINT_VALUE, 	// Return value
				IARG_END);

			RTN_Close(rtn);
		}
	}
}

void SYSCALL_1_HANDLE(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, AFUNPTR handler) {
	typedef void (*syshandler1_t)(THREADID, ADDRINT);
	((syshandler1_t) handler)(tid, PIN_GetSyscallArgument(ctxt, std, 0));
}

void SYSCALL_2_HANDLE(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, AFUNPTR handler) {
	typedef void (*syshandler1_t)(THREADID, ADDRINT, ADDRINT);
	((syshandler1_t) handler)(tid, PIN_GetSyscallArgument(ctxt, std, 0), PIN_GetSyscallArgument(ctxt, std, 1));
}

void SYSCALL_3_HANDLE(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, AFUNPTR handler) {
	typedef void (*syshandler1_t)(THREADID, ADDRINT, ADDRINT, ADDRINT);
	((syshandler1_t) handler)(tid, PIN_GetSyscallArgument(ctxt, std, 0), PIN_GetSyscallArgument(ctxt, std, 1),
		PIN_GetSyscallArgument(ctxt, std, 2));
}

void SYSCALL_4_HANDLE(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, AFUNPTR handler) {
	typedef void (*syshandler1_t)(THREADID, ADDRINT, ADDRINT, ADDRINT, ADDRINT);
	((syshandler1_t) handler)(tid, PIN_GetSyscallArgument(ctxt, std, 0), PIN_GetSyscallArgument(ctxt, std, 1),
		PIN_GetSyscallArgument(ctxt, std, 2), PIN_GetSyscallArgument(ctxt, std, 3));
}

void SYSCALL_5_HANDLE(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, AFUNPTR handler) {
	typedef void (*syshandler1_t)(THREADID, ADDRINT, ADDRINT, ADDRINT, ADDRINT, ADDRINT);
	((syshandler1_t) handler)(tid, PIN_GetSyscallArgument(ctxt, std, 0), PIN_GetSyscallArgument(ctxt, std, 1),
		PIN_GetSyscallArgument(ctxt, std, 2), PIN_GetSyscallArgument(ctxt, std, 3),
		PIN_GetSyscallArgument(ctxt, std, 4));
}

void SYSCALL_6_HANDLE(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, AFUNPTR handler) {
	typedef void (*syshandler1_t)(THREADID, ADDRINT, ADDRINT, ADDRINT, ADDRINT, ADDRINT, ADDRINT);
	((syshandler1_t) handler)(tid, PIN_GetSyscallArgument(ctxt, std, 0), PIN_GetSyscallArgument(ctxt, std, 1),
		PIN_GetSyscallArgument(ctxt, std, 2), PIN_GetSyscallArgument(ctxt, std, 3),
		PIN_GetSyscallArgument(ctxt, std, 4), PIN_GetSyscallArgument(ctxt, std, 5));
}
