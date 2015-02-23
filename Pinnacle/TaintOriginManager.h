/*
 * TaintOriginManager.h
 *
 *  Created on: Dec 11, 2014
 *      Author: anon
 */

#ifndef TAINTORIGINMANAGER_H_
#define TAINTORIGINMANAGER_H_

#include <string>
#include <map>
#include <vector>
#include <utility>

#include "pin.H"

struct TaintOrigin {
	TaintOrigin(const std::string &name, unsigned nargs, AFUNPTR handler_entry, AFUNPTR handler_exit) :
		m_name(name), m_nargs(nargs), m_handler_entry(handler_entry), m_handler_exit(handler_exit) {
	}

	std::string m_name;
	unsigned m_nargs;
	AFUNPTR m_handler_entry;
	AFUNPTR m_handler_exit;
};

class TaintOriginManager {
private:
	// Map indexed by image name. Each image name has a vector of origins that we need to hook.
	std::map<std::string, std::vector<TaintOrigin *>> m_images;

	// Vector that holds all the tuples (sys_no, syscall_handler).
	std::map<ADDRINT, TaintOrigin *> m_syscalls;

public:
	TaintOriginManager();

	// Add the tuple (image, function) as a taint origin.
	void add_function(const std::string &image, const std::string &function, unsigned nargs, AFUNPTR handler_entry,
		AFUNPTR handler_exit);

	// Add a syscall as a source of taint information.
	void add_syscall(const std::string &syscall, unsigned sys_no, unsigned nargs, AFUNPTR handler_entry,
		AFUNPTR handler_exit);

	// Inspects the image and hooks the taint origins if any.
	void on_library_loaded(const IMG &image);

	// Syscall handlers.
	void on_syscall_entry(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std);
	void on_syscall_exit(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std);
};

void SYSCALL_1_HANDLE(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, AFUNPTR handler);
void SYSCALL_2_HANDLE(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, AFUNPTR handler);
void SYSCALL_3_HANDLE(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, AFUNPTR handler);
void SYSCALL_4_HANDLE(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, AFUNPTR handler);
void SYSCALL_5_HANDLE(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, AFUNPTR handler);
void SYSCALL_6_HANDLE(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, AFUNPTR handler);

#endif /* TAINTORIGINMANAGER_H_ */
