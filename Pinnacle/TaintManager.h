/*
 * File:   TaintManager.h
 * Author: Agustin Gianni (agustingianni@gmail.com)
 *
 * Created on March 19, 2011, 3:36 PM
 */

#ifndef TAINTMANAGER_H
#define	TAINTMANAGER_H

#include <string>
#include <bitset>
#include <memory>
#include <unordered_map>

#include "pin.H"
#include "Utilities.h"
#include "ArchDefines.h"
#include "TaintInformation.h"
#include "TaintOriginHandlers.h"

typedef std::unordered_map<ADDRINT, std::bitset<BITMAP_SIZE>> TaintBitField;
typedef std::unordered_map<ADDRINT, std::unordered_map<ADDRINT, std::shared_ptr<TaintInformation>>>MemMap;
typedef std::unordered_map<REG, std::shared_ptr<TaintInformation>> RegMap;

// The taint database is in charge of storing all the tainting information
// about each byte of memory and register.
struct TaintDB {
	TaintBitField bitmap;
	MemMap mem_map;
};

// Thread specific taint information
struct ThreadSpecificTaintMaps {
	ThreadSpecificTaintMaps() {
		reg_map = new RegMap();
	}

	~ThreadSpecificTaintMaps() {
		delete reg_map;
	}

	RegMap *reg_map;
};

class TaintManager {
private:
	Utilities::Lock lock;
	TaintDB db;
	bool has_tainted_data;

	TLS_KEY regmap_tls_key;
	TLS_KEY syscall_tls_key;

public:
	TaintManager() :
		has_tainted_data(false), regmap_tls_key(PIN_CreateThreadDataKey(0)), syscall_tls_key(PIN_CreateThreadDataKey(0)) {
	}

	inline bool active() {
		return has_tainted_data == true;
	}

	// Cleanup the memory allocated for the deleted thread.
	void destroyThreadSpecificTaintMaps(THREADID tid) {
		delete static_cast<ThreadSpecificTaintMaps *>(PIN_GetThreadData(regmap_tls_key, tid));
		delete static_cast<TaintOriginHandlers::SyscallData_t *>(PIN_GetThreadData(syscall_tls_key, tid));
	}

	// This must be called whenever a new thread is created.
	void createThreadSpecificTaintMaps(THREADID tid) {
		PIN_SetThreadData(regmap_tls_key, new ThreadSpecificTaintMaps(), tid);
		PIN_SetThreadData(syscall_tls_key, new TaintOriginHandlers::SyscallData_t(), tid);
	}

	// Return a reference to the syscall information.
	inline TaintOriginHandlers::SyscallData_t *getSyscallData(THREADID tid) const {
		return static_cast<TaintOriginHandlers::SyscallData_t *>(PIN_GetThreadData(syscall_tls_key, tid));
	}

	// Return a reference to the register map.
	inline RegMap *getRegisterMap(THREADID tid) const {
		return static_cast<ThreadSpecificTaintMaps *>(PIN_GetThreadData(regmap_tls_key, tid))->reg_map;
	}

	// Memory tainting routines
	void taint(THREADID tid, ADDRINT ip, ADDRINT address, size_t size, std::shared_ptr<TaintInformation> ti);
	void untaint(THREADID tid, ADDRINT address, size_t size);

	// Register tainting routines
	void taint(THREADID tid, ADDRINT ip, REG reg, std::shared_ptr<TaintInformation> ti);
	void untaint(THREADID tid, REG reg);

	// Query routines
	bool tainted(THREADID tid, ADDRINT address, size_t size);
	bool tainted(THREADID tid, REG reg);

	// Pull information about the stored taint information
	std::shared_ptr<TaintInformation> getTaintInformation(ADDRINT address);
	std::shared_ptr<TaintInformation> getTaintInformation(ADDRINT address, size_t size);
	std::shared_ptr<TaintInformation> getTaintInformation(THREADID tid, REG reg);
};

#endif	/* TAINTMANAGER_H */
