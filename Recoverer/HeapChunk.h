/*
 * HeapChunk.h
 *
 *  Created on: Dec 9, 2014
 *      Author: anon
 */

#ifndef HEAPCHUNK_H_
#define HEAPCHUNK_H_

#include "pin.H"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

// Names of the allocation routines
const char *malloc_names[] = { "malloc", "_malloc", "_Znwm", "__Znwm", "_Znam", "__Znam", "_Znwj", "__Znwj", "_Znaj",
	"__Znaj", "_ZnwmRKSt9nothrow_t", "__ZnwmRKSt9nothrow_t", "_ZnamRKSt9nothrow_t", "__ZnamRKSt9nothrow_t",
	"_ZnwjRKSt9nothrow_t", "__ZnwjRKSt9nothrow_t", "_ZnajRKSt9nothrow_t", "__ZnajRKSt9nothrow_t", "operator new",
	"operator new[]", "_XprtMemAlloc@4" };

// Names of the deallocation routines
const char *free_names[] = { "free", "_free", "_ZdaPv", "__ZdaPv", "_ZdlPv", "__ZdlPv", "_ZdlPvRKSt9nothrow_t",
	"__ZdlPvRKSt9nothrow_t", "_ZdaPvRKSt9nothrow_t", "__ZdaPvRKSt9nothrow_t", "operator delete", "operator delete[]",
	"_XprtMemFree@4" };

struct TimeStampManager {
	size_t m_timestamp;
	PIN_MUTEX m_lock;

	TimeStampManager() :
		m_timestamp(1) {
		PIN_MutexInit(&m_lock);
	}

	size_t get() {
		size_t ret;
		PIN_MutexLock(&m_lock);
		ret = m_timestamp++;
		PIN_MutexUnlock(&m_lock);
		return ret;
	}
};

struct HeapChunk {
	ADDRINT m_address;
	size_t m_size;
	size_t m_timestamp;

	HeapChunk(ADDRINT address, size_t size = 0, size_t timestamp = 0) :
		m_address(address), m_size(size), m_timestamp(timestamp) {
	}

	HeapChunk() :
		m_address(0), m_size(0), m_timestamp(0) {
	}

	bool contains(ADDRINT address) const {
		return address >= m_address && address < (m_address + m_size);
	}

	bool operator<(const HeapChunk &rhs) const {
		return m_address < rhs.m_address;
	}
};

struct InterestingFunction {
	ADDRINT m_address;
	mutable set<HeapChunk> m_used_chunks;

	InterestingFunction(ADDRINT address) :
		m_address(address) {
	}

	bool operator<(const InterestingFunction &rhs) const {
		return m_address < rhs.m_address;
	}
};

// Each thread will have a set of basic block hits and a log file.
struct ThreadData {
	size_t m_alloc_size;
};

#endif /* HEAPCHUNK_H_ */
