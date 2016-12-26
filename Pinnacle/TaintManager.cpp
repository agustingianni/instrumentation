/*
 * File: TaintManager.cpp
 * Author: Agustin Gianni (agustingianni@gmail.com)
 *
 * Created on March 20, 2011, 4:36 PM
 */

#include <map>
#include <set>
#include <vector>
#include <string>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <cassert>
#include <iostream>
#include <memory>

// Disable debugging information.
#define NDEBUG 1

#include "dbg.h"
#include "pin.H"
#include "Pinnacle.h"
#include "Utilities.h"
#include "Registers.h"
#include "ArchDefines.h"
#include "TaintManager.h"
#include "TaintInformation.h"

extern Pinnacle *pinnacle;

using namespace std;
using namespace Utilities;

void TaintManager::taint(THREADID tid, ADDRINT ip, ADDRINT address, size_t size,
	std::shared_ptr<TaintInformation> ti) {
	DEBUG("address=%p size=%.8zx ip=%p", (void * ) address, size, (void * ) ip);

	ADDRINT last = address + size;
	ADDRINT page_id = -1;
	ADDRINT page_offset;

	lock.get(1);

	has_tainted_data = true;

	while (address < last) {
		page_offset = PAGE_OFFSET(address);
		page_id = PAGE_ID(address);

		// Using operator[] forces the insertion, don't change it.
		db.bitmap[page_id][page_offset] = 1;
		db.mem_map[page_id].insert(make_pair(page_offset, ti));
		address++;
	}

	lock.release();

	// TODO: Evaluate if this is the correct place to place this log.
	pinnacle->onTaintEvent(ip);
}

void TaintManager::taint(THREADID tid, ADDRINT ip, REG reg, std::shared_ptr<TaintInformation> ti) {
	DEBUG("reg=%s ip=%p", REG_StringShort(reg).c_str(), (void * ) ip);

	lock.get(2);

	has_tainted_data = true;

	auto regmap = getRegisterMap(tid);
	regmap->insert(make_pair(reg, ti));

	auto sub_registers = Registers::getSubRegisters(reg);
	while (*sub_registers != REG_INVALID_) {
		regmap->insert(make_pair(*sub_registers, ti));
		sub_registers++;
	}

	lock.release();

	// TODO: Evaluate if this is the correct place to place this log.
	pinnacle->onTaintEvent(ip);
}

void TaintManager::untaint(THREADID tid, ADDRINT address, size_t size) {
	DEBUG("address=%p size=%.8zx", (void * ) address, size);

	assert(active() && "Called untaint without an active taint manager");

	ADDRINT last = address + size;
	ADDRINT page_id = -1;
	ADDRINT page_offset;

	TaintBitField::iterator bitmap_page_it;
	MemMap::iterator memmap_page_it;

	lock.get(3);

	while (address < last) {
		// The page_id changes with some iterations.
		if (page_id != PAGE_ID(address)) {
			page_id = PAGE_ID(address);

			// If the page has no entry then no address should be untainted.
			bitmap_page_it = db.bitmap.find(page_id);
			if (bitmap_page_it == db.bitmap.end()) {
				address = PAGE_NEXT(address);
				continue;
			}

			// If the page has no entry then no address should be untainted.
			memmap_page_it = db.mem_map.find(page_id);
			if (memmap_page_it == db.mem_map.end()) {
				address = PAGE_NEXT(address);
				continue;
			}
		}

		// The page offset changes with every address.
		page_offset = PAGE_OFFSET(address);

		bitmap_page_it->second[page_offset] = 0;
		memmap_page_it->second.erase(page_offset);

		address++;
	}

	lock.release();
}

void TaintManager::untaint(THREADID tid, REG reg) {
	DEBUG("reg=%s", REG_StringShort(reg).c_str());

	assert(active() && "Called untaint without an active taint manager");

	lock.get(4);

	// Even though the main register is not tainted, the subregister might.
	auto regmap = getRegisterMap(tid);
	regmap->erase(reg);

	// Untaint the subregisters.
	auto sub_registers = Registers::getSubRegisters(reg);
	while (*sub_registers != REG_INVALID_) {
		regmap->erase(*sub_registers);
		sub_registers++;
	}

	lock.release();
}

bool TaintManager::tainted(THREADID tid, ADDRINT address, size_t size) {
	assert(active() && "Called tainted without an active taint manager");

	TaintBitField::iterator it;
	ADDRINT prev_id = -1;
	bool ret = false;
	size_t i = 0;

	lock.get(5);

	while (i < size) {
		// Avoid looking for the same iterator if the id does not change.
		if (prev_id != PAGE_ID(address + i)) {
			prev_id = PAGE_ID(address + i);
			it = db.bitmap.find(prev_id);

			// If we did not find the id, we still need to look for the rest
			if (it == db.bitmap.end()) {
				i++;
				continue;
			}
		} else if (it == db.bitmap.end()) {
			i++;
			continue;
		}

		if (it->second[PAGE_OFFSET(address + i)]) {
			ret = true;
			break;
		}

		i++;
	}

	lock.release();
	return ret;
}

bool TaintManager::tainted(THREADID tid, REG reg) {
	assert(active() && "Called tainted without an active taint manager");

	bool ret = false;

	lock.get(6);

	// TODO: we need to do this better.
	auto regmap = getRegisterMap(tid);
	auto it = regmap->find(reg);
	if (it != regmap->end())
		ret = (it->second) != 0;

	lock.release();
	return ret;
}

std::shared_ptr<TaintInformation> TaintManager::getTaintInformation(ADDRINT address) {
	std::shared_ptr<TaintInformation> ret;

	lock.get(7);

	auto it = db.mem_map.find(PAGE_ID(address));
	if (it != db.mem_map.end()) {
		auto it2 = it->second.find(PAGE_OFFSET(address));
		if (it2 != it->second.end())
			ret = it2->second;
	}

	lock.release();
	return ret;
}

std::shared_ptr<TaintInformation> TaintManager::getTaintInformation(ADDRINT address, size_t size) {
	TaintBitField::iterator it;
	ADDRINT prev_id = -1;
	std::shared_ptr<TaintInformation> ret;
	size_t i = 0;

	lock.get(8);

	while (i < size) {
		// Avoid looking for the same iterator if the id does not change.
		if (prev_id != PAGE_ID(address + i)) {
			prev_id = PAGE_ID(address + i);
			it = db.bitmap.find(prev_id);

			// If we did not find the id, we still need to look for the rest
			if (it == db.bitmap.end()) {
				i++;
				continue;
			}
		} else if (it == db.bitmap.end()) {
			i++;
			continue;
		}

		if (it->second[PAGE_OFFSET(address + i)]) {
			MemMap::iterator x = db.mem_map.find(PAGE_ID(address + i));
			if (x != db.mem_map.end()) {
				auto y = x->second.find(PAGE_OFFSET(address + i));
				if (y != x->second.end())
					ret = y->second;
			}

			break;
		}

		i++;
	}

	lock.release();
	return ret;
}

std::shared_ptr<TaintInformation> TaintManager::getTaintInformation(THREADID tid, REG reg) {
	std::shared_ptr<TaintInformation> ret;

	lock.get(9);
	auto regmap = getRegisterMap(tid);
	auto it = regmap->find(reg);

	if (it != regmap->end())
		ret = it->second;

	lock.release();
	return ret;
}
