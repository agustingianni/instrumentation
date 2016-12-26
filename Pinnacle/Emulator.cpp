/*
 * File: Emulator.cpp
 * Author: Agustin Gianni (agustingianni@gmail.com)
 *
 * Created on March 20, 2011, 4:36 PM
 */

#include <string>
#include <fstream>
#include <iomanip>
#include <cassert>
#include <iostream>
#include <memory>

#include "pin.H"

#include "Pinnacle.h"
#include "Emulator.h"
#include "Utilities.h"
#include "TaintManager.h"

extern Pinnacle *pinnacle;

using namespace std;
using namespace Utilities;

namespace Emulator {

void lea(THREADID tid, ADDRINT ip, REG wreg, REG base, REG index, UINT32 scale, UINT32 displacement) {
	std::shared_ptr<TaintInformation> ti;
	if (base) {
		ti = pinnacle->taint_manager->getTaintInformation(tid, base);
		if (ti) {
			auto t = std::make_shared<TaintInformation>(ip, ti);
			pinnacle->taint_manager->taint(tid, ip, wreg, t);
		}
	}

	if (index) {
		ti = pinnacle->taint_manager->getTaintInformation(tid, index);
		if (ti) {
			auto t = std::make_shared<TaintInformation>(ip, ti);
			pinnacle->taint_manager->taint(tid, ip, wreg, t);
		}
	}

	if (!ti) {
		pinnacle->taint_manager->untaint(tid, wreg);
	}
}

void leave(THREADID tid, ADDRINT ip, REG rRBP, REG wRSP, REG wRBP, ADDRINT addr, INT32 size) {
	auto ti = pinnacle->taint_manager->getTaintInformation(tid, rRBP);
	// RSP = RBP
	if (ti) {
		auto t = std::make_shared<TaintInformation>(ip, ti);
		pinnacle->taint_manager->taint(tid, ip, wRSP, t);
	}

	// RBP = [RSP]
	ti = pinnacle->taint_manager->getTaintInformation(addr, size);
	if (ti) {
		auto t = std::make_shared<TaintInformation>(ip, ti);
		pinnacle->taint_manager->taint(tid, ip, wRBP, t);
	}
}

void enter(THREADID tid, ADDRINT ip, ADDRINT addr, INT32 size, REG rRBP, REG wRBP, REG rRSP) {
	auto ti = pinnacle->taint_manager->getTaintInformation(tid, rRBP);
	if (ti) {
		// If RBP is tainted then taint [RSP;RSP+SIZE]
		auto t = std::make_shared<TaintInformation>(ip, ti);
		pinnacle->taint_manager->taint(tid, ip, addr, size, t);
	}

	ti = pinnacle->taint_manager->getTaintInformation(tid, rRSP);
	if (ti) {
		// If RSP was tainted, taint RBP
		auto t = std::make_shared<TaintInformation>(ip, ti);
		pinnacle->taint_manager->taint(tid, ip, wRBP, t);
	}
}

void generic_mm(THREADID tid, ADDRINT ip, ADDRINT waddr, INT32 wsize, ADDRINT raddr, INT32 rsize, BOOL checkSource) {
	// emulate [wmem] = [wmem] op [rmem]
	if (checkSource && pinnacle->taint_manager->tainted(tid, waddr, wsize))
		return;

	auto ti = pinnacle->taint_manager->getTaintInformation(raddr, rsize);
	if (ti) {
		auto t = std::make_shared<TaintInformation>(ip, ti);
		pinnacle->taint_manager->taint(tid, ip, waddr, wsize, t);
	} else {
		pinnacle->taint_manager->untaint(tid, waddr, wsize);
	}
}

void generic_mr(THREADID tid, ADDRINT ip, ADDRINT addr, INT32 size, REG reg, BOOL checkSource) {
	// emulate [mem] = [mem] op reg
	if (checkSource && pinnacle->taint_manager->tainted(tid, addr, size))
		return;

	auto ti = pinnacle->taint_manager->getTaintInformation(tid, reg);
	if (ti) {
		auto t = std::make_shared<TaintInformation>(ip, ti);
		pinnacle->taint_manager->taint(tid, ip, addr, size, t);
	} else {
		pinnacle->taint_manager->untaint(tid, addr, size);
	}
}

void generic_rm(THREADID tid, ADDRINT ip, ADDRINT addr, INT32 size, REG reg, BOOL checkSource) {
	// emulate reg = reg op [mem]
	if (checkSource && pinnacle->taint_manager->tainted(tid, reg))
		return;

	auto ti = pinnacle->taint_manager->getTaintInformation(addr, size);
	if (ti) {
		auto t = std::make_shared<TaintInformation>(ip, ti);
		pinnacle->taint_manager->taint(tid, ip, reg, t);
	} else {
		pinnacle->taint_manager->untaint(tid, reg);
	}
}

void generic_rr(THREADID tid, ADDRINT ip, REG rreg, REG wreg, BOOL checkSource) {
	// emulate wreg = wreg op rreg
	if (checkSource && pinnacle->taint_manager->tainted(tid, wreg))
		return;

	// emulate wreg = rreg
	auto ti = pinnacle->taint_manager->getTaintInformation(tid, rreg);
	if (ti) {
		auto t = std::make_shared<TaintInformation>(ip, ti);
		pinnacle->taint_manager->taint(tid, ip, wreg, t);
	} else {
		pinnacle->taint_manager->untaint(tid, wreg);
	}
}

void generic_ri(THREADID tid, ADDRINT ip, REG reg, UINT32 imm, BOOL checkSource) {
	bool tainted = pinnacle->taint_manager->tainted(tid, reg);

	// this emulates something like reg = reg op imm
	if (checkSource && tainted)
		return;

	// this emulates something like reg = imm
	if (tainted)
		pinnacle->taint_manager->untaint(tid, reg);
}

//
// Emulate a generica data transfer with an address as the destination
// and an immediate value as the source.
// It is important to note that there are operations that use the destination
// to operate with the immediate value and therefore we need to take into
// acount the taint status of the destination address.
//
// @ip: address of the instruction
// @addr: desination address
// @size: size of write
// @imm: immediate value used
// @checkSouce: if true then we take into acount the taint status of the destination address.
//
void generic_mi(THREADID tid, ADDRINT ip, ADDRINT addr, INT32 size, UINT32 imm, BOOL checkSource) {
	bool tainted = pinnacle->taint_manager->tainted(tid, addr, size);

	// this emulates something like [addr] = [addr] op imm
	if (checkSource && tainted)
		return;

	// this emulates something like [addr] = imm
	if (tainted)
		pinnacle->taint_manager->untaint(tid, addr, size);
}

void imul_m(THREADID tid, ADDRINT ip, REG wreg1, REG wreg2, ADDRINT addr, INT32 size) {
	// NOTE: Here we loose information in the case where both are tainted
	auto ti = pinnacle->taint_manager->getTaintInformation(tid, wreg1);
	if (!ti)
		ti = pinnacle->taint_manager->getTaintInformation(addr, size);

	if (ti) {
		auto t = std::make_shared<TaintInformation>(ip, ti);
		pinnacle->taint_manager->taint(tid, ip, wreg1, t);
		pinnacle->taint_manager->taint(tid, ip, wreg2, t);
	} else {
		pinnacle->taint_manager->untaint(tid, wreg1);
		pinnacle->taint_manager->untaint(tid, wreg2);
	}
}

void imul_r(THREADID tid, ADDRINT ip, REG wreg1, REG wreg2, REG rreg) {
	// NOTE: Here we loose information in the case where both are tainted
	auto ti = pinnacle->taint_manager->getTaintInformation(tid, rreg);
	if (!ti)
		ti = pinnacle->taint_manager->getTaintInformation(tid, wreg1);

	if (ti) {
		auto t = std::make_shared<TaintInformation>(ip, ti);
		pinnacle->taint_manager->taint(tid, ip, wreg1, t);
		pinnacle->taint_manager->taint(tid, ip, wreg2, t);
	} else {
		pinnacle->taint_manager->untaint(tid, wreg1);
		pinnacle->taint_manager->untaint(tid, wreg2);
	}
}

void imul_rr(THREADID tid, ADDRINT ip, REG wreg, REG rreg1, REG rreg2) {
	// NOTE: Here we loose information in the case where both are tainted
	auto ti = pinnacle->taint_manager->getTaintInformation(tid, rreg1);
	if (!ti)
		ti = pinnacle->taint_manager->getTaintInformation(tid, rreg2);

	if (ti) {
		auto t = std::make_shared<TaintInformation>(ip, ti);
		pinnacle->taint_manager->taint(tid, ip, wreg, t);
	} else {
		pinnacle->taint_manager->untaint(tid, wreg);
	}
}

void imul_rm(THREADID tid, ADDRINT ip, REG wreg, REG rreg, ADDRINT addr, INT32 size) {
	// NOTE: Here we loose information in the case where both are tainted
	auto ti = pinnacle->taint_manager->getTaintInformation(tid, rreg);
	if (!ti)
		ti = pinnacle->taint_manager->getTaintInformation(addr, size);

	if (ti) {
		auto t = std::make_shared<TaintInformation>(ip, ti);
		pinnacle->taint_manager->taint(tid, ip, wreg, t);
	} else {
		pinnacle->taint_manager->untaint(tid, wreg);
	}
}

void imul_rmi(THREADID tid, ADDRINT ip, REG wreg, ADDRINT addr, INT32 size, UINT32 imm) {
	// NOTE: Here we loose precision.
	// if any of the bytes of the interval [addr;addr+size] is tainted then taint wreg
	auto ti = pinnacle->taint_manager->getTaintInformation(addr, size);
	if (ti) {
		auto t = std::make_shared<TaintInformation>(ip, ti);
		pinnacle->taint_manager->taint(tid, ip, wreg, t);
	} else {
		pinnacle->taint_manager->untaint(tid, wreg);
	}
}

void imul_rri(THREADID tid, ADDRINT ip, REG wreg, REG rreg, UINT32 imm) {
	std::shared_ptr<TaintInformation> ti;
	ti = pinnacle->taint_manager->getTaintInformation(tid, rreg);
	if (ti) {
		auto t = std::make_shared<TaintInformation>(ip, ti);
		pinnacle->taint_manager->taint(tid, ip, wreg, t);
	} else {
		pinnacle->taint_manager->untaint(tid, wreg);
	}
}

void xor_reg_self(THREADID tid, ADDRINT ip, REG reg) {
	if (pinnacle->taint_manager->tainted(tid, reg))
		pinnacle->taint_manager->untaint(tid, reg);
}

void pusha(THREADID tid, ADDRINT ip, ADDRINT addr, INT32 size) {
	REG array[] = { REG_AX, REG_CX, REG_DX, REG_BX, REG_SP, REG_BP, REG_SI, REG_DI, REG_INVALID_ };
	UINT32 curr_byte = 0;

	for (REG *cur_reg = array; *cur_reg != REG_INVALID_; ++cur_reg) {
		if (auto ti = pinnacle->taint_manager->getTaintInformation(tid, *cur_reg)) {
			pinnacle->taint_manager->taint(tid, ip, addr + curr_byte, 2, ti);
		}

		curr_byte += 2;
	}
}

void push_flags(THREADID tid, ADDRINT ip, ADDRINT addr, INT32 size) {
	pinnacle->taint_manager->untaint(tid, addr, size);
}

void pushad(THREADID tid, ADDRINT ip, ADDRINT addr, INT32 size) {
	REG array[] = { REG_EAX, REG_ECX, REG_EDX, REG_EBX, REG_ESP, REG_EBP, REG_ESI, REG_EDI, REG_INVALID_ };
	UINT32 curr_byte = 0;

	for (REG *cur_reg = array; *cur_reg != REG_INVALID_; ++cur_reg) {
		if (auto ti = pinnacle->taint_manager->getTaintInformation(tid, *cur_reg)) {
			pinnacle->taint_manager->taint(tid, ip, addr + curr_byte, 4, ti);
		}

		curr_byte += 4;
	}
}

void popa(THREADID tid, ADDRINT ip, ADDRINT addr, INT32 size) {
	REG array[] = { REG_DI, REG_SI, REG_BP, REG_SP, REG_BX, REG_DX, REG_CX, REG_AX, REG_INVALID_ };
	UINT32 curr_byte = 0;

	for (REG *cur_reg = array; *cur_reg != REG_INVALID_; ++cur_reg) {
		if (*cur_reg == REG_SP) {
			curr_byte += 2;
			continue;
		}

		if (auto ti = pinnacle->taint_manager->getTaintInformation(addr + curr_byte, 2)) {
			pinnacle->taint_manager->taint(tid, ip, *cur_reg, ti);
		}

		curr_byte += 2;
	}
}

void popad(THREADID tid, ADDRINT ip, ADDRINT addr, INT32 size) {
	REG array[] = { REG_EDI, REG_ESI, REG_EBP, REG_ESP, REG_EBX, REG_EDX, REG_ECX, REG_EAX, REG_INVALID_ };
	UINT32 curr_byte = 0;

	for (REG *cur_reg = array; *cur_reg != REG_INVALID_; ++cur_reg) {
		if (*cur_reg == REG_ESP) {
			curr_byte += 4;
			continue;
		}

		if (auto ti = pinnacle->taint_manager->getTaintInformation(addr + curr_byte, 4)) {
			pinnacle->taint_manager->taint(tid, ip, *cur_reg, ti);
		}

		curr_byte += 4;
	}
}

}
