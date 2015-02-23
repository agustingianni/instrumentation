/*
 * File: InstructionSemantics.cpp
 * Author: Agustin Gianni (agustingianni@gmail.com)
 *
 * Created on March 20, 2011, 4:36 PM
 */

#include <iostream>

#include "pin.H"
#include "Emulator.h"
#include "Utilities.h"
#include "Processor.h"

using namespace std;
using namespace Emulator;

void Processor::process_binary_bin(const INS &ins) {
	//
	// Status: complete
	//
	// ins ::= add | adc | sbb | sub
	// ins     eax/ax/al, immediate data
	// ins     reg, reg
	// ins     reg, mem
	// ins     reg, immediate data
	// ins     mem, reg
	// ins     mem, immediate data
	//
	// Example instruction:
	//   add RA, RB
	//   RA = RA + RB
	//
	// This means we need to check first if RA is tainted. If it is, then no further
	// actions should be taken. If RA is not tainted but RB is tainted, then we will taint RA

	bool isImm = INS_OperandIsImmediate(ins, 1);
	if (INS_IsMemoryWrite(ins)) {
		if (isImm) {
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_mi, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYWRITE_EA,
				IARG_MEMORYWRITE_SIZE, IARG_UINT32, (UINT32) INS_OperandImmediate(ins, 1), IARG_UINT32, true,
				IARG_END);
		} else {
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_mr, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYWRITE_EA,
				IARG_MEMORYWRITE_SIZE, IARG_UINT32, INS_RegR(ins, INS_MaxNumRRegs(ins) - 1), IARG_UINT32, true,
				IARG_END);
		}
	} else {
		if (isImm) {
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_ri, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32,
				INS_RegW(ins, 0), IARG_UINT32, (UINT32) INS_OperandImmediate(ins, 1), IARG_UINT32, true,
				IARG_END);
		} else if (INS_IsMemoryRead(ins)) {
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_rm, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYREAD_EA,
				IARG_MEMORYREAD_SIZE, IARG_UINT32, INS_RegW(ins, 0), IARG_UINT32, true,
				IARG_END);
		} else {
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_rr, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32,
				INS_RegR(ins, 1), IARG_UINT32, INS_RegW(ins, 0), IARG_UINT32, true,
				IARG_END);
		}
	}
}

void Processor::process_binary_unary(const INS &ins) {
	//
	// Status: complete
	//
	//
	// ins ::= mul | div | idiv
	// ins     reg
	// ins     mem
	if (INS_IsMemoryRead(ins)) {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) imul_m, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32,
			INS_RegW(ins, 0), IARG_UINT32, INS_RegW(ins, 1), IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
			IARG_END);
	} else {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) imul_r, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32,
			INS_RegW(ins, 0), IARG_UINT32, INS_RegW(ins, 1), IARG_UINT32, INS_RegR(ins, 0),
			IARG_END);
	}
}

void Processor::process_shift_trinary(const INS &ins) {
	//
	// Status: complete
	//
	// If the first operand was tainted, then keep it tainted.
	// if it was not tainted, and the second argument is tainted
	// mark operand 1 as tainted.
	//
	// inst ::= shld | shrd
	// inst    reg, reg, cl
	// inst    reg, reg, imm
	// inst    mem, reg, cl
	// inst    mem, reg, imm
	if (INS_IsMemoryWrite(ins)) {
		// If the third operand is a register we need to skip ip
		REG rreg;
		if (INS_OperandIsImmediate(ins, 2))
			rreg = INS_RegR(ins, INS_MaxNumRRegs(ins) - 1);
		else
			rreg = INS_RegR(ins, INS_MaxNumRRegs(ins) - 2);

		// mem, reg
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_mr, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYWRITE_EA,
			IARG_MEMORYWRITE_SIZE, IARG_UINT32, rreg, IARG_UINT32, true,
			IARG_END);
	} else {
		// reg, reg
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_rr, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32,
			INS_RegR(ins, 1), IARG_UINT32, INS_RegW(ins, 0), IARG_UINT32, true,
			IARG_END);
	}
}

void Processor::process_logical_binary(const INS &ins) {
	//
	// Status: complete
	//
	// inst = or | xor | and
	// and     reg, reg
	// and     reg, mem
	// and     reg, immediate data
	// and     rax/eax/ax/al, immediate data ?????
	// and     mem, immediate data
	// and     mem, reg

	bool isImm = INS_OperandIsImmediate(ins, 1);
	INT32 opcode = INS_Opcode(ins);

	if (INS_IsMemoryWrite(ins)) {
		if (isImm) {
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_mi, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYWRITE_EA,
				IARG_MEMORYWRITE_SIZE, IARG_UINT32, (UINT32) INS_OperandImmediate(ins, 1), IARG_UINT32, true,
				IARG_END);
		} else {
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_mr, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYWRITE_EA,
				IARG_MEMORYWRITE_SIZE, IARG_UINT32, INS_RegR(ins, INS_MaxNumRRegs(ins) - 1), IARG_UINT32, true,
				IARG_END);
		}
	} else {
		if (isImm) {
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_ri, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32,
				INS_RegW(ins, 0), IARG_UINT32, (UINT32) INS_OperandImmediate(ins, 1), IARG_UINT32, true,
				IARG_END);
		} else if (INS_IsMemoryRead(ins)) {
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_rm, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYREAD_EA,
				IARG_MEMORYREAD_SIZE, IARG_UINT32, INS_RegW(ins, 0), IARG_UINT32, true,
				IARG_END);
		} else {
			// XOR reg, reg needs special handling as it may
			// not propagate any taint information
			if (opcode == XED_ICLASS_XOR && INS_RegR(ins, 1) == INS_RegW(ins, 0)) {
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) xor_reg_self, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32,
					INS_RegR(ins, 1),
					IARG_END);
			} else {
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_rr, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32,
					INS_RegR(ins, 1), IARG_UINT32, INS_RegW(ins, 0), IARG_UINT32, true,
					IARG_END);
			}
		}
	}
}

void Processor::process_movbe(const INS &ins) {
	//
	// Status: complete
	//
	// TODO: This needs to be fixed, since it will swap the taint status.
	//
	// ins ::= movbe
	// movbe reg, mem
	// movbe mem, reg

	if (INS_OperandIsReg(ins, 1)) {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_mr, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYWRITE_EA,
			IARG_MEMORYWRITE_SIZE, IARG_UINT32, INS_RegR(ins, INS_MaxNumRRegs(ins) - 1), IARG_UINT32, false,
			IARG_END);
	} else {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_rm, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYREAD_EA,
			IARG_MEMORYREAD_SIZE, IARG_UINT32, INS_RegW(ins, INS_MaxNumWRegs(ins) - 1), IARG_UINT32, false,
			IARG_END);
	}
}

void Processor::process_mov_ext(const INS &ins) {
	//
	// Status: complete
	//
	// ins ::= movsx | movsxd | movzx
	// ins reg, reg
	// ins reg, mem
	if (INS_OperandIsReg(ins, 1)) {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_rr, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32,
			INS_RegR(ins, 0), IARG_UINT32, INS_RegW(ins, 0), IARG_UINT32, false,
			IARG_END);
	} else {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_rm, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYREAD_EA,
			IARG_MEMORYREAD_SIZE, IARG_UINT32, INS_RegW(ins, 0), IARG_UINT32, false,
			IARG_END);
	}
}

void Processor::process_cmov(const INS &ins) {
	//
	// Status: complete
	//
	// ins ::= CMOVB CMOVBE CMOVL CMOVLE CMOVNB CMOVNBE CMOVNL CMOVNLE
	//         CMOVNO CMOVNP CMOVNS CMOVNZ CMOVO CMOVP CMOVS CMOVZ
	// cmov reg, reg
	// cmov reg, mem
	//
	// This is a regular mov but it only executes if a given condition
	// is met. That is the reason why we use INS_InsertPredicatedCall
	if (INS_OperandIsReg(ins, 1)) {
		INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_rr, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32,
			INS_RegR(ins, 0), IARG_UINT32, INS_RegW(ins, 0), IARG_UINT32, false,
			IARG_END);
	} else {
		INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_rm, IARG_THREAD_ID, IARG_INST_PTR,
			IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_UINT32, INS_RegW(ins, 0), IARG_UINT32, false,
			IARG_END);
	}
}

void Processor::process_mov(const INS &ins) {
	//
	// Status: complete
	//
	// ins ::= mov
	// reg, mem
	// reg, imm
	// reg, reg
	// mem, reg
	// mem, imm
	bool isImm = INS_OperandIsImmediate(ins, 1);
	if (INS_IsMemoryWrite(ins)) {
		if (isImm) {
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_mi, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYWRITE_EA,
				IARG_MEMORYWRITE_SIZE, IARG_UINT32, (UINT32) INS_OperandImmediate(ins, 1), IARG_UINT32, false,
				IARG_END);
		} else {
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_mr, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYWRITE_EA,
				IARG_MEMORYWRITE_SIZE, IARG_UINT32, INS_RegR(ins, INS_MaxNumRRegs(ins) - 1), IARG_UINT32, false,
				IARG_END);
		}
	} else {
		if (isImm) {
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_ri, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32,
				INS_RegW(ins, 0), IARG_UINT32, (UINT32) INS_OperandImmediate(ins, 1), IARG_UINT32, false,
				IARG_END);
		} else if (INS_IsMemoryRead(ins)) {
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_rm, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYREAD_EA,
				IARG_MEMORYREAD_SIZE, IARG_UINT32, INS_RegW(ins, 0), IARG_UINT32, false,
				IARG_END);
		} else {
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_rr, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32,
				INS_RegR(ins, 0), IARG_UINT32, INS_RegW(ins, 0), IARG_UINT32, false,
				IARG_END);
		}
	}
}

void Processor::process_xchg(const INS &ins) {
	//
	// Status: complete
	//
	// TODO: This will swap the taint status
	//
	// ins ::= xchg
	// reg, reg
	// reg, mem
	// mem, reg
	if (INS_IsMemoryWrite(ins)) {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_mr, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYWRITE_EA,
			IARG_MEMORYWRITE_SIZE, IARG_UINT32, INS_RegR(ins, INS_MaxNumRRegs(ins) - 1), IARG_UINT32, false,
			IARG_END);
	} else {
		if (INS_OperandIsReg(ins, 1)) {
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_rr, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32,
				INS_RegR(ins, 1), IARG_UINT32, INS_RegW(ins, 0), IARG_UINT32, false,
				IARG_END);
		} else {
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_rm, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYREAD_EA,
				IARG_MEMORYREAD_SIZE, IARG_UINT32, INS_RegW(ins, 0), IARG_UINT32, false,
				IARG_END);
		}
	}
}

void Processor::process_call(const INS &ins) {
	//
	// Status: complete
	//
	// ins ::= call
	// call reg
	// call mem
	// call imm
	if (INS_OperandIsReg(ins, 0)) {
		INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_rr, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32,
			INS_RegR(ins, 0), IARG_UINT32, INS_RegW(ins, 0), IARG_UINT32, false,
			IARG_END);
	} else if (INS_OperandIsMemory(ins, 0)) {
		INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_rm, IARG_THREAD_ID, IARG_INST_PTR,
			IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_UINT32, INS_RegW(ins, 0), IARG_UINT32, false,
			IARG_END);
	}
}

void Processor::process_push(const INS &ins) {
	//
	// Status: complete
	//
	// ins ::= push
	// push reg
	// push imm
	// push mem

	if (INS_OperandIsReg(ins, 0)) {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_mr, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYWRITE_EA,
			IARG_MEMORYWRITE_SIZE, IARG_UINT32, INS_RegR(ins, 0), IARG_UINT32, false,
			IARG_END);
	} else if (INS_OperandIsImmediate(ins, 0)) {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_mi, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYWRITE_EA,
			IARG_MEMORYWRITE_SIZE, IARG_UINT32, (UINT32) INS_OperandImmediate(ins, 0), IARG_UINT32, false,
			IARG_END);
	} else {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_mm, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYWRITE_EA,
			IARG_MEMORYWRITE_SIZE, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_UINT32, false,
			IARG_END);
	}
}

/*!
 * Pushes the contents of the AX, CX, DX, BX, SP (original value), BP, SI, and DI general-
 * purpose registers onto the stack in that order.
 *
 * @param ins
 */
void Processor::process_pusha(const INS &ins) {
	Utilities::PrintInstructionDetails(ins);

	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) pusha, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYWRITE_EA,
		IARG_MEMORYWRITE_SIZE,
		IARG_END);
}

void Processor::process_pushad(const INS &ins) {
	Utilities::PrintInstructionDetails(ins);
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) pushad, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYWRITE_EA,
		IARG_MEMORYWRITE_SIZE,
		IARG_END);
}

void Processor::process_push_flags(const INS &ins) {
	Utilities::PrintInstructionDetails(ins);
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) push_flags, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYWRITE_EA,
		IARG_MEMORYWRITE_SIZE,
		IARG_END);
}

void Processor::process_pop(const INS &ins) {
	if (INS_OperandIsReg(ins, 0)) {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_rm, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYREAD_EA,
			IARG_MEMORYREAD_SIZE, IARG_UINT32, INS_RegW(ins, 0), IARG_UINT32, false,
			IARG_END);
	} else {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_mm, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYWRITE_EA,
			IARG_MEMORYWRITE_SIZE, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_UINT32, false,
			IARG_END);
	}
}

void Processor::process_popa(const INS &ins) {
	Utilities::PrintInstructionDetails(ins);
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) popa, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYREAD_EA,
		IARG_MEMORYREAD_SIZE,
		IARG_END);
}

void Processor::process_popad(const INS &ins) {
	Utilities::PrintInstructionDetails(ins);
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) popad, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYREAD_EA,
		IARG_MEMORYREAD_SIZE,
		IARG_END);
}

void Processor::process_jmp(const INS &ins) {
	//
	// Status: complete
	//
	// Here we also analyze the conditional jumps. So far this looks good. Maybe I should
	// change this in the future, but I see no reason to do it.
	//
	// ins ::= jmp
	// jmp reg
	// jmp mem
	// jmp imm
	//
	if (INS_OperandIsReg(ins, 0)) {
		INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_rr, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32,
			INS_RegR(ins, 0), IARG_UINT32, INS_RegW(ins, 0), IARG_UINT32, false,
			IARG_END);
	} else if (INS_OperandIsMemory(ins, 0)) {
		INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_rm, IARG_THREAD_ID, IARG_INST_PTR,
			IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_UINT32, INS_RegW(ins, 0), IARG_UINT32, false,
			IARG_END);
	}
}

void Processor::process_ret(const INS &ins) {
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_rm, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYREAD_EA,
		IARG_MEMORYREAD_SIZE, IARG_UINT32, INS_RegW(ins, 0), IARG_UINT32, false,
		IARG_END);
}

void Processor::process_convert(const INS &ins) {
	// Propagate the taint status into other registers.
	// CBW  -> If AL  is tainted AH  is tainted now.
	// CDQ  -> If EAX is tainted EDX is tainted now.
	// CDQE -> If EAX is tainted RAX is tainted now.
	// CQO  -> If RAX is tainted RDX is tainted now.
	// CWD  -> If AX  is tainted DX  is tainted now.
	// CWDE -> If AX  is tainted EAX is tainted now.
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_rr, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32,
		INS_RegR(ins, 0), IARG_UINT32, INS_RegW(ins, 0), IARG_UINT32, true,
		IARG_END);
}

void Processor::process_movs(const INS &ins) {
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_mm, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYWRITE_EA,
		IARG_MEMORYWRITE_SIZE, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_UINT32, false,
		IARG_END);
}

void Processor::process_lods(const INS &ins) {
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_rm, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYREAD_EA,
		IARG_MEMORYREAD_SIZE, IARG_UINT32, INS_RegW(ins, 0), IARG_UINT32, false,
		IARG_END);
}

void Processor::process_stos(const INS &ins) {
	//
	// Status: complete
	//
	// ins ::= STOS | STOSB | STOSW | STOSD | STOSQ
	//
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) generic_mr, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYWRITE_EA,
		IARG_MEMORYWRITE_SIZE, IARG_UINT32, INS_RegR(ins, 1), IARG_UINT32, false,
		IARG_END);
}

void Processor::process_leave(const INS &ins) {
	//
	// Status: complete
	//
	// Set RSP to RBP, then pop RBP.
	// if RBP is tainted then taint RSP
	// if [esp] is tainted taint RBP
	//
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) leave, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32, INS_RegR(ins, 0), // RBP
	IARG_UINT32, INS_RegW(ins, 1),       // RSP
	IARG_UINT32, INS_RegW(ins, 0),       // RBP
	IARG_MEMORYREAD_EA,                  // [RSP]
		IARG_MEMORYREAD_SIZE, IARG_UINT32, false,
		IARG_END);
}

void Processor::process_enter(const INS &ins) {
	//
	// Status: complete
	//
	// [esp] = RBP
	// RBP = RSP
	//
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) enter, IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYWRITE_EA,     // [RSP]
		IARG_MEMORYWRITE_SIZE, IARG_UINT32, INS_RegR(ins, 0),       // RBP
		IARG_UINT32, INS_RegW(ins, 0),       // RBP
		IARG_UINT32, INS_RegR(ins, 1),       // RSP
		IARG_UINT32, false,
		IARG_END);
}

void Processor::process_binary_imul(const INS &ins) {
	//
	// Status: complete
	//
	// TODO: imul reg is not working.
	//
	// imul    mem
	// imul    reg
	// imul    reg, reg                (3)
	// imul    reg, reg, immediate     (2)
	// imul    reg, mem, immediate     (2)
	// imul    reg, mem                (3)
	// imul    reg, immediate          (2)
	if (INS_OperandIsMemory(ins, 0)) {
		// imul MEM
		// RDX:RAX = RAX * MEM
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) imul_m, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32,
			INS_RegW(ins, 0), IARG_UINT32, INS_RegW(ins, 1), IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
			IARG_END);
	} else {
		if (INS_IsMemoryRead(ins)) {
			if (INS_OperandIsImmediate(ins, 2)) {
				// imul REG, MEM, IMM
				// REG = MEM * IMM
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) imul_rmi, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32,
					INS_RegW(ins, 0), IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_UINT32,
					(UINT32) INS_OperandImmediate(ins, 2),
					IARG_END);
			} else {
				// imul REG, MEM
				// REG = REG * MEM
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) imul_rm, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32,
					INS_RegW(ins, 0), IARG_UINT32, INS_RegR(ins, 0), IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
					IARG_END);
			}
		} else if (INS_OperandIsReg(ins, 1)) {
			if (INS_OperandIsImmediate(ins, 2)) {
				// imul RA, RB, IMM
				// RA = RB * IMM
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) imul_rri, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32,
					INS_RegW(ins, 0), IARG_UINT32, INS_RegR(ins, 0), IARG_UINT32, (UINT32) INS_OperandImmediate(ins, 2),
					IARG_END);
			} else {
				// imul RA, RB
				// RA = RA * RB
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) imul_rr, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32,
					INS_RegW(ins, 0), IARG_UINT32, INS_RegR(ins, 0), IARG_UINT32, INS_RegR(ins, 1),
					IARG_END);
			}
		} else {
			// imul REG
			// RDX:RAX = RAX * REG
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) imul_r, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32,
				INS_RegW(ins, 0), IARG_UINT32, INS_RegW(ins, 1), IARG_UINT32, INS_RegR(ins, 0),
				IARG_END);
		}
	}
}

void Processor::process_lea(const INS &ins) {
	//
	// Status: complete
	//
	// This will write to a register the address expressed by the second operand
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) lea, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32, INS_RegW(ins, 0),
		IARG_UINT32, INS_MemoryBaseReg(ins), IARG_UINT32, INS_MemoryIndexReg(ins), IARG_UINT32, INS_MemoryScale(ins),
		IARG_UINT32, INS_MemoryDisplacement(ins), IARG_UINT32, false,
		IARG_END);
}
