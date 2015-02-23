/*
 * File: InstructionSemantics.h
 * Author: Agustin Gianni (agustingianni@gmail.com)
 *
 * Created on March 20, 2011, 4:36 PM
 */

#ifndef INSTRUCTIONSEMANTICS_H
#define INSTRUCTIONSEMANTICS_H

#include "pin.H"

class Processor {
public:
	// XED_CATEGORY_STRINGOP
	void process_movs(const INS &ins);
	void process_lods(const INS &ins);
	void process_stos(const INS &ins);

	// XED_CATEGORY_BINARY
	void process_binary_bin(const INS &ins);
	void process_binary_unary(const INS &ins);
	void process_binary_imul(const INS &ins);

	// XED_CATEGORY_SHIFT
	void process_shift_trinary(const INS &ins);

	// XED_CATEGORY_LOGICAL
	void process_logical_binary(const INS &ins);

	// XED_CATEGORY_DATAXFER
	void process_mov(const INS &ins);
	void process_xchg(const INS &ins);
	void process_movbe(const INS &ins);
	void process_mov_ext(const INS &ins);

	// XED_CATEGORY_MISC
	void process_lea(const INS &ins);
	void process_leave(const INS &ins);
	void process_enter(const INS &ins);

	// XED_CATEGORY_CALL
	void process_call(const INS &ins);

	// XED_CATEGORY_PUSH
	void process_push(const INS &ins);
	void process_pusha(const INS &ins);
	void process_pushad(const INS &ins);
	void process_push_flags(const INS &ins);

	// XED_CATEGORY_POP
	void process_pop(const INS &ins);
	void process_popa(const INS &ins);
	void process_popad(const INS &ins);

	// XED_CATEGORY_UNCOND_BR
	void process_jmp(const INS &ins);

	// XED_CATEGORY_CONVERT
	void process_convert(const INS &ins);

	// XED_CATEGORY_RET
	void process_ret(const INS &ins);

	// XED_CATEGORY_CMOV
	void process_cmov(const INS &ins);
};

#endif // INSTRUCTIONSEMANTICS_H
