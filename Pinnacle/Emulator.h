/*
 * File: Emulator.h
 * Author: Agustin Gianni (agustingianni@gmail.com)
 *
 * Created on March 20, 2011, 4:36 PM
 */

#ifndef EMULATOR_H
#define EMULATOR_H

#include "pin.H"

namespace Emulator {
void generic_mr(THREADID tid, ADDRINT ip, ADDRINT addr, INT32 size, REG reg, BOOL checkSource);
void generic_rm(THREADID tid, ADDRINT ip, ADDRINT addr, INT32 size, REG reg, BOOL checkSource);
void generic_mi(THREADID tid, ADDRINT ip, ADDRINT addr, INT32 size, UINT32 imm, BOOL checkSource);
void generic_mm(THREADID tid, ADDRINT ip, ADDRINT waddr, INT32 wsize, ADDRINT raddr, INT32 rsize, BOOL checkSource);
void generic_rr(THREADID tid, ADDRINT ip, REG rreg, REG wreg, BOOL checkSource);
void generic_ri(THREADID tid, ADDRINT ip, REG reg, UINT32 imm, BOOL checkSource);
void enter(THREADID tid, ADDRINT ip, ADDRINT addr, INT32 size, REG rRBP, REG wRBP, REG rRSP);
void leave(THREADID tid, ADDRINT ip, REG rRBP, REG wRSP, REG wRBP, ADDRINT addr, INT32 size);
void lea(THREADID tid, ADDRINT ip, REG wreg, REG base, REG index, UINT32 scale, UINT32 displacement);
void imul_m(THREADID tid, ADDRINT ip, REG wreg1, REG wreg2, ADDRINT addr, INT32 size);
void imul_r(THREADID tid, ADDRINT ip, REG wreg1, REG wreg2, REG rreg);
void imul_rr(THREADID tid, ADDRINT ip, REG wreg, REG rreg1, REG rreg2);
void imul_rm(THREADID tid, ADDRINT ip, REG wreg, REG rreg, ADDRINT addr, INT32 size);
void imul_rmi(THREADID tid, ADDRINT ip, REG wreg, ADDRINT addr, INT32 size, UINT32 imm);
void imul_rri(THREADID tid, ADDRINT ip, REG wreg, REG rreg, UINT32 imm);
void syscall_before(THREADID tid, ADDRINT ip, CONTEXT *ctxt);
void syscall_after(THREADID tid, ADDRINT ip, CONTEXT *ctxt);
void xor_reg_self(THREADID tid, ADDRINT ip, REG reg);
void pusha(THREADID tid, ADDRINT ip, ADDRINT addr, INT32 size);
void pushad(THREADID tid, ADDRINT ip, ADDRINT addr, INT32 size);
void push_flags(THREADID tid, ADDRINT ip, ADDRINT addr, INT32 size);
void popa(THREADID tid, ADDRINT ip, ADDRINT addr, INT32 size);
void popad(THREADID tid, ADDRINT ip, ADDRINT addr, INT32 size);
}

#endif // EMULATOR_H
