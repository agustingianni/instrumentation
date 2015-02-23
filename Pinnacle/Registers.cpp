/*
 * File: Registers.cpp
 * Author: Agustin Gianni (agustingianni@gmail.com)
 *
 * Created on March 20, 2011, 4:36 PM
 */

#include "pin.H"
#include "Registers.h"

#ifdef TARGET_IA32E
// Context registers in the Intel(R) 64 architecture
static const REG RAX_SUB_REG[] = { REG_EAX, REG_AX, REG_AH, REG_AL, REG_INVALID_ };
static const REG RBX_SUB_REG[] = { REG_EBX, REG_BX, REG_BH, REG_BL, REG_INVALID_ };
static const REG RCX_SUB_REG[] = { REG_ECX, REG_CX, REG_CH, REG_CL, REG_INVALID_ };
static const REG RDX_SUB_REG[] = { REG_EDX, REG_DX, REG_DH, REG_DL, REG_INVALID_ };
static const REG RSI_SUB_REG[] = { REG_ESI, REG_SI, REG_SIL, REG_INVALID_ };
static const REG RDI_SUB_REG[] = { REG_EDI, REG_DI, REG_DIL, REG_INVALID_ };
static const REG RBP_SUB_REG[] = { REG_EBP, REG_BP, REG_BPL, REG_INVALID_ };
static const REG RSP_SUB_REG[] = { REG_ESP, REG_SP, REG_SPL, REG_INVALID_ };
static const REG R8_SUB_REG[] = { REG_R8D, REG_R8W, REG_R8B, REG_INVALID_ };
static const REG R9_SUB_REG[] = { REG_R9D, REG_R9W, REG_R9B, REG_INVALID_ };
static const REG R10_SUB_REG[] = { REG_R10D, REG_R10W, REG_R10B, REG_INVALID_ };
static const REG R11_SUB_REG[] = { REG_R11D, REG_R11W, REG_R11B, REG_INVALID_ };
static const REG R12_SUB_REG[] = { REG_R12D, REG_R12W, REG_R12B, REG_INVALID_ };
static const REG R13_SUB_REG[] = { REG_R13D, REG_R13W, REG_R13B, REG_INVALID_ };
static const REG R14_SUB_REG[] = { REG_R14D, REG_R14W, REG_R14B, REG_INVALID_ };
static const REG R15_SUB_REG[] = { REG_R15D, REG_R15W, REG_R15B, REG_INVALID_ };
static const REG INVALID_SUB_REG[] = {REG_INVALID_};

const REG *Registers::getSubRegisters(REG reg) {
	switch (reg) {
	case REG_RAX:
		return &RAX_SUB_REG[0];
	case REG_EAX:
		return &RAX_SUB_REG[1];
	case REG_AX:
		return &RAX_SUB_REG[2];
	case REG_RBX:
		return &RBX_SUB_REG[0];
	case REG_EBX:
		return &RBX_SUB_REG[1];
	case REG_BX:
		return &RBX_SUB_REG[2];
	case REG_RCX:
		return &RCX_SUB_REG[0];
	case REG_ECX:
		return &RCX_SUB_REG[1];
	case REG_CX:
		return &RCX_SUB_REG[2];
	case REG_RDX:
		return &RDX_SUB_REG[0];
	case REG_EDX:
		return &RDX_SUB_REG[1];
	case REG_DX:
		return &RDX_SUB_REG[2];
	case REG_RSI:
		return &RSI_SUB_REG[0];
	case REG_ESI:
		return &RSI_SUB_REG[1];
	case REG_SI:
		return &RSI_SUB_REG[2];
	case REG_RDI:
		return &RDI_SUB_REG[0];
	case REG_EDI:
		return &RDI_SUB_REG[1];
	case REG_DI:
		return &RDI_SUB_REG[2];
	case REG_RBP:
		return &RBP_SUB_REG[0];
	case REG_EBP:
		return &RBP_SUB_REG[1];
	case REG_BP:
		return &RBP_SUB_REG[2];
	case REG_RSP:
		return &RSP_SUB_REG[0];
	case REG_ESP:
		return &RSP_SUB_REG[1];
	case REG_SP:
		return &RSP_SUB_REG[2];
	case REG_R8:
		return &R8_SUB_REG[0];
	case REG_R8D:
		return &R8_SUB_REG[1];
	case REG_R8W:
		return &R8_SUB_REG[2];
	case REG_R9:
		return &R9_SUB_REG[0];
	case REG_R9D:
		return &R9_SUB_REG[1];
	case REG_R9W:
		return &R9_SUB_REG[2];
	case REG_R10:
		return &R10_SUB_REG[0];
	case REG_R10D:
		return &R10_SUB_REG[1];
	case REG_R10W:
		return &R10_SUB_REG[2];
	case REG_R11:
		return &R11_SUB_REG[0];
	case REG_R11D:
		return &R11_SUB_REG[1];
	case REG_R11W:
		return &R11_SUB_REG[2];
	case REG_R12:
		return &R12_SUB_REG[0];
	case REG_R12D:
		return &R12_SUB_REG[1];
	case REG_R12W:
		return &R12_SUB_REG[2];
	case REG_R13:
		return &R13_SUB_REG[0];
	case REG_R13D:
		return &R13_SUB_REG[1];
	case REG_R13W:
		return &R13_SUB_REG[2];
	case REG_R14:
		return &R14_SUB_REG[0];
	case REG_R14D:
		return &R14_SUB_REG[1];
	case REG_R14W:
		return &R14_SUB_REG[2];
	case REG_R15:
		return &R15_SUB_REG[0];
	case REG_R15D:
		return &R15_SUB_REG[1];
	case REG_R15W:
		return &R15_SUB_REG[2];
	default:
		break;
	}

	return INVALID_SUB_REG;
}

#else
// Context registers in the IA-32 architecture
static const REG EAX_SUB_REG[] = { REG_AX, REG_AH, REG_AL, REG_INVALID_ };
static const REG EBX_SUB_REG[] = { REG_BX, REG_BH, REG_BL, REG_INVALID_ };
static const REG ECX_SUB_REG[] = { REG_CX, REG_CH, REG_CL, REG_INVALID_ };
static const REG EDX_SUB_REG[] = { REG_DX, REG_DH, REG_DL, REG_INVALID_ };
static const REG ESI_SUB_REG[] = { REG_SI, REG_INVALID_ };
static const REG EDI_SUB_REG[] = { REG_DI, REG_INVALID_ };
static const REG EBP_SUB_REG[] = { REG_BP, REG_INVALID_ };
static const REG ESP_SUB_REG[] = { REG_SP, REG_INVALID_ };
static const REG INVALID_SUB_REG[] = {REG_INVALID_};

const REG *Registers::getSubRegisters(REG reg) {
	switch (reg) {
	case REG_EAX:
		return &EAX_SUB_REG[0];
	case REG_AX:
		return &EAX_SUB_REG[1];
	case REG_EBX:
		return &EBX_SUB_REG[0];
	case REG_BX:
		return &EBX_SUB_REG[1];
	case REG_ECX:
		return &ECX_SUB_REG[0];
	case REG_CX:
		return &ECX_SUB_REG[1];
	case REG_EDX:
		return &EDX_SUB_REG[0];
	case REG_DX:
		return &EDX_SUB_REG[1];
	case REG_ESI:
		return &ESI_SUB_REG[0];
	case REG_SI:
		return &ESI_SUB_REG[1];
	case REG_EDI:
		return &EDI_SUB_REG[0];
	case REG_DI:
		return &EDI_SUB_REG[1];
	case REG_EBP:
		return &EBP_SUB_REG[0];
	case REG_BP:
		return &EBP_SUB_REG[1];
	case REG_ESP:
		return &ESP_SUB_REG[0];
	case REG_SP:
		return &ESP_SUB_REG[1];
	default:
		break;
	}

	return INVALID_SUB_REG;
}
#endif
