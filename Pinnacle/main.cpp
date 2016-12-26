#include <iostream>
#include <cstdio>

#include "pin.H"

#include "Pinnacle.h"
#include "Processor.h"
#include "Registers.h"
#include "TaintManager.h"
#include "SyscallNumbers.h"
#include "WhiteListManager.h"
#include "TaintOriginManager.h"
#include "TaintOriginHandlers.h"

using namespace std;

Pinnacle *pinnacle;

// Knob controling the elements address to the whitelist.
static KNOB<string> KnobWhiteList(KNOB_MODE_APPEND, "pintool", "w", "", "Pattern to match against the taint sources");
static KNOB<string> KnobLogName(KNOB_MODE_WRITEONCE, "pintool", "o", "taint.log", "Name of the taint log");

BOOL Pinnacle::init() {
	log = new TraceLogger();
	processor = new Processor();
	taint_manager = new TaintManager();
	whitelist_manager = new WhiteListManager();
	descriptor_manager = new DescriptorManager();
	origin_manager = new TaintOriginManager();

	log->open(KnobLogName.ValueString());

#if defined(TARGET_LINUX) || defined(TARGET_MAC)
	origin_manager->add_syscall("accept", Syscall::sys_accept, 3, HANDLER(accept));
	origin_manager->add_syscall("bind", Syscall::sys_bind, 3, HANDLER(bind));
	origin_manager->add_syscall("close", Syscall::sys_close, 1, HANDLER(close));
	origin_manager->add_syscall("connect", Syscall::sys_connect, 3, HANDLER(connect));
	origin_manager->add_syscall("dup", Syscall::sys_dup, 1, HANDLER(dup));
	origin_manager->add_syscall("dup2", Syscall::sys_dup2, 2, HANDLER(dup2));
	origin_manager->add_syscall("dup3", Syscall::sys_dup3, 3, HANDLER(dup3));
	origin_manager->add_syscall("mmap", Syscall::sys_mmap, 6, HANDLER(mmap));
	origin_manager->add_syscall("munmap", Syscall::sys_munmap, 2, HANDLER(munmap));
	origin_manager->add_syscall("open", Syscall::sys_open, 3, HANDLER(open));
	origin_manager->add_syscall("openat", Syscall::sys_openat, 3, HANDLER(openat));
	origin_manager->add_syscall("pread", Syscall::sys_pread, 4, HANDLER(pread));
	origin_manager->add_syscall("read", Syscall::sys_read, 3, HANDLER(read));
	origin_manager->add_syscall("readv", Syscall::sys_readv, 3, HANDLER(readv));
	origin_manager->add_syscall("recvfrom", Syscall::sys_recvfrom, 6, HANDLER(recvfrom));
	origin_manager->add_syscall("recvmsg", Syscall::sys_recvmsg, 3, HANDLER(recvmsg));
	origin_manager->add_syscall("socket", Syscall::sys_socket, 3, HANDLER(socket));
	origin_manager->add_syscall("socketcall", Syscall::sys_socketcall, 3, HANDLER(socketcall));
#elif defined(TARGET_WINDOWS)
	origin_manager->add_function("wsock32.dll", "recv", 4, HANDLER(recv));
	origin_manager->add_function("wsock32.dll", "recvfrom", 6, HANDLER(recvfrom));
	origin_manager->add_function("ws2_32.dll", "recv", 4, HANDLER(recv));
	origin_manager->add_function("ws2_32.dll", "recvfrom", 6, HANDLER(recvfrom));
	origin_manager->add_function("kernel32.dll", "ReadFile", 5, HANDLER(ReadFile));

#endif

	for (UINT32 i = 0; i < KnobWhiteList.NumberOfValues(); ++i) {
		string value = KnobWhiteList.Value(i);
		printf("LOG: Adding pattern to the whitelist: %s\n", value.c_str());
		whitelist_manager->add(value);
	}

	return true;
}

VOID Pinnacle::onTaintEvent(ADDRINT ip) {
	log->logTaintedInstruction(ip);
}

VOID Pinnacle::instrumentInstruction(const INS &ins) {
	// All the information about which instructions fall into category X
	// was extracted from:
	// $ grep LOGIC idata.txt | grep SSE -v | grep -v AVX | grep -v MMX | cut -d' ' -f1  | sort | uniq
	INT32 category = INS_Category(ins);
	INT32 opcode = INS_Opcode(ins);

	// I consider this switch complete.
	switch (category) {
	case XED_CATEGORY_SHIFT:
		switch (opcode) {
		case XED_ICLASS_SHLD:
		case XED_ICLASS_SHRD:
			processor->process_shift_trinary(ins);
			break;
		}
		break;
	case XED_CATEGORY_LOGICAL:
		switch (opcode) {
		case XED_ICLASS_OR:
		case XED_ICLASS_XOR:
		case XED_ICLASS_AND:
			processor->process_logical_binary(ins);
			break;
		}
		break;
	case XED_CATEGORY_BINARY:
		switch (opcode) {
		case XED_ICLASS_ADD:
		case XED_ICLASS_ADC:
		case XED_ICLASS_SBB:
		case XED_ICLASS_SUB:
			processor->process_binary_bin(ins);
			break;
		case XED_ICLASS_MUL:
		case XED_ICLASS_DIV:
		case XED_ICLASS_IDIV:
			processor->process_binary_unary(ins);
			break;
		case XED_ICLASS_IMUL:
			processor->process_binary_imul(ins);
			break;
		}
		break;
	case XED_CATEGORY_DATAXFER:
		switch (opcode) {
		case XED_ICLASS_MOV:
			processor->process_mov(ins);
			break;
		case XED_ICLASS_XCHG:
			processor->process_xchg(ins);
			break;
		case XED_ICLASS_MOVSX:
		case XED_ICLASS_MOVSXD:
		case XED_ICLASS_MOVZX:
			processor->process_mov_ext(ins);
			break;
		case XED_ICLASS_MOVBE:
			processor->process_movbe(ins);
			break;
		}
		break;
	case XED_CATEGORY_STRINGOP:
		switch (opcode) {
		case XED_ICLASS_MOVSB:
		case XED_ICLASS_MOVSW:
		case XED_ICLASS_MOVSD:
		case XED_ICLASS_MOVSQ:
			processor->process_movs(ins);
			break;
		case XED_ICLASS_STOSB:
		case XED_ICLASS_STOSW:
		case XED_ICLASS_STOSD:
		case XED_ICLASS_STOSQ:
			processor->process_stos(ins);
			break;
		case XED_ICLASS_LODSB:
		case XED_ICLASS_LODSW:
		case XED_ICLASS_LODSD:
		case XED_ICLASS_LODSQ:
			processor->process_lods(ins);
			break;
		}
		break;
	case XED_CATEGORY_MISC:
		switch (opcode) {
		case XED_ICLASS_LEA:
			processor->process_lea(ins);
			break;
		case XED_ICLASS_LEAVE:
			processor->process_leave(ins);
			break;
		case XED_ICLASS_ENTER:
			processor->process_enter(ins);
			break;
		}
		break;
	case XED_CATEGORY_POP:
		switch (opcode) {
		case XED_ICLASS_POP:
			processor->process_pop(ins);
			break;
		case XED_ICLASS_POPA:
		case XED_ICLASS_POPAD:
			processor->process_popa(ins);
			break;
		}
		break;
	case XED_CATEGORY_PUSH:
		switch (opcode) {
		case XED_ICLASS_PUSH:
			processor->process_push(ins);
			break;
		case XED_ICLASS_PUSHF:
		case XED_ICLASS_PUSHFD:
		case XED_ICLASS_PUSHFQ:
			processor->process_push_flags(ins);
			break;
		case XED_ICLASS_PUSHA:
		case XED_ICLASS_PUSHAD:
			processor->process_pusha(ins);
			break;
		}
		break;
	case XED_CATEGORY_CALL:
		switch (opcode) {
		case XED_ICLASS_CALL_NEAR:
		case XED_ICLASS_CALL_FAR:
			processor->process_call(ins);
			break;
		}
		break;
	case XED_CATEGORY_COND_BR:
		switch (opcode) {
		case XED_ICLASS_JB:
		case XED_ICLASS_JBE:
		case XED_ICLASS_JL:
		case XED_ICLASS_JLE:
		case XED_ICLASS_JNB:
		case XED_ICLASS_JNBE:
		case XED_ICLASS_JNL:
		case XED_ICLASS_JNLE:
		case XED_ICLASS_JNO:
		case XED_ICLASS_JNP:
		case XED_ICLASS_JNS:
		case XED_ICLASS_JNZ:
		case XED_ICLASS_JO:
		case XED_ICLASS_JP:
		case XED_ICLASS_JS:
		case XED_ICLASS_JZ:
			processor->process_jmp(ins);
			break;
		}
		break;
	case XED_CATEGORY_UNCOND_BR:
		switch (opcode) {
		case XED_ICLASS_JMP:
		case XED_ICLASS_JMP_FAR:
			processor->process_jmp(ins);
			break;
		}
		break;
	case XED_CATEGORY_CMOV:
		switch (opcode) {
		case XED_ICLASS_CMOVB:
		case XED_ICLASS_CMOVBE:
		case XED_ICLASS_CMOVL:
		case XED_ICLASS_CMOVLE:
		case XED_ICLASS_CMOVNB:
		case XED_ICLASS_CMOVNBE:
		case XED_ICLASS_CMOVNL:
		case XED_ICLASS_CMOVNLE:
		case XED_ICLASS_CMOVNO:
		case XED_ICLASS_CMOVNP:
		case XED_ICLASS_CMOVNS:
		case XED_ICLASS_CMOVNZ:
		case XED_ICLASS_CMOVO:
		case XED_ICLASS_CMOVP:
		case XED_ICLASS_CMOVS:
		case XED_ICLASS_CMOVZ:
			processor->process_cmov(ins);
			break;
		}
		break;
	case XED_CATEGORY_RET:
		switch (opcode) {
		case XED_ICLASS_RET_NEAR:
		case XED_ICLASS_RET_FAR:
			processor->process_ret(ins);
			break;
		}
		break;
	case XED_CATEGORY_CONVERT:
		switch (opcode) {
		case XED_ICLASS_CBW:
		case XED_ICLASS_CDQ:
		case XED_ICLASS_CDQE:
		case XED_ICLASS_CQO:
		case XED_ICLASS_CWD:
		case XED_ICLASS_CWDE:
			processor->process_convert(ins);
			break;
		}
		break;
	}
}

VOID Pinnacle::onThreadStartEvent(THREADID tid, CONTEXT *ctxt, INT32 flags) {
	taint_manager->createThreadSpecificTaintMaps(tid);
}

VOID Pinnacle::onThreadFiniEvent(THREADID tid, const CONTEXT *ctxt, INT32 c) {
	taint_manager->destroyThreadSpecificTaintMaps(tid);
}

VOID Pinnacle::onImageLoadEvent(const IMG &img) {
	origin_manager->on_library_loaded(img);
	log->logImageLoad(img);
}

VOID Pinnacle::onImageUnloadEvent(const IMG &img) {
	log->logImageUnload(img);
}

VOID Pinnacle::onSyscallEntryEvent(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std) {
	origin_manager->on_syscall_entry(tid, ctxt, std);
}

VOID Pinnacle::onSyscallExitEvent(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std) {
	origin_manager->on_syscall_exit(tid, ctxt, std);
}

VOID Pinnacle::onFiniEvent(INT32 code) {
	log->close();
}

VOID Pinnacle::onStartEvent() {
	// When we attach to a process we do not have the chance to hook image loads.
	for (IMG img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)) {
		onImageLoadEvent(img);
	}
}

VOID Pinnacle::onTraceEvent(const TRACE &trace) {
	if (!taint_manager->active())
		return;

	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
			instrumentInstruction(ins);
		}
	}
}

// Thread creation event handler.
static VOID OnThreadStart(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *pinnacle) {
	static_cast<Pinnacle *>(pinnacle)->onThreadStartEvent(tid, ctxt, flags);
}

// Thread destruction event handler.
static VOID OnThreadFini(THREADID tid, const CONTEXT *ctxt, INT32 c, VOID *pinnacle) {
	static_cast<Pinnacle *>(pinnacle)->onThreadFiniEvent(tid, ctxt, c);
}

// Image load event handler.
static VOID OnImageLoad(IMG img, VOID *pinnacle) {
	static_cast<Pinnacle *>(pinnacle)->onImageLoadEvent(img);
}

// Image unload event handler.
static VOID OnImageUnload(IMG img, VOID *pinnacle) {
	static_cast<Pinnacle *>(pinnacle)->onImageUnloadEvent(img);
}

static VOID OnSyscallEntry(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *pinnacle) {
	static_cast<Pinnacle *>(pinnacle)->onSyscallEntryEvent(tid, ctxt, std);
}

static VOID OnSyscallExit(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *pinnacle) {
	static_cast<Pinnacle *>(pinnacle)->onSyscallExitEvent(tid, ctxt, std);
}

// Trace hit event handler.
static VOID OnTraceEvent(TRACE t, VOID *pinnacle) {
	static_cast<Pinnacle *>(pinnacle)->onTraceEvent(t);
}

static VOID OnFinishEvent(INT32 code, VOID *pinnacle) {
	printf("LOG: Application finished, waiting to other threads to finish\n");
	static_cast<Pinnacle *>(pinnacle)->onFiniEvent(code);
}

static VOID OnApplicationStart(VOID *pinnacle) {
	printf("LOG: Application started\n");
	static_cast<Pinnacle *>(pinnacle)->onStartEvent();
}

static INT32 ShowUsage() {
	PIN_ERROR("LOG: Pinnacle Taint Analysis Tool\n" + KNOB_BASE::StringKnobSummary() + "\n");
	return -1;
}

int main(int argc, char *argv[]) {
	PIN_InitSymbols();

	if (PIN_Init(argc, argv)) {
		cerr << "PIN_Init failed!" << endl;
		return ShowUsage();
	}

	// Initialize pinnacle.
	pinnacle = new Pinnacle();
	pinnacle->init();

	// Handlers for syscall entry and exit.
	PIN_AddSyscallEntryFunction(OnSyscallEntry, pinnacle);
	PIN_AddSyscallExitFunction(OnSyscallExit, pinnacle);

	// Handlers for thread creation and destruction.
	PIN_AddThreadStartFunction(OnThreadStart, pinnacle);
	PIN_AddThreadFiniFunction(OnThreadFini, pinnacle);

	// Image load/unload instrumentation.
	IMG_AddInstrumentFunction(OnImageLoad, pinnacle);
	IMG_AddUnloadFunction(OnImageUnload, pinnacle);

	TRACE_AddInstrumentFunction(OnTraceEvent, pinnacle);

	// Start and finish of the process event handlers.
	PIN_AddApplicationStartFunction(OnApplicationStart, pinnacle);
	PIN_AddFiniFunction(OnFinishEvent, pinnacle);

	// Run the target program instrumented.
	PIN_StartProgram();

	return 0;
}
