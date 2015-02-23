/*
 * Pinnacle.h
 *
 *  Created on: Dec 13, 2014
 *      Author: anon
 */

#ifndef PINNACLE_H_
#define PINNACLE_H_

#include "pin.H"

#include "Processor.h"
#include "TraceLogger.h"
#include "TaintManager.h"
#include "WhiteListManager.h"
#include "TaintOriginManager.h"
#include "TaintOriginHandlers.h"

class Pinnacle {
public:
	Processor *processor;
	TraceLogger *log;
	TaintManager *taint_manager;
	WhiteListManager *whitelist_manager;
	DescriptorManager *descriptor_manager;
	TaintOriginManager *origin_manager;

private:
	VOID instrumentInstruction(const INS &ins);

public:
	BOOL init();
	VOID onTaintEvent(ADDRINT ip);
	VOID onThreadStartEvent(THREADID tid, CONTEXT *ctxt, INT32 flags);
	VOID onThreadFiniEvent(THREADID tid, const CONTEXT *ctxt, INT32 c);
	VOID onImageLoadEvent(const IMG &img);
	VOID onImageUnloadEvent(const IMG &img);
	VOID onSyscallEntryEvent(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std);
	VOID onSyscallExitEvent(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std);
	VOID onFiniEvent(INT32 code);
	VOID onStartEvent();
	VOID onTraceEvent(const TRACE &trace);

};

#endif /* PINNACLE_H_ */
