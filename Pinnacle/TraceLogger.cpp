/*
 * File:   TraceLogger.cpp
 * Author: Agustin Gianni (agustingianni@gmail.com)
 *
 * Created on March 19, 2011, 3:29 PM
 */

#include <fstream>
#include <iostream>

#include "pin.H"
#include "TraceLogger.h"

using namespace std;

void TraceLogger::open(const string &f_name) {
	output.open(f_name.c_str(), ios::out | ios::binary | ios::trunc);
	output.rdbuf()->pubsetbuf(buffer, buffer_size);
}

void TraceLogger::close() {
	output.close();
}

void TraceLogger::logImageLoad(const IMG &img) {
	logImageLoad(IMG_Name(img), IMG_LowAddress(img), IMG_HighAddress(img));
}

void TraceLogger::logImageUnload(const IMG &img) {
	logImageUnload(IMG_Name(img));
}

// Log the log of an image. We log the start and end addresses so we can rebase IDA.
void TraceLogger::logImageLoad(const string &img_name, ADDRINT img_base, ADDRINT img_end) {
	lock.get(1);
	output << TL_IMG_LOAD << SEP << img_name << SEP << (void *) img_base << SEP << (void *) img_end << '\n';
	lock.release();
}

// We also log the unloads in case another image is loaded in the same address sapce.
void TraceLogger::logImageUnload(const string &img_name) {
	lock.get(2);
	output << TL_IMG_UNLOAD << SEP << img_name << '\n';
	lock.release();
}

// Log the address of the tainted instruction.
void TraceLogger::logTaintedInstruction(ADDRINT address) {
	lock.get(3);
	output << TL_INST_EXEC << SEP << (void *) address << '\n';
	lock.release();
}
