/*
 * File:   TraceLogger.h
 * Author: Agustin Gianni (agustingianni@gmail.com)
 *
 * Created on March 19, 2011, 3:29 PM
 */

#ifndef TRACELOGGER_H_
#define TRACELOGGER_H_

#include <string>
#include <fstream>

#include "pin.H"
#include "Utilities.h"

#define SEP ";"
#define TL_IMG_LOAD "L"
#define TL_IMG_UNLOAD "U"
#define TL_INST_EXEC "T"

class TraceLogger {
public:

	void open(const string &f_name);
	void close();

	void logImageLoad(const IMG &img);
	void logImageUnload(const IMG &img);
	void logImageLoad(const std::string &img_name, ADDRINT img_base, ADDRINT img_end);
	void logImageUnload(const std::string &img_name);
	void logTaintedInstruction(ADDRINT address);

private:
	Utilities::Lock lock;
	ofstream output;

	static const unsigned buffer_size = 0x8000;
	char buffer[buffer_size];
};

#endif /* TRACELOGGER_H_ */
