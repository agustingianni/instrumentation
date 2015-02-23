/*
 * TaintOriginHandlers.h
 *
 *  Created on: Dec 11, 2014
 *      Author: anon
 */

#ifndef TAINTORIGINHANDLERS_H_
#define TAINTORIGINHANDLERS_H_

#if defined(TARGET_WINDOWS)
#include "TaintOriginHandlersWindows.h"
#else
#include "TaintOriginHandlersUnix.h"
#endif

#endif /* TAINTORIGINHANDLERS_H_ */
