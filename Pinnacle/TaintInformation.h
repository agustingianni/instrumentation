/*
 * File: TaintInformation.h
 * Author: Agustin Gianni (agustingianni@gmail.com)
 *
 * Created on March 20, 2011, 4:36 PM
 */

#ifndef TAINTINFORMATION_H_
#define TAINTINFORMATION_H_

#include <string>
#include <boost/shared_ptr.hpp>

#include "pin.H"
#include "DescriptorManager.h"

struct TaintInformation {
	ADDRINT origin;
	boost::shared_ptr<TaintInformation> next;

	TaintInformation(ADDRINT origin);
	TaintInformation(ADDRINT origin, boost::shared_ptr<TaintInformation> next);
};

struct ReadTaintInformation: public TaintInformation {
	DescriptorType descriptor;
	off_t offset;

	ReadTaintInformation(ADDRINT origin, DescriptorType fd, off_t offset);
};

#endif /* TAINTINFORMATION_H_ */
