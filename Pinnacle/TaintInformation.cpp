/*
 * File: TaintInformation.cpp
 * Author: Agustin Gianni (agustingianni@gmail.com)
 *
 * Created on March 20, 2011, 4:36 PM
 */

#include <sstream>
#
#include "pin.H"
#include "TaintInformation.h"
#include "DescriptorManager.h"

using namespace std;

TaintInformation::TaintInformation(ADDRINT origin) :
	origin(origin) {
}

TaintInformation::TaintInformation(ADDRINT origin, boost::shared_ptr<TaintInformation> next) :
	origin(origin), next(next) {
}

ReadTaintInformation::ReadTaintInformation(ADDRINT origin, DescriptorType descriptor, off_t offset) :
	TaintInformation(origin), descriptor(descriptor), offset(offset) {
}
