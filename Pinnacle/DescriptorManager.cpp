/*
 * File: DescriptorManager.cpp
 * Author: Agustin Gianni (agustingianni@gmail.com)
 *
 * Created on March 20, 2011, 4:36 PM
 */

#include "DescriptorManager.h"
#include <memory>

using namespace std;

// Create a new DescriptorState for a given descriptor.
std::shared_ptr<DescriptorState> DescriptorManager::createDescriptorState(DescriptorType descriptor) {
	auto ds = std::make_shared<DescriptorState>(descriptor);
	desc_map[descriptor] = ds;
	return ds;
}

// Duplicate the original 'ds' and place it into another socket.
void DescriptorManager::dupDescriptorState(DescriptorType descriptor, std::shared_ptr<DescriptorState> ds) {
	auto copy = std::make_shared<DescriptorState>(descriptor);
	*copy = *ds;
	desc_map[descriptor] = copy;
}

// Set the corresponding 'Descriptorstate' structure to a given descriptor.
// This is used for example for handling the dup family of system calls in unix.
void DescriptorManager::setDescriptorState(DescriptorType descriptor, std::shared_ptr<DescriptorState> ds) {
	desc_map[descriptor] = ds;
}

void DescriptorManager::removeDescriporState(DescriptorType descriptor) {
	auto it = desc_map.find(descriptor);
	if (it != desc_map.end()) {
		desc_map.erase(it);
	}
}

std::shared_ptr<DescriptorState> DescriptorManager::getDescriptorState(DescriptorType descriptor) {
	auto it = desc_map.find(descriptor);
	return (it == desc_map.end()) ? std::shared_ptr<DescriptorState>() : it->second;
}

// Check if the descriptor is being tracked by the descriptor manager
// this is mainly used to check if we are working on the default
// file descriptors which were not created by the software but by the OS.
// It also works with file descriptors that were skipped by our taint source
// whitelist.
bool DescriptorManager::checkDescriptor(DescriptorType descriptor) {
	return desc_map.find(descriptor) != desc_map.end();
}
