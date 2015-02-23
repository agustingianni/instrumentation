/*
 * WhitelistManager.h
 *
 *  Created on: Jul 18, 2011
 *      Author: gr00vy
 */

#ifndef WHITELISTMANAGER_H_
#define WHITELISTMANAGER_H_

#include <string>
#include <vector>

class WhiteListManager {
private:
	std::vector<std::string> whitelist;

public:
	void add(const string &name) {
		whitelist.push_back(name);
	}

	bool check(const string &name) {
		if (whitelist.empty())
			return true;

		for (const auto &s : whitelist) {
			if (name.find(s) != string::npos)
				return true;
		}

		return false;
	}

};

#endif /* WHITELISTMANAGER_H_ */
