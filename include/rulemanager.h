#include <iostream>
#include <fstream>
#include <string>
#include <dirent.h>
#include <set>
#include <map>
#include <iostream>
#include <filesystem>
#include "logger.h"
#include "settings.h"
#include "rule.h"

#ifndef RULES
#define RULES

namespace fs = std::filesystem;
using namespace std;

class RuleManager {

	struct ruleReturn {
		bool success;
		map<string, string> rule;
	};

	private:

		const set<string> available_rule_settings {
			"COMMAND",
			"NO_CHECK",
			"FREEZE",
			"OOM_KILL_ENABLED",
			"PID_KILL_ENABLED",
			"SEND_PROCESS_FILES",
			"CPU_TRIGGER_THRESHOLD",
			"MEM_TRIGGER_THRESHOLD"
		};

		const set<string> mandatory_rule_settings {
			"COMMAND",
			"CPU_TRIGGER_THRESHOLD",
			"MEM_TRIGGER_THRESHOLD"
		};

		string rules_directory;

		map<string, Rule> rules;

		ruleReturn readRuleFile(string);
		bool registerRule(map<string, string>);
		bool checkIfRuleIsValid(map<string, string>);
		void loadRules();
		void generateRuleFromFile(string&);
		void showRuleContent(map<string, string>);

	public:

		RuleManager(Settings*&);
};

#endif

