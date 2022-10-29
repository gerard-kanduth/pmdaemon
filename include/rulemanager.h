#ifndef RULES
#define RULES

#include <iostream>
#include <filesystem>
#include <fstream>
#include <set>
#include <map>
#include <string>
#include <typeinfo>
#include "logger.h"
#include "settings.h"
#include "rule.h"

namespace fs = std::filesystem;
using namespace std;

class RuleManager {

	private:

		struct ruleReturn {
			bool success;
			map<string, string> rule;
		};

		const set<string> mandatory_rule_settings {
			"RULE_NAME",
			"COMMAND",
			"CPU_TRIGGER_THRESHOLD",
			"MEM_TRIGGER_THRESHOLD"
		};

		const set<string> available_rule_settings {
			"RULE_NAME",
			"COMMAND",
			"NO_CHECK",
			"FREEZE",
			"OOM_KILL_ENABLED",
			"PID_KILL_ENABLED",
			"SEND_PROCESS_FILES",
			"CPU_TRIGGER_THRESHOLD",
			"MEM_TRIGGER_THRESHOLD",
			"CHECKS_BEFORE_ALERT"
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

