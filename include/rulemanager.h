#ifndef RULES
#define RULES

#include <iostream>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <typeinfo>
#include "logger.h"
#include "settings.h"
#include "rule.h"

namespace fs = std::filesystem;
using namespace std;

class RuleManager {

	private:

		struct RuleReturn {
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
			"ENABLE_LIMITING",
			"LIMIT_CPU_PERCENT",
			"LIMIT_MEM_PERCENT",
			"CHECKS_BEFORE_ALERT"
		};

		const char* rules_directory;

		map<string, Rule> rules;

		const char* cgroup_root_dir = "/sys/fs/cgroup";
		const char* daemon_name;

		RuleReturn readRuleFile(string);
		bool createCgroup(Rule*);
		bool checkIfRuleIsValid(map<string, string>);
		bool generateRuleFromFile(string);
		bool registerRule(map<string, string>);
		void loadRules();
		void showRuleContent(map<string, string>);

	public:

		RuleManager(const char*, string);
		Rule* loadIfRuleExists(string*);

};

#endif