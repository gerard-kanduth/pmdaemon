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
#include <unistd.h>
#include "logger.h"
#include "settings.h"
#include "utils.h"
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
			"LIMIT_MEMORY_VALUE",
			"CHECKS_BEFORE_ALERT"
		};

		const char* rules_directory = nullptr;
		const char* daemon_name = nullptr;
		const char* cgroup_root_dir = "/sys/fs/cgroup";
		string subtree_control_file = "cgroup.subtree_control";
		string cpu_max_file = "cpu.max";
		string procs_file = "cgroup.procs";
		string memory_high_file = "memory.high";
		string memory_max_file = "memory.max";
		string freezer_file = "cgroup.freeze";

		map<string, Rule> rules;

		RuleReturn readRuleFile(string);
		bool createCgroup(Rule*);
		bool checkIfRuleIsValid(map<string, string>);
		bool generateRuleFromFile(string);
		bool registerRule(map<string, string>);
		void loadRules();
		void showRuleContent(Rule);

	public:

		RuleManager(const char*, string);
		Rule* loadIfRuleExists(string);
		void showRules();

};

#endif