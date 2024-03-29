#ifndef RULES
#define RULES

#include <iostream>
#include <filesystem>
#include <fstream>
#include <unordered_map>
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
			unordered_map<string, string> rule;
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
			"INCLUDE_BINARY_FOLDER_CHECK",
			"WILDCARD_MATCH",
			"CHECKS_BEFORE_ALERT"
		};

		const char* rules_directory = nullptr;
		const char* daemon_name = nullptr;
		const char* cgroup_root_dir = "/sys/fs/cgroup";
		string cpu_max_file = "cpu.max";
		string freezer_file = "cgroup.freeze";
		string kill_file = "cgroup.kill";
		string memory_high_file = "memory.high";
		string memory_max_file = "memory.max";
		string procs_file = "cgroup.procs";
		string subtree_control_file = "cgroup.subtree_control";

		unordered_map<string, Rule> rules;

		RuleReturn readRuleFile(string);
		bool createCgroup(Rule*);
		bool checkIfRuleIsValid(unordered_map<string, string>);
		bool generateRuleFromFile(string);
		bool registerRule(unordered_map<string, string>);
		void loadRules();
		void showRuleContent(Rule);

	public:

		RuleManager(const char*, string);
		Rule* loadIfRuleExists(string);
		bool removeCgroupRules();
		void showRules();

};

#endif
