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

namespace fs = std::filesystem;
using namespace std;

#ifndef RULE
#define RULE

class Rule {

	private:

		bool no_check = false;
		bool freeze = false;
		bool oom_kill_enabled = false;
		bool pid_kill_enabled = false;
		bool send_process_files = false;
		double cpu_trigger_threshold;
		double mem_trigger_threshold;
		int checks_before_alert;
		string command;

	public:

		Rule(Settings*&);
};

#endif

#ifndef RULES
#define RULES

class Rules {

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
			"MEM_TRIGGER_THRESHOLD",
			"CHECKS_BEFORE_ALERT"
		};

		const set<string> mandatory_rule_settings {
			"COMMAND",
			"CPU_TRIGGER_THRESHOLD",
			"MEM_TRIGGER_THRESHOLD"
		};

		string rules_directory;

		map<string, Rule> rules;

		ruleReturn readRuleFile(string);
		bool checkIfRuleIsValid(map<string, string>);
		void loadRules(Settings*&);
		void generateRuleFromFile(string&);
		void showRuleContent(map<string, string>);

	public:

		Rules(Settings*&);
};

#endif

