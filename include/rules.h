#include <iostream>
#include <string>
#include <dirent.h>
#include <map>
#include <set>
#include <iostream>
#include <filesystem>
#include "logger.h"
#include "settings.h"

#ifndef RULES
#define RULES

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
		double cpu_trigger_threashold;
		double mem_trigger_threashold;
		int check_before_alert;
		string command;

	public:

		Rule(Settings*&);
};

#endif

class Rules {

	private:

		string rules_directory;
		int rule_number = 0;
		Rule** rules;

		void loadRules(Settings*&);
		void generateRuleFromFile(string&);

	public:

		Rules(Settings*&);
};

#endif

