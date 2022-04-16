#include <iostream>
#include <string>
#include <dirent.h>
#include <map>
#include <set>

using namespace std;

class Rule {
	
	private:
		const set<string> rule_settings {
			"COMMAND",
			"NO_CHECK",
			"CPU_TRIGGER_THRESHOLD",
			"MEM_TRIGGER_THRESHOLD",
			"ZOMBIE_TRIGGER",
			"CHECKS_BEFORE_ALERT",
			"SEND_PROCESS_FILES",
			"GRAYLOG_ENABLE"			
		};
		map<string, string> rules;
		bool rule_success = false;
		
	public:
		Rule();
};

class Rules {
	
	private:
		const char *rules_directory;
		int rule_number = 0;
		Rule rules[];
	
	public:
		Rules(string);
	
};