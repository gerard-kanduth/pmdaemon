#ifndef RULE
#define RULE

#include <string>
#include <set>
#include <map>

using namespace std;

class Rule {

	public:

		bool no_check;
		bool freeze;
		bool oom_kill_enabled;
		bool pid_kill_enabled;
		bool send_process_files;
		double cpu_trigger_threshold;
		double mem_trigger_threshold;
		int checks_before_alert;
		string rule_name;
		string command;

};

#endif