#ifndef RULE
#define RULE

#include <string>

using namespace std;

class Rule {

	public:

		bool no_check;
		bool freeze;
		bool oom_kill_enabled;
		bool pid_kill_enabled;
		bool send_process_files;
		bool enable_limiting;
		double limit_cpu_percent = NAN;
		double limit_mem_percent = NAN;
		double cpu_trigger_threshold = NAN;
		double mem_trigger_threshold = NAN;
		int checks_before_alert;
		string rule_name;
		string command;
		string cgroup_name;

};

#endif