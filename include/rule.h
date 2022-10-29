#include <string>

#ifndef RULE
#define RULE

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
		string command;

};
#endif