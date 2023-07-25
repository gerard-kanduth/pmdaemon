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
		bool include_binary_folder_check;
		bool wildcard_match;

		double cpu_trigger_threshold = NAN;
		double mem_trigger_threshold = NAN;

		int checks_before_alert;
		int limit_cpu_percent = -1;
		int limit_memory_value = -1;

		string rule_name;
		string command;
		string cgroup_root_dir;
		string cgroup_subtree_control_file;
		string cgroup_name;
		string cgroup_cpu_max_file;
		string cgroup_procs_file;
		string cgroup_memory_high_file;
		string cgroup_memory_max_file;
		string cgroup_kill_file;
		string cgroup_freezer_file;

};

#endif
