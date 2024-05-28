#ifndef RULE
#define RULE

#include <cmath>
#include <string>

using namespace std;

class Rule {

    public:

        bool no_check;
        bool freeze;
        bool oom_kill_enabled;
        bool pid_kill_enabled;
        bool regex_search_enabled;
        bool send_notifications;
        bool enable_limiting;
        bool include_binary_folder_check;
        bool wildcard_match;
        double cpu_trigger_threshold;
        int checks_before_alert;
        int limit_cpu_percent;
        long long limit_memory_value;
        long long  mem_trigger_threshold;
        string rule_name;
        string command;
        string regex_search_pattern_string;
        string cgroup_root_dir;
        string cgroup_subtree_control_file;
        string cgroup_name;
        string cgroup_cpu_max_file;
        string cgroup_procs_file;
        string cgroup_memory_high_file;
        string cgroup_memory_max_file;
        string cgroup_freezer_file;
        regex regex_search_pattern;

};

#endif
