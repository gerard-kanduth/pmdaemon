#ifndef CONTROLLER
#define CONTROLLER

#include <cctype>
#include <cmath>
#include <iostream>
#include <iomanip>
#include <curl/curl.h>
#include <limits>
#include <unordered_map>
#include <sstream>
#include <stdio.h>
#include <string>
#include <unistd.h>
#include "logger.h"
#include "rulemanager.h"
#include "settings.h"

using namespace std;

class Controller {

	private:

		// cgroup list struct
		struct CgroupListItem {
			int pid;
			string cgroup;
		};

		// struct for a process
		struct Process {
			int pid;
			string state;
			string user;
			double pcpu;
			double pmem;
			string command;
		} current_process;

		// penalty list-item
		struct PenaltyListItem {
			int pid;
			int penalty_counter;
			int cooldown_counter;
			string penalty_cause;
			string cgroup_name;
			bool alerted = false;
			bool in_cgroup = false;
			bool limited = false;
		};

		// advanced process information
		struct ProcessInfo {
			int _pid;
			double _pcpu;
			double _pmem;
			string _command;
			string _status;
			string _io;
			string _limits;
			string _syscall;
			string _cgroup;
			string _cause;
			string _state;
		};

		// penalty list
		unordered_map<int,PenaltyListItem> penalty_list;
		unordered_map<int,PenaltyListItem>::iterator it;

		// settings object (contains all settings)
		Settings* settings = nullptr;

		// rules object (contains all loaded rules)
		RuleManager* rulemanager = nullptr;

		// pointer for specific rule
		Rule* specific_rule = nullptr;

		// the name of the daemon
		const char* daemon_name;

		// curl instance used for http logging
		// libcurl, see: https://curl.se/libcurl
		CURL* curl = nullptr;
		CURLcode curl_result;

		// the comand which will be constantly checked "2>&1" used to get stderr
		string command = "ps -e -ww --no-headers -o %p\\; -o stat -o \\;%U -o \\;%C\\; -o %mem -o \\;%a 2>&1";

		// main cgroup.procs file which contains all pids which are not part of a specific cgroup
		string main_cgroup_procs_file = "/sys/fs/cgroup/cgroup.procs";

		// additional buffer and pipe for reading output
		array<char, 128> input_buffer;
		string check_result;

		// number of failed checks
		int error_checks = 0;

		// max number of fails before daemon terminates
		int max_errors;

		// variable for hostname
		char hostname_buffer[128];
		const char* hostname = nullptr;

		// helper variables
		size_t next_semi_colon_pos;
		string ps_line;
		string c_pid;
		string c_state;
		string c_user;
		string c_pcpu;
		string c_pmem;
		string c_command;

		// used to limit trailing zeroes on measured values
		char limit_pcpu[128];
		char limit_pmem[128];

		// default limits (if no specific rule is set for process)
		bool state_trigger;
		bool load_rules;
		bool specific_rules_check_only;
		bool term_cgroup_cleanup;
		double default_cpu_trigger_threshold;
		double default_mem_trigger_threshold;
		int default_checks_before_alert;
		int checks_cooldown;

		// enable_limiting can only be enabled in specific_rules
		bool default_enable_limiting = false;
		bool* enable_limiting = &default_enable_limiting;

		// send_process_files can only be disabled in specific_rules
		bool send_process_files;

		// the defaults will be used if LOAD_RULES is disabled
		int* checks_before_alert = &default_checks_before_alert;
		double* cpu_trigger_threshold = &default_cpu_trigger_threshold;
		double* mem_trigger_threshold = &default_mem_trigger_threshold;

		// graylog related variables
		bool graylog_enabled;
		bool graylog_http_secure;
		int graylog_port;
		string graylog_fqdn;
		string graylog_http_path;
		string graylog_transport_method;
		string graylog_http_protocol_prefix;
		string graylog_final_url;

		// graylog message variables
		double graylog_message_version = 1.1;
		int graylog_message_level = 1;

		// private functions
		ProcessInfo collectProcessInfo(Process*, string);
		bool addPidToCgroup(string*, int*);
		bool checkProcess(Process*);
		bool curlPostJSON(const char*);
		bool checkIfCgroupEmpty(string*, int*);
		bool checkPenaltyList(Process*, string);
		bool cleanupPenaltyList();
		bool createCgroup(string*, int*);
		bool doLimit(Process*);
		bool enableCgroupControllers();
		bool iterateProcessList(string);
		bool removeCgroup(string);
		bool removePidFromCgroup(int);
		string readProcFile(string, int*);
		void graylogAlert(ProcessInfo);
		void graylogHTTPAlert(ProcessInfo);
		void graylogUDPAlert(ProcessInfo);
		void graylogTCPAlert(ProcessInfo);
		void graylogLimitInfo(Process*);
		void graylogHTTPlimitInfo(Process*);
		void graylogUDPlimitInfo(Process*);
		void graylogTCPlimitInfo(Process*);

	public:

		// public functions
		Controller(const char*, Settings*&);
		~Controller();
		bool cleanupCgroups();
		bool doCheck();
		bool terminate();
		void showInformation();

};

#endif