#include <cctype>
#include <iostream>
#include <curl/curl.h>
#include <map>
#include <sstream>
#include <stdio.h>
#include <string>
#include <unistd.h>
#include "logger.h"
#include "rules.h"
#include "settings.h"

#include <iostream>
#include <iomanip>
#include <cmath>
#include <limits>

using namespace std;

class Controller {

	private:

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
			bool alerted = false;
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
		map<int,PenaltyListItem> penalty_list;
		map<int,PenaltyListItem>::iterator it;

		// settings object (contains all settings)
		Settings* settings;

		// rules object (contains all loaded rules)
		Rules* rules;

		// curl instance used for http logging
		// libcurl, see: https://curl.se/libcurl
		CURL* curl;
		CURLcode curl_result;

		// the comand which will be constantly checked "2>&1" used to get stderr
		string command = "ps -e -ww --no-headers -o %p\\; -o stat -o \\;%U -o \\;%C\\; -o %mem -o \\;%a 2>&1";

		// additional buffer and pipe for reading output
		array<char, 128> input_buffer;
		string check_result;

		// number of failed checks
		int error_checks = 0;

		// max number of fails before daemon terminates
		int max_errors;

		// variable for hostname
		char hostname_buffer[128];
		const char* hostname;

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
		double cpu_trigger_threshold;
		double mem_trigger_threshold;
		int checks_cooldown;
		int checks_before_alert;

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
		bool curlPostJSON(const char*);
		bool checkPenaltyList(Process*, string);
		string readProcFile(string, int*);
		void graylogHTTPAlert(ProcessInfo);
		void graylogUDPAlert(ProcessInfo);
		void graylogTCPAlert(ProcessInfo);

	public:

		// public functions
		Controller(Settings*&);
		~Controller();
		bool checkProcess(Process*);
		void doAlert(ProcessInfo);
		bool doCheck();
		bool iterateProcessList(string);
		
};