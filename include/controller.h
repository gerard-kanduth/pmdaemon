#include <cctype>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <unistd.h>
#include "logger.h"
#include "rules.h"
#include "settings.h"

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
			string comand;
		} current_process;

		// penalty list-item
		struct PenaltyListItem {
			int pid;
			int penalty_counter;
			int cooldown_counter;
			bool alerted = false;
		};

		// penalty list
		map<int,PenaltyListItem> penalty_list;
		map<int,PenaltyListItem>::iterator it;

		// settings object (contains all settings)
		Settings* settings;

		// rules object (contains all loaded rules)
		Rules* rules;

		// the comand which will be constantly checked "2>&1" used to get stderr
		string command = "ps -e -ww --no-headers -o %p\\; -o stat -o \\;%U -o \\;%C\\; -o %mem -o \\;%a 2>&1";

		// additional buffer and pipe for reading output
		array<char, 128> input_buffer;
		string check_result;
		
		// number of failed checks
		int error_checks = 0;

		// max number of fails before daemon terminates
		int max_errors;
		
		// helper variables
		size_t next_semi_colon_pos;
		string ps_line;
		string c_pid;
		string c_state;
		string c_user;
		string c_pcpu;
		string c_pmem;
		string c_comand;

		// default limits (if no specific rule is set for process)
		bool zombie_trigger;
		double cpu_trigger_threshold;
		double mem_trigger_threshold;
		int checks_cooldown;
		int checks_before_alert;

	public:
		Controller(Settings*&);
		bool checkProcess(Process*);
		void doAlert(Process*);
		bool doCheck();
		bool iterateProcessList(string);
		
};