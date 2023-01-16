#include "controller.h"

// UNUSED macro for hiding "unused parameter" warnings due to future TODO's
#define UNUSED(object) (void)(object)

Controller::Controller(const char* dname, Settings*& stngs) {

	Logger::logNotice("Initializing the controller ...");
	this->daemon_name = dname;
	this->settings = stngs;
	gethostname(this->hostname_buffer, sizeof(this->hostname_buffer));
	this->hostname = this->hostname_buffer;

	// load needed settings
	this->max_errors = stngs->getMaxErrors();
	this->default_cpu_trigger_threshold = stngs->getCpuTriggerThreshold();
	this->default_mem_trigger_threshold = stngs->getMemTriggerThreshold();
	this->default_checks_before_alert = stngs->getChecksBeforeAlert();
	this->state_trigger = stngs->getStateTrigger();
	this->checks_cooldown = stngs->getChecksCooldown();
	this->graylog_enabled = stngs->getGraylogEnabled();
	this->load_rules = stngs->getLoadRules();
	this->specific_rules_check_only = stngs->getSpecificRulesCheckOnly();
	this->term_cgroup_cleanup = stngs->getTermCgroupCleanup();

	if (this->graylog_enabled) {
		this->graylog_transport_method = stngs->getGraylogTransportMethod();
		this->graylog_port = stngs->getGraylogPort();
		this->graylog_fqdn = stngs->getGraylogFQDN();
		this->graylog_http_path = stngs->getGraylogHTTPPath();
		this->graylog_http_secure = stngs->getGraylogHTTPSecure();

		if (this->graylog_transport_method == "http") {

			// setup the curl environment
			// libcurl, see: https://curl.se/libcurl/c/curl_global_init.html
			curl_global_init(CURL_GLOBAL_ALL);

			if (this->graylog_http_secure)
				this->graylog_http_protocol_prefix = "https://";
			else
				this->graylog_http_protocol_prefix = "http://";
			this->graylog_final_url = this->graylog_http_protocol_prefix+this->graylog_fqdn+":"+to_string(this->graylog_port)+this->graylog_http_path;

			Logger::logInfo("Processes will be logged to "+graylog_final_url);
		}
	}

	// load rules if not deactivated in the settings
	if (load_rules) {
		if (!enableCgroupControllers())
			exit(EXIT_FAILURE);
		this->rulemanager = new RuleManager(this->daemon_name, stngs->getRulesDir());
	}

}

Controller::~Controller() {
	Logger::logInfo("Removing the controller ...");

	// cleanup of curl environment
	// libcurl, see: https://curl.se/libcurl/c/curl_global_cleanup.html
	curl_global_cleanup();
}

bool Controller::doCheck() {
	Logger::logDebug("[ Checking processes ... ]");
	try {

		// create a pipe to read from stdin and stderr
		FILE* pipe = popen(command.c_str(), "r");
		if (!pipe) {
			Logger::logError("Something went wrong during check! Exit!");
			throw 1;
		}

		// read output via input-buffer
		check_result = "";
		while (fgets(input_buffer.data(), 128, pipe) != NULL) {
			check_result += input_buffer.data();
		}

		// close pipe and check the return-code (throw error if command failed)
		auto return_code = pclose(pipe);
		if (return_code != 0)
			throw 1;

		// iterate over process-list and check processes
		if (!iterateProcessList(check_result))
			throw 1;

		// penalty-list needs to be cleaned
		if (!cleanupPenaltyList())
			throw 1;

	// catch if an error occurs during check-cycle
	} catch (...) {
		Logger::logError("Unable to run PS command!");
		error_checks++;

		// terminate if number of failed checks exceeded
		if (error_checks >= max_errors){
			Logger::logError("More than "+to_string(max_errors)+ " errors during checking! Exit!");
			Logger::logDebug(check_result);
			return false;
		}
	}
	return true;
}

bool Controller::enableCgroupControllers() {
	string cgrpsubcont_file = "/sys/fs/cgroup/cgroup.subtree_control";
	Logger::logInfo("Enabling needed cgroup2 controllers ...");

	if (Utils::writeToFile(cgrpsubcont_file, "+cpu +cpuset +memory +pids\n")) {
		Logger::logInfo("Done!");
		return true;
	} else {
		Logger::logError("Unable to enable controllers! Terminating.");
		return false;
	}

}

bool Controller::iterateProcessList(string cresult) {
	try {

		std::istringstream ps_output(cresult);

		while(getline(ps_output, ps_line)) {

			// retrieve the pid
			next_semi_colon_pos = ps_line.find(";");
			c_pid = ps_line.substr(0,next_semi_colon_pos);
			c_pid.erase(remove_if(c_pid.begin(), c_pid.end(), ::isspace), c_pid.end());
			ps_line = ps_line.substr(next_semi_colon_pos + 1);
			current_process.pid = stoi(c_pid);

			// retrieve the state
			next_semi_colon_pos = ps_line.find(";");
			c_state = ps_line.substr(0,next_semi_colon_pos);
			c_state.erase(remove_if(c_state.begin(), c_state.end(), ::isspace), c_state.end());
			ps_line = ps_line.substr(next_semi_colon_pos + 1);
			current_process.state = c_state;		

			// retrieve the user
			next_semi_colon_pos = ps_line.find(";");
			c_user = ps_line.substr(0,next_semi_colon_pos);
			c_user.erase(remove_if(c_user.begin(), c_user.end(), ::isspace), c_user.end());
			ps_line = ps_line.substr(next_semi_colon_pos + 1);
			current_process.user = c_user;

			// retrieve the pcpu
			next_semi_colon_pos = ps_line.find(";");
			c_pcpu = ps_line.substr(0,next_semi_colon_pos);
			c_pcpu.erase(remove_if(c_pcpu.begin(), c_pcpu.end(), ::isspace), c_pcpu.end());
			ps_line = ps_line.substr(next_semi_colon_pos + 1);
			current_process.pcpu = stod(c_pcpu);

			// retrieve the pmem
			next_semi_colon_pos = ps_line.find(";");
			c_pmem = ps_line.substr(0,next_semi_colon_pos);
			c_pmem.erase(remove_if(c_pmem.begin(), c_pmem.end(), ::isspace), c_pmem.end());
			ps_line = ps_line.substr(next_semi_colon_pos + 1);
			current_process.pmem = stod(c_pmem);

			// retrieve the command
			next_semi_colon_pos = ps_line.find("\n");
			c_command = ps_line.substr(0,next_semi_colon_pos);
			current_process.command = c_command;

			// check the current process
			checkProcess(&current_process);
		}

	} catch (...) {
		Logger::logError("Something went wrong while iterating the process list!");
		return false;
	}

	return true;
}

bool Controller::checkProcess(Process* process) {

	// check if a specific rule for the command is available if LOAD_RULES is enabled
	// Rule* specific_rule = nullptr;
	if (this->load_rules) {

		this->specific_rule = this->rulemanager->loadIfRuleExists(process->command);

		if (this->specific_rule) {

			if (Logger::getLogLevel() == "debug")
				Logger::logDebug("Checking '"+process->command+"' with PID '"+to_string(process->pid)+"' command '"+this->specific_rule->command+"' due to rule '"+this->specific_rule->rule_name+"'");

			// skip command if the NO_CHECK setting is set in rule
			if (this->specific_rule->no_check) {
				if (Logger::getLogLevel() == "debug")
					Logger::logDebug("Skipping '"+this->specific_rule->command+"' due to NO_CHECK in rule "+this->specific_rule->rule_name);
				return true;
			} else {
				this->cpu_trigger_threshold = &this->specific_rule->cpu_trigger_threshold;
				this->mem_trigger_threshold = &this->specific_rule->mem_trigger_threshold;
				this->checks_before_alert = &this->specific_rule->checks_before_alert;
				this->enable_limiting = &this->specific_rule->enable_limiting;
				this->send_process_files = this->specific_rule->send_process_files;
			}

		} else {

			// Needs to be set before dropping out if SPECIFIC_RULES_CHECK_ONLY is enabled
			this->cpu_trigger_threshold = &this->default_cpu_trigger_threshold;
			this->mem_trigger_threshold = &this->default_mem_trigger_threshold;
			this->checks_before_alert = &this->default_checks_before_alert;
			this->enable_limiting = &this->default_enable_limiting;
			this->send_process_files = true;

			// do not check processes if SPECIFIC_RULES_CHECK_ONLY is enabled
			if (this->specific_rules_check_only) {
				return true;
			}

		}
	}

	if (process->pcpu > *this->cpu_trigger_threshold) {
		Logger::logDebug("Process with PID "+to_string(process->pid)+ " has a load of "+to_string(process->pcpu));
		return checkPenaltyList(process, "cpu");
	}

	if (process->pmem > *this->mem_trigger_threshold) {
		Logger::logDebug("Process with PID "+to_string(process->pid)+ " uses "+to_string(process->pmem)+" of RAM");
		return checkPenaltyList(process, "mem");
	}

	if (this->state_trigger) {
		if (process->state == "Z") {
			Logger::logDebug("Process with PID "+to_string(process->pid)+ " state changed to ZOMBIE ("+process->state+")");
			return checkPenaltyList(process, "zombie");
		}

		if (process->state == "D" || process->state == "D+") {
			Logger::logDebug("Process with PID "+to_string(process->pid)+ " state changed to UNINTERRUPTIBLE SLEEP ("+process->state+")");
			return checkPenaltyList(process, "dstate");
		}
	}

	return true;

}

// check if PID is on penalty-list, if not add it
bool Controller::checkPenaltyList(Process* process, string penalty_cause) {

	// if pid is in penalty-list raise counter
	it = penalty_list.find(process->pid);
	if (it != penalty_list.end() && it->second.penalty_cause == penalty_cause) {
		Logger::logDebug("Process with PID "+to_string(process->pid)+" already on penalty-list.");
		if (it->second.in_cgroup == false) {
			it->second.penalty_counter++;
		}

		// alert if not already alerted
		if (it->second.penalty_counter >= *this->checks_before_alert && it->second.alerted == false && it->second.in_cgroup == false) {

			if (this->send_process_files) {
				graylogAlert(collectProcessInfo(process, penalty_cause));
			}
			it->second.alerted = true;

			if (*this->enable_limiting) {
				if(doLimit(process)) {
					it->second.in_cgroup = true;
					Logger::logInfo("["+this->specific_rule->rule_name+"] Added PID "+to_string(process->pid)+" to cgroup "+this->specific_rule->cgroup_name);
					graylogLimitInfo(process);

					// if PID_KILL_ENABLED is set to 1 simply kill the process
					if (this->specific_rule->pid_kill_enabled) {
						if (!Utils::writeToFile(this->specific_rule->cgroup_kill_file, "1")) {
							Logger::logError("Something went wrong while modifying "+this->specific_rule->cgroup_kill_file);
							return false;
						}
					}

				} else {
					Logger::logError("["+this->specific_rule->rule_name+"] Unable to add PID "+to_string(process->pid)+" to cgroup "+this->specific_rule->cgroup_name);
				}
			}
		}

		// pid is already in cgroup, therefore only discard pid from penalty_list if cgroup is no longer present
		else if (it->second.in_cgroup) {
			if (!fs::exists(it->second.cgroup_name)) {
				penalty_list.erase(it);
				it = penalty_list.end();
			}
			return true;
		}

		// decrease cooldown-counter if already alerted
		else {
			// check if cooldown-counter not 0, otherwise remove pid from list
			if (it->second.penalty_cause != "zombie" && it->second.penalty_cause != "dstate") {
				if (it->second.cooldown_counter > 0 && it->second.alerted == true)
					it->second.cooldown_counter--;
				else if (it->second.cooldown_counter <= 0)
					penalty_list.erase(it);
			}
		}
	}

	// add the pid to the penalty-list if not found
	else {

		PenaltyListItem penalty_pid;
		penalty_pid.pid = process->pid;
		penalty_pid.penalty_counter = 1;
		penalty_pid.cooldown_counter = checks_cooldown;
		penalty_pid.penalty_cause = penalty_cause;
		if (*this->enable_limiting) {
			string cgroup_name = this->specific_rule->cgroup_root_dir;
			cgroup_name += "/pid-";
			cgroup_name += to_string(process->pid);
			penalty_pid.cgroup_name = cgroup_name;
		} else { penalty_pid.cgroup_name = "none"; }
		penalty_pid.limited = *this->enable_limiting;

		penalty_list[process->pid] = penalty_pid;
		Logger::logDebug("Added "+to_string(process->pid)+" to penalty-list due to "+penalty_cause+".");
	}
	return true;
}

bool Controller::cleanupPenaltyList() {

	if (!penalty_list.empty()) {

		it = penalty_list.begin();
		while (it != penalty_list.end()) {

			std::string pid = to_string(it->first);

			if (fs::exists("/proc/"+to_string(it->first))) {
				it++;
			} else {
				it = penalty_list.find(it->first);

				if (it->second.limited) {
					removeCgroup(it->second.cgroup_name);
				}

				Logger::logInfo("Removing PID "+pid+" from penalty-list");
				penalty_list.erase(it);
				it = penalty_list.end();
				break;
			}
		}
	}
	return true;
}

bool Controller::addPidToCgroup(string* cgroup_parent_group, int* pid) {

	string cgroup = *cgroup_parent_group;
	cgroup += "/pid-";
	cgroup += to_string(*pid);

	string cgroup_procs_file = cgroup;
	cgroup_procs_file += "/cgroup.procs";

	if (!fs::exists(cgroup.c_str())) {
		createCgroup(cgroup_parent_group, pid);
	}

	return Utils::writeToFile(cgroup_procs_file, to_string(*pid));

}

bool Controller::checkIfCgroupEmpty(string* cgroup_parent_group, int* pid) {

	string proc_file_name = *cgroup_parent_group;
	proc_file_name += "/pid-";
	proc_file_name += to_string(*pid);
	proc_file_name += "/pids.current";

	fstream proc_file;
	proc_file.open(proc_file_name, ios::in);

	if (proc_file.is_open()) {
		string line;
		getline(proc_file, line);
		proc_file.close();

		if (stoi(line) == 0)
			return true;
		else
			return false;

	} else {
		Logger::logError("Unable to read file ");
		proc_file.close();
		return false;
	}

}

bool Controller::cleanupCgroups() {

	Logger::logNotice("Received SIGUSR1 signal, performing cgroup cleanup");

	bool cleanup_successful = true;

	unordered_map<int,PenaltyListItem>::iterator delete_iterator;

	while (!this->penalty_list.empty()) {
		delete_iterator = this->penalty_list.begin();
		Logger::logInfo("Removing "+to_string(delete_iterator->first)+" from penalty_list.");
		if (!removePidFromCgroup(delete_iterator->first)) {
			cleanup_successful = false;
			break;
		}
		if (!removeCgroup(delete_iterator->second.cgroup_name)) {
			cleanup_successful = false;
			break;
		}
		this->penalty_list.erase(delete_iterator);
	}

	if (cleanup_successful) {
		Logger::logInfo("Cleanup of penalty_list and cgroups successful!");
	}
	else {
		Logger::logError("Something went wrong during cleanupCgroup!");
	}

	cleanup_successful = this->rulemanager->removeCgroupRules();

	return cleanup_successful;
}

bool Controller::createCgroup(string* cgroup_parent_group, int* pid) {

	string cgroup = *cgroup_parent_group;
	cgroup += "/pid-";
	cgroup += to_string(*pid);

	if (mkdir(cgroup.c_str(), 0755) != -1) {
		Logger::logInfo("Created cgroup "+cgroup);
		return true;
	}
	else {
		Logger::logError("Unable to create cgroup "+cgroup);
		return false;
	}

}

bool Controller::doLimit(Process* process) {
	return addPidToCgroup(&this->specific_rule->cgroup_root_dir, &process->pid);
}

bool Controller::removeCgroup(string cgroup) {

	if (std::filesystem::remove(cgroup)) {
		Logger::logInfo("Removed cgroup "+cgroup);
		return true;
	}
	else {
		Logger::logError("Unable to remove cgroup "+cgroup);
		return false;
	}

}

bool Controller::removePidFromCgroup(int pid) {
	return Utils::writeToFile(main_cgroup_procs_file, to_string(pid));
}

// collect information about the process
Controller::ProcessInfo Controller::collectProcessInfo(Process* process, string penalty_cause) {
	ProcessInfo process_info;
	process_info._cause = penalty_cause;
	process_info._pid = process->pid;
	process_info._state = process->state;
	process_info._pcpu = process->pcpu;
	process_info._pmem = process->pmem;
	process_info._command = process->command;

	// read /proc/<pid>/status
	process_info._status = readProcFile("status", &process->pid);

	// read /proc/<pid>/io
	process_info._io = readProcFile("io", &process->pid);

	// read /proc/<pid>/limits
	process_info._limits = readProcFile("limits", &process->pid);

	// read /proc/<pid>/syscall
	process_info._syscall = readProcFile("syscall", &process->pid);

	// read /proc/<pid>/cgroup
	process_info._cgroup = readProcFile("cgroup", &process->pid);

	return process_info;
}

// used to read files from pseudo-filesystem from /proc/<pid>/ - see https://linux.die.net/man/5/proc
string Controller::readProcFile(string filename, int* pid) {
	try {
		string proc_file_content;
		std::ifstream proc_file("/proc/"+to_string(*pid)+"/"+filename);
		if ( proc_file.is_open() ) {
			string line;
			while(getline(proc_file, line)){
				proc_file_content += line+"\n";
			}
		}
		proc_file.close();
		return proc_file_content;
	} catch (...) {
		Logger::logError("Unable to read from /proc/"+to_string(*pid)+"/"+filename);
		return "no data";
	}
}

void Controller::graylogAlert(ProcessInfo process_info) {

	if (graylog_enabled) {
		if (graylog_transport_method == "http") {
			graylogHTTPAlert(process_info);
		}
		else if (graylog_transport_method == "udp") {
			graylogUDPAlert(process_info);
		}
		else if (graylog_transport_method == "tcp") {
			graylogTCPAlert(process_info);
		}
	}
}

void Controller::graylogLimitInfo(Process* process) {

	if (graylog_enabled) {
		if (graylog_transport_method == "http") {
			graylogHTTPlimitInfo(process);
		}
		else if (graylog_transport_method == "udp") {
			graylogUDPlimitInfo(process);
		}
		else if (graylog_transport_method == "tcp") {
			graylogTCPlimitInfo(process);
		}
	}
}

// define which data should be included into the json_data
void Controller::graylogHTTPAlert(ProcessInfo process_info) {

	// remove trailing zeroes on measured values
	sprintf(limit_pcpu, "%.2f", process_info._pcpu);
	sprintf(limit_pmem, "%.2f", process_info._pmem);

	string short_message;
	if (process_info._cause == "cpu")
		short_message = "[ ALERT ] Process with PID "+to_string(process_info._pid)+" produces a load of "+limit_pcpu+"!";
	else if (process_info._cause == "mem")
		short_message = "[ ALERT ] Process with PID "+to_string(process_info._pid)+" is using "+limit_pmem+" of RAM!";
	else if (process_info._cause == "zombie")
		short_message = "[ ALERT ] Process with PID "+to_string(process_info._pid)+" has changed the state to ZOMBIE!";
	else if (process_info._cause == "dstate")
		short_message = "[ ALERT ] Process with PID "+to_string(process_info._pid)+" has changed the state to UNINTERRUPTIBLE SLEEP!";
	else
		short_message = "[ ERROR ] No short-message!";

	// the json-body which will be send
	string json_data = "{"
		"\"version\": \""+to_string(graylog_message_version)+"\","
		"\"host\": \""+std::string(hostname)+"\","
		"\"short_message\": \""+short_message+"\","
		"\"level\": "+to_string(graylog_message_level)+","
		"\"_pid\": "+to_string(process_info._pid)+","
		"\"_pcpu\": "+limit_pcpu+","
		"\"_pmem\": "+to_string(process_info._pmem)+","
		"\"_status\": \""+process_info._status+"\","
		"\"_io\": \""+process_info._io+"\","
		"\"_limits\": \""+process_info._limits+"\","
		"\"_syscall\": \""+process_info._syscall+"\","
		"\"_cgroup\": \""+process_info._cgroup+"\","
		"\"_cause\": \""+process_info._cause+"\","
		"\"_state\": \""+process_info._state+"\","
		"\"_command\": \""+process_info._command+"\"" 
		"}";

	// send it via curl library command
	curlPostJSON(json_data.c_str());
}



void Controller::graylogUDPAlert(ProcessInfo process_info) {
	// TODO
	UNUSED(process_info);
}

void Controller::graylogTCPAlert(ProcessInfo process_info) {
	// TODO
	UNUSED(process_info);
}

void Controller::graylogHTTPlimitInfo(Process* process) {

	// the json-body which will be send
	string short_message = "[ LIMIT ] Process with PID "+to_string(process->pid)+" was added to cgroup!";

	string json_data = "{"
		"\"version\": \""+to_string(graylog_message_version)+"\","
		"\"host\": \""+std::string(hostname)+"\","
		"\"short_message\": \""+short_message+"\","
		"\"level\": "+to_string(graylog_message_level)+","
		"\"_pid\": "+to_string(process->pid)+","
		"\"_user\": \""+process->user+"\","
		"\"_state\": \""+process->state+"\","
		"\"_cgroup\": \""+readProcFile("cgroup", &process->pid)+"\","
		"\"_command\": \""+process->command+"\"" 
		"}";

	// send it via curl library command
	curlPostJSON(json_data.c_str());

}

void Controller::graylogUDPlimitInfo(Process* process) {
	// TODO
	UNUSED(process);
}

void Controller::graylogTCPlimitInfo(Process* process) {
	// TODO
	UNUSED(process);
}

bool Controller::curlPostJSON(const char* json_data) {
	// create a curl handle
	// libcurl, see: https://curl.se/libcurl/c/curl_easy_init.html
	curl = curl_easy_init();

	if (curl) {

		// headers with mime-type for the curl posts
		// libcurl, see: https://curl.se/libcurl/c/curl_slist_append.html
		struct curl_slist *headers = NULL;
		headers = curl_slist_append(headers, "Accept: application/json");
		headers = curl_slist_append(headers, "Content-Type: application/json");
		headers = curl_slist_append(headers, "charset: utf-8");

		// set all needed options for the curl post
		// libcurl, see: https://curl.se/libcurl/c/curl_easy_setopt.html
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_URL, graylog_final_url.c_str());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);

		// send the post and retrieve result
		// libcurl, see: https://curl.se/libcurl/c/curl_easy_perform.html
		curl_result = curl_easy_perform(curl);

		// check if the post was successful
		if (curl_result != CURLE_OK) {
			Logger::logError("Unable to perform a POST request to "+graylog_final_url);
			fprintf(stderr, "libcurl: Unable to post: %s\n", curl_easy_strerror(curl_result));
			return false;
		}

		// cleanup after post
		// libcurl, see: https://curl.se/libcurl/c/curl_easy_cleanup.html
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);
	}

	return true;
}

bool Controller::terminate() {

	Logger::logNotice("Shutting down the controller ...");

	if(this->term_cgroup_cleanup) {
		Logger::logInfo("Cleanup of created Cgroups");
		return cleanupCgroups();
	}
	else {
		return true;
	}

	return true;
}

void Controller::showInformation() {

	Logger::logInfo("********************");
	Logger::logInfo("*   CurrentRules   *");
	Logger::logInfo("********************");
	rulemanager->showRules();

	// show the current penalty-list (debug-only)
	Logger::logInfo("********************");
	Logger::logInfo("* PenaltyListItems *");
	Logger::logInfo("********************");
	for (it = this->penalty_list.begin(); it != this->penalty_list.end(); ++it) {
		std::stringstream penalty_list_item;
		penalty_list_item
			<< " pid: " << to_string(it->second.pid)
			<< " penalty_cause: " << it->second.penalty_cause
			<< " penalty_counter: " << to_string(it->second.penalty_counter)
			<< " cooldown_counter: " << to_string(it->second.cooldown_counter)
			<< " alerted: " << it->second.alerted
			<< " limited: " << it->second.limited
			<< " in_cgroup: " << it->second.in_cgroup
			<< " cgroup_name: " << it->second.cgroup_name;
		Logger::logInfo(penalty_list_item.str());
	}

}