#include "controller.h"

Controller::Controller(Settings*& settings) {
	Logger::logInfo("Initializing the controller ...");
	this->settings = settings;
	gethostname(this->hostname_buffer, sizeof(this->hostname_buffer));
	this->hostname = this->hostname_buffer;

	// load needed settings
	max_errors = settings->getMaxErrors();
	cpu_trigger_threshold = settings->getCpuTriggerThreshold();
	mem_trigger_threshold = settings->getMemTriggerThreshold();
	zombie_trigger = settings->getZombieTrigger();
	checks_cooldown = settings->getChecksCooldown();
	checks_before_alert = settings->getChecksBeforeAlert();
	graylog_enabled = settings->getGraylogEnabled();

	if (graylog_enabled) {
		graylog_transport_method = settings->getGraylogTransportMethod();
		graylog_port = settings->getGraylogPort();
		graylog_fqdn = settings->getGraylogFQDN();
		graylog_http_path = settings->getGraylogHTTPPath();
		graylog_http_secure = settings->getGraylogHTTPSecure();

		if (graylog_transport_method == "http") {

			// setup the curl environment
			// libcurl, see: https://curl.se/libcurl/c/curl_global_init.html
			curl_global_init(CURL_GLOBAL_ALL);

			if (graylog_http_secure)
				graylog_http_protocol_prefix = "https://";
			else
				graylog_http_protocol_prefix = "http://";
			graylog_final_url = graylog_http_protocol_prefix+graylog_fqdn+":"+to_string(graylog_port)+graylog_http_path;

			Logger::logInfo("Processes will be logged to "+graylog_final_url);
		}
	}

	// load rules
	rules = new Rules(settings->getRulesDir());

}

Controller::~Controller() {
	Logger::logInfo("Removing the controller ...");

	// cleanup of curl environment
	// libcurl, see: https://curl.se/libcurl/c/curl_global_cleanup.html
	curl_global_cleanup();
}

bool Controller::doCheck() {
	Logger::logDebug("Checking processes ...");
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
		if (iterateProcessList(check_result) == false)
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

bool Controller::iterateProcessList(string check_result) {
	try {
		std::istringstream ps_output(check_result);
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
		Logger::logError("Something went wrong while iterating the process-list!");
		return false;
	}

	// show the current penalty-list (debug-only)
	if (Logger::getLogLevel() == "debug") {
		for (it=penalty_list.begin(); it!=penalty_list.end(); ++it)
			Logger::logDebug("PID: "+to_string(it->second.pid)+" Penalty_Counter: "+to_string(it->second.penalty_counter)+" Cooldown_Counter: "+to_string(it->second.cooldown_counter));
	}
	return true;
}

bool Controller::checkProcess(Process* process) {

	// TODO
	/* Override threshold with specific rule for this specific process (if available) */

	if (process->pcpu > this->cpu_trigger_threshold) {
		Logger::logDebug("Process with PID "+to_string(process->pid)+ " has a load of "+to_string(process->pcpu));
		return checkPenaltyList(process, "cpu");
	}

	if (process->pmem > this->mem_trigger_threshold) {
		Logger::logDebug("Process with PID "+to_string(process->pid)+ " uses "+to_string(process->pmem)+" of RAM");
		return checkPenaltyList(process, "mem");
	}

	if (process->state == "Z") {
		Logger::logDebug("Process with PID "+to_string(process->pid)+ " has changed it's state to ZOMBIE");
		return checkPenaltyList(process, "zombie");
	}

	return true;

}

// check if PID is on penalty-list, if not add it
bool Controller::checkPenaltyList(Process* process, string penalty_cause) {
	// if pid is in penalty-list raise counter
	it = penalty_list.find(process->pid);
	if (it != penalty_list.end() && it->second.penalty_cause == penalty_cause) {
		Logger::logDebug("Process with PID "+to_string(process->pid)+" already on penalty-list.");
		it->second.penalty_counter++;

		// alert if not already alerted
		if (it->second.penalty_counter >= checks_before_alert && it->second.alerted == false ) {
			doAlert(collectProcessInfo(process, penalty_cause));
			it->second.alerted = true;
		}
		// decrease cooldown-counter if already alerted
		else {
			// check if cooldown-counter not 0, otherwise remove pid from list
			if (it->second.penalty_cause != "zombie") {
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
		penalty_list[process->pid] = penalty_pid;
		Logger::logDebug("Added "+to_string(process->pid)+" to penalty-list due to "+penalty_cause+".");
	}
	return true;
}

// collect information about the process
Controller::ProcessInfo Controller::collectProcessInfo(Process* process, string penalty_cause) {
	ProcessInfo process_info;
	process_info._cause = penalty_cause;
	process_info._pid = process->pid;
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

// used to read pseudo-files from /proc/<pid>/ - see https://linux.die.net/man/5/proc
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

void Controller::doAlert(ProcessInfo process_info) {
	cout << "[[ ALERT ]] PID: "+to_string(process_info._pid)+" COMMAND: "+process_info._command+" CAUSE: "+process_info._cause+"\n";
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

// define which data should be included into the json_data
void Controller::graylogHTTPAlert(ProcessInfo process_info) {

	string short_message;
	if (process_info._cause == "cpu")
		short_message = "Process with PID "+to_string(process_info._pid)+" produces a load of "+to_string(process_info._pcpu)+"!";
	else if (process_info._cause == "mem")
		short_message = "Process with PID "+to_string(process_info._pid)+" is using "+to_string(process_info._pmem)+" of RAM!";
	else if (process_info._cause == "zombie")
		short_message = "Process with PID "+to_string(process_info._pid)+" has changed the state to ZOMBIE!";
	else
		short_message = "No short-message!";

	string json_data = "{ "
		"\"version\": \""+to_string(graylog_message_version)+"\", "
		"\"host\": \""+std::string(hostname)+"\", "
		"\"short_message\": \""+short_message+"\", "
		"\"level\": "+to_string(graylog_message_level)+", "
		"\"_pid\": "+to_string(process_info._pid)+", "
		"\"_pcpu\": "+to_string(process_info._pcpu)+", "
		"\"_pmem\": "+to_string(process_info._pmem)+", "
		"\"_status\": \""+process_info._status+"\", "
		"\"_io\": \""+process_info._io+"\", "
		"\"_limits\": \""+process_info._limits+"\", "
		"\"_syscall\": \""+process_info._syscall+"\", "
		"\"_cgroup\": \""+process_info._cgroup+"\", "
		"\"_cause\": \""+process_info._cause+"\", "
		"\"_command\": \""+process_info._command+"\" }";
	curlPostJSON(json_data.c_str());
}

void Controller::graylogUDPAlert(ProcessInfo process_info) {
	// TODO
}

void Controller::graylogTCPAlert(ProcessInfo process_info) {
	// TODO
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
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 20);
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