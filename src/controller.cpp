#include "controller.h"

Controller::Controller(Settings*& settings) {
	Logger::logInfo("Initializing the controller ...");
	this->settings = settings;

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
			if (graylog_http_secure)
				Logger::logInfo("Processes will be logged to https://"+graylog_fqdn+":"+to_string(graylog_port)+graylog_http_path);
			else
				Logger::logInfo("Processes will be logged to http://"+graylog_fqdn+":"+to_string(graylog_port)+graylog_http_path);
		}
	}

	// load rules
	rules = new Rules(settings->getRulesDir());
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

		// close pipe and check the return-code (throw error if comand failed)
		auto return_code = pclose(pipe);
		if (return_code != 0)
			throw 1;

		// iterate over process-list and check processes
		if (iterateProcessList(check_result) == false)
			throw 1;

	// catch if an error occurs during check-cycle
	} catch (...) {
		Logger::logError("Unable to run PS comand!");
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

			// retrieve the comand
			next_semi_colon_pos = ps_line.find("\n");
			c_comand = ps_line.substr(0,next_semi_colon_pos);
			current_process.comand = c_comand;

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
	if (process->pcpu > this->cpu_trigger_threshold) {
		Logger::logDebug("Process with PID "+to_string(process->pid)+ " has a load of "+to_string(process->pcpu));

		// if pid is in penalty-list raise counter
		it = penalty_list.find(process->pid);
		if (it != penalty_list.end()) {
			Logger::logDebug("Process with PID "+to_string(process->pid)+ " already on penalty-list.");
			it->second.penalty_counter++;

			// alert if not already alerted
			if (it->second.penalty_counter >= checks_before_alert && it->second.alerted == false ) {
				doAlert(process);
				it->second.alerted = true;
			}
			// decrease cooldown-counter if already alerted
			else {
				// check if cooldown-counter not 0, otherwise remove pid from list
				if (it->second.cooldown_counter > 0 && it->second.alerted == true)
					it->second.cooldown_counter--;
				else if (it->second.cooldown_counter <= 0)
					penalty_list.erase(it);
			}
		}
		// add the pid to the penalty-list if not found
		else {
			PenaltyListItem penalty_pid;
			penalty_pid.pid = process->pid;
			penalty_pid.penalty_counter = 1;
			penalty_pid.cooldown_counter = checks_cooldown;
			penalty_list[process->pid] = penalty_pid;
			Logger::logDebug("Added "+to_string(process->pid)+" to penalty-list.");
		}
	}
	return true;
}

void Controller::doAlert(Process* process) {
	cout << "ALERT: "+to_string(process->pid)+" - "+process->comand+"\n";
	if (graylog_enabled) {
		if (graylog_transport_method == "http") {
			graylogHTTPAlert(process);
		}
		else if (graylog_transport_method == "udp") {
			graylogUDPAlert(process);
		}
		else if (graylog_transport_method == "tcp") {
			graylogTCPAlert(process);
		}
	}
}

void Controller::graylogHTTPAlert(Process* process) {
	
}

void Controller::graylogUDPAlert(Process* process) {
	// TODO
}

void Controller::graylogTCPAlert(Process* process) {
	// TODO
}