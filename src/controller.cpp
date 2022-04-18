#include "controller.h"

Controller::Controller(Settings*& settings) {
	Logger::logInfo("Initializing the controller ...");
	this->settings = settings;

	// load needed settings
	max_errors = settings->getMaxErrors();
	cpu_trigger_threshold = settings->getCpuTriggerThreshold();
	mem_trigger_threshold = settings->getMemTriggerThreshold();
	zombie_trigger = settings->getZombieTrigger();

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
			checkProcess(current_process);
		}
	} catch (...) {
		Logger::logError("Something went wrong while iterating the process-list!");
		return false;
	}
	return true;
}

bool Controller::checkProcess(Process process) {
	if (process.pcpu > this->cpu_trigger_threshold) {
		cout << "ALARM!!! "+process.comand+ " has a load of "+to_string(process.pcpu) << "\n";
	}
	// cout << process.pid << "\n";
	// cout << process.state << "\n";
	// cout << process.user << "\n";
	// cout << to_string(process.pcpu) << "\n";
	// cout << to_string(process.pmem) << "\n";
	// cout << process.comand << "\n";
	return true;
}

