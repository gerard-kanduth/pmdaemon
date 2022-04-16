#include <iostream>
#include <string>
#include <unistd.h>

#include "settings.h"
#include "rules.h"
#include "logger.h"

using namespace std;

// name of the daemon
const char* daemon_name = "pmdaemon";

// the comand which will be constantly checked "2>&1" used to get stderr
std::string command("ps -L -e -w -o pid=PID,pgid=PGID,uname=USER,psr=CORE,pcpu=CPU_PERCENT,cputime=CPU_TIME,pmem=MEM_PERCENT,rss=RSS,vsz=VSZ,stime=STIME,pri=PRIORITY,f=FLAG,state=STATE,wchan:30=KERNEL_FUNCTION,command=COMMAND 2>&1");

// additional buffer and pipe for reading output
std::array<char, 128> input_buffer;
std::string check_result;

// logger instance (singleton-class)
Logger Logger::logger_Instance;

// settings object (contains all settings)
Settings *settings;

// rules object (contains all loaded rules)
Rules *rules;

// boolean which defines if daemon is running
bool running = true;

// check-interval value (wait-time)
int check_interval;

// number of failed checks
int error_checks = 0;

// max number of fails before daemon terminates
int max_errors;

int main() {

	// initialize a singleton instance for the logger
	Logger::getInstance();
	Logger::setDaemonName(daemon_name);

	// load the configuration file
	settings = new Settings("/srv/process_monitoring_daemon/settings.conf");

	// terminate if configuration is broken
	if (!settings->configAvailable()){
		Logger::logError("Unable to load configuration! Stopping!");
		return 1;
	}

	// set the loglevel for the Logger
	Logger::setLogLevel(settings->getLogLevel());

	// set settings defined in settings-file
	check_interval = settings->getCheckInterval();
	max_errors = settings->getMaxErrors();

	// load rules
	rules = new Rules(settings->getRulesDir());

	Logger::logNotice("Starting "+std::string(daemon_name)+" monitoring ...");

	// the big loop
	while(running) {
		Logger::logDebug("Checking processes ...");

		/* --- start check routine --- */
		try {

			// create a pipe to read from stdin and stderr
			FILE* pipe = popen(command.c_str(), "r");
			if (!pipe)
			{
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
			Logger::logDebug(check_result);

		// catch if an error occurs during check-cycle
		} catch (...) {
			Logger::logError("Unable to run PS comand!");
			error_checks++;

			// terminate if nunmber of failed checks exceeded
			if (error_checks >= max_errors){
				Logger::logError("More than "+to_string(max_errors)+ " errors during checking! Exit!");
				Logger::logDebug(check_result);
				return 1;
			}
		}
		/* --- end check routine --- */

		// wait before next check
		sleep(check_interval);
	}

	return 0;
}