#include <iostream>
#include <string>
#include <unistd.h>
#include "controller.h"
#include "logger.h"
#include "rules.h"
#include "settings.h"

using namespace std;

// name of the daemon
const char* daemon_name = "pmdaemon";

// logger instance (singleton-class)
Logger Logger::logger_Instance;

// settings object (contains all settings)
Settings* settings;

// settings file
const char* settings_file = "/srv/process_monitoring_daemon/settings.conf";

// rules object (contains all loaded rules)
Rules* rules;

// controller-object
Controller* controller;

// boolean which defines if daemon is running
bool running = true;

// check-interval value (wait-time)
int check_interval;

int main() {

	// initialize a singleton instance for the logger
	Logger::getInstance();
	Logger::setDaemonName(daemon_name);

	// load the configuration file
	settings = new Settings(settings_file);

	// terminate if configuration is broken
	if (!settings->configAvailable()){
		Logger::logError("Unable to load configuration! Stopping!");
		return 1;
	}

	// set the loglevel for the Logger
	Logger::setLogLevel(settings->getLogLevel());

	// set settings defined in settings-file
	check_interval = settings->getCheckInterval();

	// load rules
	rules = new Rules(settings->getRulesDir());

	Logger::logNotice("Starting "+std::string(daemon_name)+" monitoring ...");

	// initializing the controller
	controller = new Controller(settings);

	/* --- start check routine --- */
	while(running) {

		// run a check-cycle (exit if too many faulty checks)
		if (controller->checkProcesses() == false)
			return 1;

		// wait before next check
		sleep(check_interval);
	}
	/* --- end check routine --- */

	return 0;
}