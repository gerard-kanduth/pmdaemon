#include <csignal>
#include <iostream>
#include <string>
#include <unistd.h>
#include "controller.h"
#include "logger.h"
#include "settings.h"
#include "utils.h"

using namespace std;

// name of the daemon
const char* daemon_name = "pmdaemon";

// logger instance (singleton-class)
Logger Logger::logger_Instance;

// controller-object
Controller* controller = nullptr;

// settings object (contains all settings)
Settings* settings = nullptr;

// settings file
const char* settings_file = "/srv/process_monitoring_daemon/settings.conf";

// boolean which defines if daemon is running
bool running = true;

// check-interval value (wait-time)
int check_interval;

// signal handler (needed to remove all created cgroups and for debug purpose)
void signalHandler(int signal) {

	switch (signal)  {

		// SIGTERM signal
		case 15:
			if (controller->terminate()) {exit(0);} else {exit(1);}
			break;

		// SIGABRT signal
		case 6:
			if (controller->terminate()) {exit(0);} else {exit(1);}
			break;

		// SIGUSR1 signal
		case 10:
			controller->cleanupCgroups();
			break;

		// SIGUSR2 signal
		case 12:
			controller->showInformation();
			break;

		// unknown signals
		default:
			cerr << daemon_name << " received unknown signal (" << to_string(signal) << ")!";
			break;

	}

}

// main, this is where all the magic happens
int main() {

    // register all needed signals to the signal handler
    signal(SIGTERM, signalHandler);
	signal(SIGABRT, signalHandler);
	signal(SIGUSR1, signalHandler);
	signal(SIGUSR2, signalHandler);

	// initialize a singleton instance for the logger
	Logger::getInstance();
	Logger::setDaemonName(daemon_name);

	// load the configuration file
	settings = new Settings(settings_file);

	// terminate if configuration is broken or not available
	if (!settings->configAvailable()){
		Logger::logError("Unable to load configuration! Stopping!");
		return 1;
	}

	// set the loglevel for the Logger
	Logger::setLogLevel(settings->getLogLevel());

	// set settings defined in settings-file
	check_interval = settings->getCheckInterval();

	// initializing the controller
	controller = new Controller(daemon_name, settings);

	/* --- start check routine --- */
	Logger::logNotice("Starting "+std::string(daemon_name)+" monitoring ...");
	while(running) {

		// run a check-cycle (exit if too many faulty checks)
		if (controller->doCheck() == false)
			return 1;

		// wait before next check
		sleep(check_interval);
	}
	/* --- end check routine --- */

	return 0;

}