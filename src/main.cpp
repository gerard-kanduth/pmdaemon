#include <iostream>
#include <string>
#include "settings.h"
#include "rules.h"
#include "logger.h"

using namespace std;

// name of the daemon
const char *daemon_name = "pmdaemon";

// logger instance (singleton-class)
Logger Logger::logger_Instance;

// settings object (contains all settings)
Settings *settings;

// rules object (contains all loaded rules)
Rules *rules;

int main() {

	// initialize a singleton instance for the logger
	Logger::getInstance();

	// load the configuration file
	settings = new Settings("/srv/process_monitoring_daemon/settings.conf");

	// terminate if configuration is broken
	if (!settings->configAvailable()){
		Logger::getInstance().logError("Unable to load configuration! Stopping!");
		return 1;
	}

	// load rules
	rules = new Rules(settings->getRulesDir());

	Logger::getInstance().logInfo("TEST");



	return 0;
}