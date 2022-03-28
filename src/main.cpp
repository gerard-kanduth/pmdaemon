#include <syslog.h>
#include <iostream>
#include <string>
#include "settings.h"

using namespace std;

// name of the daemon
const char *daemon_name = "pmdaemon";

// settings object
Settings *settings;

int main() {
	openlog(daemon_name, 0, LOG_USER);
	syslog(LOG_NOTICE, "Process Monitoring Daemon started!");
	
	// load the configuration file
	settings = new Settings("/srv/process_monitoring_daemon/settings.conf", daemon_name);
	
	// terminate if configuration is broken
	if (!settings->configAvailable()){
		syslog(LOG_PERROR, "Unable to load configuration! Stopping!");
		closelog();
		return 1;
	}
	
	if (settings->getLogLevel() == "info") {
		syslog(LOG_INFO, "Hello World");
	}
	syslog(LOG_NOTICE, "TEST");
	closelog();
	return 0;
}