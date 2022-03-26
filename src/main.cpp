#include <syslog.h>
#include <iostream>
using namespace std;

// name of the daemon
const char *daemon_name = "pmdaemon";

// set the log-level


int main() {
	//setlogmask(LOG_UPTO(LOG_NOTICE));
	openlog(daemon_name, 0, LOG_USER);
	syslog(LOG_NOTICE, "%s was started!", daemon_name);
	cout << "Hello, World!" << endl; // This prints Hello, World!
	syslog(LOG_INFO, "Hello World");
	closelog();
	return 0;
}