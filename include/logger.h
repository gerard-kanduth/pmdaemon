#include <syslog.h>
#include <iostream>
#include <string>
#ifndef LOGGER
#define LOGGER

using namespace std;

class Logger {
	private:
		Logger(){}
		static Logger logger_Instance;
		string loglevel;
		const char *daemon_name;

	public:
		static Logger& getInstance() {
			return logger_Instance;
		}
		void setLogLevel(string);
		void logInfo(string);
		void logNotice(string);
		void logDebug(string);
		void logError(string);
};
#endif