#include <syslog.h>
#include <iostream>
#include <string>

#ifndef LOGGER
#define LOGGER

using namespace std;

// has to be singleton-class since used globally in all classes
class Logger {

	private:

		static Logger logger_Instance;
		string log_level;
		string log_message;
		const char *daemon_name;

		// no use of constructor - class is singleton
		Logger(){}
		void instanceSetLogLevel(string);
		void instanceLogInfo(string);
		void instanceLogNotice(string);
		void instanceLogDebug(string);
		void instanceLogError(string);

	public:

		// only instance can be created
		static Logger& getInstance() {
			return logger_Instance;
		}
		static string getLogLevel();
		static void setLogLevel(string);
		static void logInfo(string);
		static void logNotice(string);
		static void logDebug(string);
		static void logError(string);
		static void setDaemonName(const char*);
};

#endif