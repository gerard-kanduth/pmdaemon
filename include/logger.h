#ifndef LOGGER
#define LOGGER

#include <iostream>
#include <syslog.h>
#include "datatypes.h"

using namespace std;

// has to be singleton-class since used globally in all classes
class Logger {

	private:

        	Logger();
        	static Logger *loginstance;

		string log_message;
        	LogLevel log_level;

	public:

        	// only one instance can be created
		static Logger* getInstance();

        	string SEPARATOR_LINE = string(50, '-');

        	void setLogLevel(string, int);
		void logInfo(string);
		void logNotice(string);
		void logDebug(string);
		void logError(string);
        	LogLevel getLogLevel();

};

#endif
