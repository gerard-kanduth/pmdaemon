#include "logger.h"

void Logger::setLogLevel(string loglevel) {
	if (loglevel == "info") {
		setlogmask(LOG_UPTO(LOG_INFO));
		this->loglevel = loglevel;
	}
	else if (loglevel == "notice") {
		setlogmask(LOG_UPTO(LOG_NOTICE));
		this->loglevel = loglevel;
	}
	else if (loglevel == "debug") {
		setlogmask(LOG_UPTO(LOG_DEBUG));
		this->loglevel = loglevel;
	}
	else if (loglevel == "error") {
		setlogmask(LOG_UPTO(LOG_ERR));
		this->loglevel = loglevel;
	}
	else {
		setlogmask(LOG_UPTO(LOG_INFO));
		this->loglevel = "info";	
	}
}

void Logger::logInfo(string message) {
	openlog(daemon_name, 0, LOG_DAEMON);
	syslog(LOG_INFO, message.c_str());
	closelog();
}

void Logger::logNotice(string message) {
	openlog(daemon_name, 0, LOG_DAEMON);
	syslog(LOG_NOTICE, message.c_str());
	closelog();
}

void Logger::logError(string message) {
	openlog(daemon_name, 0, LOG_DAEMON);
	syslog(LOG_PERROR, message.c_str());
	closelog();
}

void Logger::logDebug(string message) {
	openlog(daemon_name, 0, LOG_DAEMON);
	syslog(LOG_DEBUG, message.c_str());
	closelog();
}