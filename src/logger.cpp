#include "logger.h"

void Logger::setLogLevel(string log_level) {
	getInstance().instanceSetLogLevel(log_level);
}

void Logger::instanceSetLogLevel(string llevel) {
	if (llevel == "info" || llevel == "INFO") {
		setlogmask(LOG_UPTO(LOG_INFO));
		this->log_level = llevel;
	}
	else if (llevel == "notice" || llevel == "NOTICE") {
		setlogmask(LOG_UPTO(LOG_NOTICE));
		this->log_level = llevel;
	}
	else if (llevel == "debug" || llevel == "DEBUG") {
		setlogmask(LOG_UPTO(LOG_DEBUG));
		this->log_level = llevel;
	}
	else if (llevel == "error" || llevel == "ERROR") {
		setlogmask(LOG_UPTO(LOG_ERR));
		this->log_level = llevel;
	}
	else {
		logError("Invalid log_level in configuration!");
		setlogmask(LOG_UPTO(LOG_INFO));
		this->log_level = "info";
	}
	Logger::logInfo("Setting LOGLEVEL to \'"+llevel+"\'");
}

string Logger::getLogLevel(){
	return getInstance().log_level;
}

void Logger::logInfo(string message){
	return getInstance().instanceLogInfo(message);
}

void Logger::logNotice(string message){
	return getInstance().instanceLogNotice(message);
}

void Logger::logDebug(string message){
	return getInstance().instanceLogDebug(message);
}

void Logger::logError(string message){
	return getInstance().instanceLogError(message);
}

void Logger::instanceLogInfo(string message) {
	log_message = "INFO: " + message;
	openlog(daemon_name, 0, LOG_DAEMON);
	syslog(LOG_INFO, log_message.c_str());
	closelog();
}

void Logger::instanceLogNotice(string message) {
	log_message = "NOTICE: " + message;
	openlog(daemon_name, 0, LOG_DAEMON);
	syslog(LOG_NOTICE, log_message.c_str());
	closelog();
}

void Logger::instanceLogDebug(string message) {
	log_message = "DEBUG: " + message;
	openlog(daemon_name, 0, LOG_DAEMON);
	syslog(LOG_DEBUG, log_message.c_str());
	closelog();
}

void Logger::instanceLogError(string message) {
	log_message = "ERROR: " + message;
	openlog(daemon_name, 0, LOG_DAEMON);
	syslog(LOG_ERR, log_message.c_str());
	closelog();
}

void Logger::setDaemonName(const char* daemon_name){
	getInstance().daemon_name = daemon_name;
}