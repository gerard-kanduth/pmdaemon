#include "logger.h"

Logger *Logger::loginstance = nullptr;

Logger::Logger() {
    loginstance = nullptr;
}

Logger *Logger::getInstance() {
    if (!loginstance) loginstance = new Logger();
    return loginstance;
}

void Logger::setLogLevel(string llevel, int dlevel) {

    if (llevel == "info") {
        log_level = INFO;
        setlogmask(LOG_UPTO(LOG_INFO));
    }
    else if (llevel == "notice") {
        log_level = NOTICE;
        setlogmask(LOG_UPTO(LOG_NOTICE));
    }
    else if (llevel == "error") {
        log_level = ERROR;
        setlogmask(LOG_UPTO(LOG_ERR));
    }
    else if (llevel == "debug") {
        if (dlevel == 1) log_level = DEBUG1;
        else if (dlevel == 2) log_level = DEBUG2;
        setlogmask(LOG_UPTO(LOG_DEBUG));
    }
    else {
        logError("Invalid log_level in configuration!");
        log_level = INFO;
        setlogmask(LOG_UPTO(LOG_INFO));
    }

    logInfo("Setting LOGLEVEL to \'" + llevel + "\'");
    logInfo("Setting DEBUG_LEVEL to \'" + to_string(dlevel) + "\'");

}

void Logger::logInfo(string message) {
    log_message = "INFO: " + message;
    openlog(DAEMON_NAME, 0, LOG_DAEMON);
    syslog(LOG_INFO, "%s", log_message.c_str());
    closelog();
}

void Logger::logNotice(string message) {
    log_message = "NOTICE: " + message;
    openlog(DAEMON_NAME, 0, LOG_DAEMON);
    syslog(LOG_NOTICE, "%s", log_message.c_str());
    closelog();
}

void Logger::logDebug(string message) {
    log_message = "DEBUG: " + message;
    openlog(DAEMON_NAME, 0, LOG_DAEMON);
    syslog(LOG_DEBUG, "%s", log_message.c_str());
    closelog();
}

void Logger::logError(string message) {
    log_message = "ERROR: " + message;
    openlog(DAEMON_NAME, 0, LOG_DAEMON);
    syslog(LOG_ERR, "%s", log_message.c_str());
    closelog();
}

LogLevel Logger::getLogLevel() {
    return log_level;
}
