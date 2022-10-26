#include <iostream>
#include <fstream>
#include <string>
#include <set>
#include <map>
#include <cmath>
#include <algorithm>
#include "logger.h"

#ifndef SETTINGS
#define SETTINGS

using namespace std;

class Settings {

	private:

		bool config_success = false;
		const set<string> available_settings {
			"LOGLEVEL",
			"MAX_ERRORS",
			"RULES_DIRECTORY",
			"LOAD_RULES",
			"CHECK_INTERVAL",
			"SEND_PROCESS_FILES",
			"CHECKS_BEFORE_ALERT",
			"CHECKS_COOLDOWN",
			"CPU_TRIGGER_THRESHOLD",
			"MEM_TRIGGER_THRESHOLD",
			"STATE_TRIGGER",
			"GRAYLOG_ENABLED",
			"GRAYLOG_TRANSFER_METHOD",
			"GRAYLOG_FQDN",
			"GRAYLOG_PORT",
			"GRAYLOG_HTTP_SECURE",
			"GRAYLOG_HTTP_PATH"
		};

		const char *filename;
		const char *daemon_name;
		fstream settings_file;
		map<string, string> settings;

	public:

		Settings(const char*);
		bool configAvailable();
		bool readSettings();
		bool getGraylogHTTPSecure();
		bool getGraylogEnabled();
		bool getStateTrigger();
		bool getLoadRules();
		double getCpuTriggerThreshold();
		double getMemTriggerThreshold();
		int getChecksBeforeAlert();
		int getCheckInterval();
		int getChecksCooldown();
		int getGraylogPort();
		int getMaxErrors();
		string getGraylogFQDN();
		string getGraylogHTTPPath();
		string getGraylogTransportMethod();
		string getLogLevel();
		string getRulesDir();
		void showSettings();
};

#endif