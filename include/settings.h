#ifndef SETTINGS
#define SETTINGS

#include <iostream>
#include <fstream>
#include <string>
#include <set>
#include <unordered_map>
#include <cmath>
#include <algorithm>
#include "logger.h"

using namespace std;

class Settings {

	private:

		const set<string> available_settings {
			"LOGLEVEL",
			"MAX_ERRORS",
			"RULES_DIRECTORY",
			"LOAD_RULES",
			"SPECIFIC_RULES_CHECK_ONLY",
			"CHECK_INTERVAL",
			"SEND_PROCESS_FILES",
			"CHECKS_BEFORE_ALERT",
			"CHECKS_COOLDOWN",
			"CPU_TRIGGER_THRESHOLD",
			"MEM_TRIGGER_THRESHOLD",
			"STATE_TRIGGER",
			"TERM_CGROUP_CLEANUP",
			"GRAYLOG_ENABLED",
			"GRAYLOG_TRANSFER_METHOD",
			"GRAYLOG_FQDN",
			"GRAYLOG_PORT",
			"GRAYLOG_HTTP_SECURE",
			"GRAYLOG_HTTP_PATH"
		};

		bool config_success = false;

		const char* filename = nullptr;
		const char* daemon_name = nullptr;
		fstream settings_file;
		unordered_map<string, string> settings;

	public:

		Settings(const char*);
		bool configAvailable();
		bool readSettings();
		bool getGraylogHTTPSecure();
		bool getGraylogEnabled();
		bool getStateTrigger();
		bool getLoadRules();
		bool getSpecificRulesCheckOnly();
		bool getTermCgroupCleanup();
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