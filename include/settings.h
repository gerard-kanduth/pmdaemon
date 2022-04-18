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
			"CHECK_INTERVAL",
			"SEND_PROCESS_FILES",
			"CHECKS_BEFORE_ALERT",
			"CHECKS_COOLDOWN",
			"CPU_TRIGGER_THRESHOLD",
			"MEM_TRIGGER_THRESHOLD",
			"ZOMBIE_TRIGGER",
			"GRAYLOG_ENABLE",
			"GRAYLOG_URL",
			"GRAYLOG_PORT"
		};
		const char *filename;
		const char *daemon_name;
		fstream settings_file;
		map<string, string> settings;

	public:
		Settings(const char*);
		bool configAvailable();
		bool readSettings();
		bool getZombieTrigger();
		double getCpuTriggerThreshold();
		double getMemTriggerThreshold();
		int getChecksBeforeAlert();
		int getCheckInterval();
		int getChecksCooldown();
		int getMaxErrors();
		string getLogLevel();
		string getRulesDir();
		void showSettings();
};

#endif