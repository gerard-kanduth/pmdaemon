#include <iostream>
#include <fstream>
#include <string>
#include <set>
#include <map>
#include <syslog.h>

using namespace std;

class Settings {

	private:
		const set<string> available_settings{
			"LOGLEVEL",
			"RULES_DIRECTORY",
			"CHECK_INTERVAL",
			"SEND_PROCESS_FILES",
			"CHECKS_BEFORE_ALERT",
			"CPU_TRIGGER_THRESHOLD",
			"MEM_TRIGGER_THRESHOLD",
			"ZOMBIE_TRIGGER",
			"GRAYLOG_ENABLE",
			"GRAYLOG_URL",
			"GRAYLOG_PORT"
		};
		map<string, string> settings;
		fstream settings_file;
		const char *filename;
		const char *daemon_name;
		bool config_success = false;

	public:
		Settings(const char*, const char*);
		void showSettings();
		bool configAvailable();
		bool readSettings();
		string getLogLevel();
};