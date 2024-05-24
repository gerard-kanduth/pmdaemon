#ifndef SETTINGS
#define SETTINGS

#include <unordered_map>
#include <cmath>
#include <algorithm>
#include "logger.h"
#include "utils.h"

#define SETTINGS_FILE "/etc/pmdaemon/settings.conf"

using namespace std;

class Settings {

	private:

        	// Logger Instance
        	Logger* logger = nullptr;

		const set<string> available_settings {
			"LOGLEVEL",
        		"DEBUG_LEVEL",
			"MAX_ERRORS",
			"RULES_DIRECTORY",
			"LOAD_RULES",
			"SPECIFIC_RULES_CHECK_ONLY",
			"CHECK_INTERVAL",
        		"SEND_NOTIFICATIONS",
			"CHECKS_BEFORE_ALERT",
			"CHECKS_COOLDOWN",
			"CPU_TRIGGER_THRESHOLD",
			"MEM_TRIGGER_THRESHOLD",
			"STATE_TRIGGER",
        		"WHITELISTED_USERS",
			"TERM_CGROUP_CLEANUP",
        		"GLOBAL_ACTION_ENABLED",
        		"GLOBAL_ACTION",
        		"JAIL_CPU_LIMIT",
        		"JAIL_MEM_LIMIT",
        		"MAX_ALERTS_GLOBAL_ACTION",
			"GRAYLOG_ENABLED",
			"GRAYLOG_TRANSFER_METHOD",
			"GRAYLOG_FQDN",
			"GRAYLOG_PORT",
			"GRAYLOG_HTTP_SECURE",
        		"GRAYLOG_HTTP_PATH",
        		"LOGSTASH_ENABLED",
        		"LOGSTASH_TRANSFER_METHOD",
        		"LOGSTASH_FQDN",
        		"LOGSTASH_PORT",
        		"LOGSTASH_HTTP_SECURE",
        		"LOGSTASH_HTTP_PATH"
		};

        	Settings();
        	static Settings *settingsinstance;

		bool config_success = false;

		fstream settings_file;
		unordered_map<string, string> settings;

	public:

        	// only one instance can be created
        	static Settings* getInstance();

        	bool configAvailable();
        	bool readSettings();
        	bool getGraylogHTTPSecure();
        	bool getLogstashHTTPSecure();
        	bool getGraylogEnabled();
        	bool getLogstashEnabled();
        	bool getStateTrigger();
        	bool getLoadRules();
        	bool getSpecificRulesCheckOnly();
        	bool getGlobalActionEnabled();
        	bool getTermCgroupCleanup();
        	bool getSendNotifications();
        	double getCpuTriggerThreshold();
        	double getJailCPULimit();
        	GlobalAction getGlobalAction();
        	int getChecksBeforeAlert();
        	int getCheckInterval();
        	int getChecksCooldown();
        	int getGraylogPort();
        	int getLogstashPort();
        	int getMaxErrors();
        	int getMaxAlertGlobalAction();
        	int getDebugLevel();
        	long long getJailMEMLimit();
        	long long getMemTriggerThreshold();
        	string getGraylogFQDN();
        	string getLogstashFQDN();
        	string getGraylogHTTPPath();
        	string getLogstashHTTPPath();
        	string getLogLevel();
        	string getRulesDir();
        	set<string> getWhitelistedUsers();
        	TransportType getGraylogTransportMethod();
        	TransportType getLogstashTransportMethod();
        	void logTotalRAM();
        	void showSettings();
};

#endif
