#include "settings.h"

Settings::Settings(const char* filename) {
	this->filename = filename;
	Logger::logInfo("Loading configuration file " + std::string(this->filename));
	this->config_success = readSettings();
}

bool Settings::configAvailable() {
	return this->config_success;
}

bool Settings::readSettings() {
	this->settings_file.open(this->filename, ios::in);
	if (!this->settings_file) {
		Logger::logError("Settings file " + std::string(this->filename) + " is not present or readable!");
		return false;
	}
	else {
		if (this->settings_file.is_open()) {
			string line;
			while(getline(this->settings_file, line)) {
				if(this->available_settings.find(line.substr(0, line.find("="))) != this->available_settings.end()) {
					this->settings.insert(std::pair<string,string>(line.substr(0, line.find("=")),line.substr(line.find("=")+1)));
				}
			}
			this->settings_file.close();
		}
	}
	return true;
}

bool Settings::getGraylogEnabled() {
	try {
		int graylog_enabled = stoi(settings["GRAYLOG_ENABLED"]);
		if (std::floor(graylog_enabled) == graylog_enabled && graylog_enabled == 0 || graylog_enabled == 1) {
			Logger::logInfo("Setting GRAYLOG_ENABLE to \'" + to_string(graylog_enabled) + "\'");
			if (graylog_enabled == 1)
				return true;
			else
				return false;
		}
		else
			throw 2;
	} catch (...) {
		Logger::logError("Invalid GRAYLOG_ENABLED value in configuration! Using '0'.");
		return false;
	}
}

bool Settings::getGraylogHTTPSecure() {
	try {
		int graylog_http_secure = stoi(settings["GRAYLOG_HTTP_SECURE"]);
		if (std::floor(graylog_http_secure) == graylog_http_secure && graylog_http_secure == 0 || graylog_http_secure == 1) {
			Logger::logInfo("Setting GRAYLOG_HTTP_SECURE to \'" + to_string(graylog_http_secure) + "\'");
			if (graylog_http_secure == 1)
				return true;
			else
				return false;
		}
		else
			throw 2;
	} catch (...) {
		Logger::logError("Invalid GRAYLOG_HTTP_SECURE value in configuration! Using '0'.");
		return false;
	}
}

bool Settings::getStateTrigger() {
	try {
		int state_trigger = stoi(settings["STATE_TRIGGER"]);
		if (std::floor(state_trigger) == state_trigger && state_trigger == 0 || state_trigger == 1) {
			Logger::logInfo("Setting STATE_TRIGGER to \'" + to_string(state_trigger) + "\'");
			if (state_trigger == 1)
				return true;
			else
				return false;
		}
		else
			throw 2;
	} catch (...) {
		Logger::logError("Invalid STATE_TRIGGER value in configuration! Using '0'.");
		return false;
	}
}

bool Settings::getLoadRules() {
	try {
		int load_rules = stoi(settings["LOAD_RULES"]);
		if (std::floor(load_rules) == load_rules && load_rules == 0 || load_rules == 1) {
			Logger::logInfo("Setting LOAD_RULES to \'" + to_string(load_rules) + "\'");
			if (load_rules == 1)
				return true;
			else
				return false;
		}
		else
			throw 2;
	} catch (...) {
		Logger::logError("Invalid LOAD_RULES value in configuration! Using '0'.");
		return false;
	}
}

double Settings::getCpuTriggerThreshold() {
	try {
		string ctt = settings["CPU_TRIGGER_THRESHOLD"];
		double cpu_trigger_threshold = stod(ctt.c_str());
		char buffer[6];
		sprintf(buffer, "%.2f", cpu_trigger_threshold);
		string cpu_trigger_threshold_string(buffer);
		Logger::logInfo("Setting CPU_TRIGGER_THRESHOLD to \'" + cpu_trigger_threshold_string + "\'");
		return cpu_trigger_threshold;
	} catch (...) {
		Logger::logError("Invalid CPU_TRIGGER_THRESHOLD value in configuration! Using '90.0'.");
		return 90.0;
	}
}

double Settings::getMemTriggerThreshold() {
	try {
		string mtt = settings["MEM_TRIGGER_THRESHOLD"];
		double mem_trigger_threshold = stod(mtt.c_str());
		char buffer[6];
		sprintf(buffer, "%.2f", mem_trigger_threshold);
		string mem_trigger_threshold_string(buffer);
		Logger::logInfo("Setting MEM_TRIGGER_THRESHOLD to \'" + mem_trigger_threshold_string + "\'");
		return mem_trigger_threshold;
	} catch (...) {
		Logger::logError("Invalid MEM_TRIGGER_THRESHOLD value in configuration! Using '50.0'.");
		return 50.0;
	}
}

int Settings::getGraylogPort() {
	try {
		int graylog_port = stoi(settings["GRAYLOG_PORT"]);
		if (std::floor(graylog_port) == graylog_port && graylog_port >= 0) {
			Logger::logInfo("Setting GRAYLOG_PORT to \'" + to_string(graylog_port) + "\'");
			return graylog_port;
		}
		else
			throw 2;
	} catch (...) {
		Logger::logError("Invalid GRAYLOG_PORT value in configuration! Using '12201'.");
		return 12201;
	}
}

int Settings::getCheckInterval() {
	try {
		int check_interval = stoi(settings["CHECK_INTERVAL"]);
		if (std::floor(check_interval) == check_interval && check_interval > 0) {
			Logger::logInfo("Setting CHECK_INTERVAL to \'" + to_string(check_interval) + "\'");
			return check_interval;
		}
		else
			throw 2;
	} catch (...) {
		Logger::logError("Invalid CHECK_INTERVAL value in configuration! Using '5' seconds.");
		return 5;
	}
}

int Settings::getChecksBeforeAlert() {
	try {
		int checks_before_alert = stoi(settings["CHECKS_BEFORE_ALERT"]);
		if (std::floor(checks_before_alert) == checks_before_alert && checks_before_alert >= 0) {
			Logger::logInfo("Setting CHECKS_BEFORE_ALERT to \'" + to_string(checks_before_alert) + "\'");
			return checks_before_alert;
		}
		else
			throw 2;
	} catch (...) {
		Logger::logError("Invalid CHECKS_BEFORE_ALERT value in configuration! Using '10'.");
		return 10;
	}
}

int Settings::getChecksCooldown() {
	try {
		int checks_cooldown = stoi(settings["CHECKS_COOLDOWN"]);
		if (std::floor(checks_cooldown) == checks_cooldown && checks_cooldown >= 0) {
			Logger::logInfo("Setting CHECKS_COOLDOWN to \'" + to_string(checks_cooldown) + "\'");
			return checks_cooldown;
		}
		else
			throw 2;
	} catch (...) {
		Logger::logError("Invalid CHECKS_COOLDOWN value in configuration! Using '50'.");
		return 50;
	}
}

int Settings::getMaxErrors() {
	try {
		int max_errors = stoi(settings["MAX_ERRORS"]);
		if (std::floor(max_errors) == max_errors) {
			Logger::logInfo("Setting MAX_ERRORS to \'" + to_string(max_errors) + "\'");
			return max_errors;
		}
		else
			throw 2;
	} catch (...) {
		Logger::logError("Invalid MAX_ERRORS value in configuration! Using '10'.");
		return 10;
	}
}

string Settings::getGraylogFQDN() {
	try {
		string graylog_fqdn = settings["GRAYLOG_FQDN"];
		transform(graylog_fqdn.begin(), graylog_fqdn.end(), graylog_fqdn.begin(), ::tolower);
		if (graylog_fqdn != "") {
			Logger::logInfo("Setting GRAYLOG_FQDN to \'" + graylog_fqdn + "\'");
			return graylog_fqdn;
		}
		else
			throw 2;
	} catch (...) {
		Logger::logError("Invalid GRAYLOG_FQDN value in configuration! Using 'localhost'.");
		return "localhost";
	}
}

string Settings::getGraylogHTTPPath() {
	try {
		string graylog_http_path = settings["GRAYLOG_HTTP_PATH"];
		transform(graylog_http_path.begin(), graylog_http_path.end(), graylog_http_path.begin(), ::tolower);
		if (graylog_http_path != "" && graylog_http_path.find('/') != std::string::npos) {
			Logger::logInfo("Setting GRAYLOG_HTTP_PATH to \'" + graylog_http_path + "\'");
			return graylog_http_path;
		}
		else
			throw 2;
	} catch (...) {
		Logger::logError("Invalid GRAYLOG_HTTP_PATH value in configuration! Using '/gelf'.");
		return "/gelf";
	}
}

string Settings::getGraylogTransportMethod() {
	try {
		string graylog_transport_method = settings["GRAYLOG_TRANSFER_METHOD"];
		transform(graylog_transport_method.begin(), graylog_transport_method.end(), graylog_transport_method.begin(), ::tolower);
		if (graylog_transport_method == "http" || graylog_transport_method == "udp" || graylog_transport_method == "tcp") {
			Logger::logInfo("Setting GRAYLOG_TRANSFER_METHOD to \'" + graylog_transport_method + "\'");
			return graylog_transport_method;
		}
		else
			throw 2;
	} catch (...) {
		Logger::logError("Invalid GRAYLOG_TRANSFER_METHOD value in configuration! Using 'http'.");
		return "http";
	}
}

string Settings::getLogLevel() {
	try {
		string log_level = settings["LOGLEVEL"];
		transform(log_level.begin(), log_level.end(), log_level.begin(), ::tolower);
		if (log_level == "info" || log_level == "notice" || log_level == "debug" || log_level == "error")
				return log_level;
		else
			throw 2;
	} catch (...) {
		Logger::logError("Invalid LOGLEVEL value in configuration! Using 'info'.");
		return "info";
	}
}

string Settings::getRulesDir() {
	try {
		if (settings["RULES_DIRECTORY"].empty())
			return "/etc/pmdaemon/rules.d";
		else
			return settings["RULES_DIRECTORY"];
	} catch (...) {
		Logger::logError("Invalid RULES_DIRECTORY value in configuration! Using '/etc/pmdaemon/rules.d'.");
		return "/etc/pmdaemon/rules.d";
	}
}

void Settings::showSettings() {
	for (auto s : this->settings)
		std::cout << s.first << "\t-> " << s.second << '\n';	
}