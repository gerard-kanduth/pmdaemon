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

bool Settings::getZombieTrigger() {
	try {
		int zombie_trigger = stoi(settings["ZOMBIE_TRIGGER"]);
		if (std::floor(zombie_trigger) == zombie_trigger && zombie_trigger >= 0 && zombie_trigger <= 1) {
			Logger::logInfo("Setting ZOMBIE_TRIGGER to \'" + to_string(zombie_trigger) + "\'");
			if (zombie_trigger == 1)
				return true;
			else
				return false;
		}
		else
			throw 2;
	} catch (...) {
		Logger::logError("Invalid ZOMBIE_TRIGGER value in configuration! Using '0'.");
		return false;
	}
}

double Settings::getCpuTriggerThreshold() {
	try {
		string ctt = settings["CPU_TRIGGER_THRESHOLD"];
		double cpu_trigger_threshold = stod(ctt.c_str());
		Logger::logInfo("Setting CPU_TRIGGER_THRESHOLD to \'" + to_string(cpu_trigger_threshold) + "\'");
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
		Logger::logInfo("Setting MEM_TRIGGER_THRESHOLD to \'" + to_string(mem_trigger_threshold) + "\'");
		return mem_trigger_threshold;
	} catch (...) {
		Logger::logError("Invalid MEM_TRIGGER_THRESHOLD value in configuration! Using '50.0'.");
		return 50.0;
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