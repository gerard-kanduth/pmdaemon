#include "settings.h"

Settings::Settings(const char *filename) {
	this->filename = filename;
	Logger::logInfo("Loading configuration file " + std::string(this->filename));
	this->config_success = readSettings();
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

bool Settings::configAvailable() {
	return this->config_success;
}

void Settings::showSettings() {
	for (auto s : this->settings)
		std::cout << s.first << "\t-> " << s.second << '\n';	
}

int Settings::getCheckInterval() {
	try {
		int check_interval = stoi(settings["CHECK_INTERVAL"]);
		if (std::floor(check_interval) == check_interval) {
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
		if (settings["LOGLEVEL"] == "info" ||
			settings["LOGLEVEL"] == "INFO" ||
			settings["LOGLEVEL"] == "notice" ||
			settings["LOGLEVEL"] == "NOTICE" ||
			settings["LOGLEVEL"] == "debug" ||
			settings["LOGLEVEL"] == "DEBUG" ||
			settings["LOGLEVEL"] == "error" ||
			settings["LOGLEVEL"] == "ERROR")
				return settings["LOGLEVEL"];
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