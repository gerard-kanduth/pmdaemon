#include "settings.h"
#include "logger.h"

Settings::Settings(const char *filename) {
	this->filename = filename;
	Logger::getInstance().logInfo(("Loading configuration file %s", this->filename));
	this->config_success = readSettings();
}

bool Settings::readSettings() {
	this->settings_file.open(this->filename, ios::in);
	if (!this->settings_file) {
		Logger::getInstance().logError(("Settings file %s is not present or readable!", this->filename));
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

string Settings::getLogLevel() {
	if (settings["LOGLEVEL"] == "info" || 
		settings["LOGLEVEL"] == "notice" || 
		settings["LOGLEVEL"] == "debug" || 
		settings["LOGLEVEL"] == "error")
		return settings["LOGLEVEL"];
	else
		return "info";
}

string Settings::getRulesDir() {
	if (settings["RULES_DIRECTORY"].empty())
		return "/etc/pmdaemon/rules.d";
	else
		return settings["RULES_DIRECTORY"];	
}