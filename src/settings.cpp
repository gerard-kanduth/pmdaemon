#include "settings.h"

Settings::Settings(const char *filename, const char *daemon_name){
	this->filename = filename;
	this->daemon_name = daemon_name;
	openlog(daemon_name, 0, LOG_USER);
	syslog(LOG_NOTICE, "Loading configuration file %s", this->filename);
	this->config_success = readSettings();
	closelog();
}

bool Settings::readSettings(){
	this->settings_file.open(this->filename, ios::in);
	if (!this->settings_file) {
		syslog(LOG_PERROR, "Settings file %s is not present or readable!", this->filename);
		return false;
	}
	else {
		if (this->settings_file.is_open()){
			string line;
			while(getline(this->settings_file, line)){
				if(this->available_settings.find(line.substr(0, line.find("="))) != this->available_settings.end()){
					this->settings.insert(std::pair<string,string>(line.substr(0, line.find("=")),line.substr(line.find("=")+1)));
				}
			}
			this->settings_file.close();
		}
	}
	return true;
}

bool Settings::configAvailable(){
	return this->config_success;
}

void Settings::showSettings(){
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