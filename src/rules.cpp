#include "rules.h"
#include "logger.h"

Rules::Rules(string rules_directory) {
	this->rules_directory = rules_directory.c_str();
	Logger::getInstance().logInfo(("Loading rules from %s", this->rules_directory));
	
	
	//syslog(LOG_INFO, "Loading rule %s", rules_file);
	
}

Rule::Rule() {
	
}