#include "rules.h"

Rules::Rules(string rules_directory) {
	this->rules_directory = rules_directory.c_str();
	Logger::logInfo("Loading rules from " + std::string(this->rules_directory));
	
}

Rule::Rule() {
	
}