#include "rules.h"

Rules::Rules(Settings*& settings) {
	this->rules_directory = settings->getRulesDir().c_str();
	Logger::logInfo("Loading rules from " + std::string(this->rules_directory));
	this->loadRules(settings);
}

void Rules::loadRules(Settings*& settings) {
	const std::filesystem::path rules_dir{this->rules_directory};

	// load all files in this->rules_directory ending with ".conf"
	for(auto& rule_file: fs::directory_iterator(rules_dir)) {
		if (rule_file.path().u8string().find(".conf", 0) != string::npos) {
			string current_rule_file = std::string(rule_file.path());
			Logger::logInfo("Loading rule " +current_rule_file);
			this->generateRuleFromFile(current_rule_file);
		}
	}

}

void Rules::generateRuleFromFile(string &rule_file) {
	Logger::logDebug("Content of rule " +rule_file);
	cout << rule_file << "\n";
}

Rule::Rule(Settings*& settings) {
	this->cpu_trigger_threashold = settings->getCpuTriggerThreshold();
	this->mem_trigger_threashold = settings->getMemTriggerThreshold();
	// TODO
}