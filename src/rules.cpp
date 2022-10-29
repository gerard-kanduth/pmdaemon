#include "rules.h"

Rules::Rules(Settings*& settings) {
	this->rules_directory = settings->getRulesDir().c_str();
	Logger::logInfo("Loading available rules from " + std::string(this->rules_directory));
	this->loadRules(settings);
}

void Rules::loadRules(Settings*& settings) {
	const std::filesystem::path rules_dir{this->rules_directory};

	// load all files in this->rules_directory ending with ".conf"
	for(auto& file: fs::directory_iterator(rules_dir)) {
		if (file.path().u8string().find(".conf", 0) != string::npos) {
			string current_rule_file = std::string(file.path());
			Logger::logInfo("Loading rule " +current_rule_file);
			generateRuleFromFile(current_rule_file);
		}
	}

}

void Rules::generateRuleFromFile(string &filename) {
	Logger::logDebug("Content of rule " +filename);
	ruleReturn rule_content = readRuleFile(filename);

	// check if the rule file was readable and present
	if (!rule_content.success) {
		Logger::logError("Unable to load rule settings! Please have a look at this rule.");
	}
	else {
		if (checkIfRuleIsValid(rule_content.rule)) {
			Logger::logInfo("Done!");
			showRuleContent(rule_content.rule);
		}
		else {
			Logger::logError("Incomplete rule! Make sure all mandatory rule settings are set.");
		}
	}
}

// check if all mandatory_rule_settings are set, otherwise discard this rule
bool Rules::checkIfRuleIsValid(map<string, string> rule) {
	for (auto s : this->mandatory_rule_settings) {
		if (rule[s].empty())
			return false;
	}
	return true;
}

Rules::ruleReturn Rules::readRuleFile(string filename) {
	ruleReturn current_rule_content;
	map<string, string> rule;
	fstream rules_file;
	rules_file.open(filename, ios::in);
	if (!rules_file) {
		Logger::logError("Rule file " + filename + " is not present or readable!");
		current_rule_content.success = false;
		current_rule_content.rule = rule;
	}
	else {
		if (rules_file.is_open()) {
			string line;
			while(getline(rules_file, line)) {
				if(this->available_rule_settings.find(line.substr(0, line.find("="))) != this->available_rule_settings.end()) {
					rule.insert(std::pair<string,string>(line.substr(0, line.find("=")),line.substr(line.find("=")+1)));
				}
			}
			rules_file.close();
		}
		current_rule_content.success = true;
		current_rule_content.rule = rule;
	}
	return current_rule_content;
}

// for debug purpose only
void Rules::showRuleContent(map<string, string> rule) {
	for (auto s : rule)
		std::cout << s.first << " -> " << s.second << '\n';
}

Rule::Rule(Settings*& settings) {
	this->cpu_trigger_threshold = settings->getCpuTriggerThreshold();
	this->mem_trigger_threshold = settings->getMemTriggerThreshold();
	// TODO
}