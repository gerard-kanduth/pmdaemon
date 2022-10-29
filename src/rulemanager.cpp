#include "rulemanager.h"

RuleManager::RuleManager(Settings*& settings) {
	this->rules_directory = settings->getRulesDir().c_str();
	Logger::logInfo("Loading available rules from " + std::string(this->rules_directory));
	loadRules();
}

void RuleManager::loadRules() {
	const std::filesystem::path rules_dir{this->rules_directory};

	// load all files in this->rules_directory ending with ".conf"
	for(auto& file: fs::directory_iterator(rules_dir)) {
		if (file.path().u8string().find(".conf", 0) != string::npos) {
			string current_rule_file = std::string(file.path());
			generateRuleFromFile(current_rule_file);
		}
	}
}

// check if read values are valid
void RuleManager::generateRuleFromFile(string &filename) {
	Logger::logInfo("Loading file " +filename);
	ruleReturn file_content = readRuleFile(filename);

	// check if the rule file was readable and present
	if (!file_content.success) {
		Logger::logError("Unable to read this file! Please have a look at this rule.");
	}
	else {
		Logger::logInfo("  |-> Validating file ...");
		if (checkIfRuleIsValid(file_content.rule)) {
			showRuleContent(file_content.rule);
			Logger::logInfo("  |-> Registering rule ...");
			if (registerRule(file_content.rule))
				Logger::logInfo("  '-> Done!");
			else
				Logger::logError(" '-> Unable to register rule! Error parsing rule settings.");
		}
		else {
			Logger::logError(" '-> Broken or incomplete rule! Skipping.");
			Logger::logDebug("Make sure all mandatory settings are present and correct datatypes are used.");
		}
	}
}

bool RuleManager::registerRule(map<string, string> file_content) {

	try {

		Rule rule;

		// mandatory rule settings first
		rule.rule_name = file_content["RULE_NAME"];
		rule.command = file_content["COMMAND"];
		rule.cpu_trigger_threshold = stod(file_content["CPU_TRIGGER_THRESHOLD"]);
		rule.mem_trigger_threshold = stod(file_content["MEM_TRIGGER_THRESHOLD"]);

		if (!file_content["CHECKS_BEFORE_ALERT"].empty())
			rule.checks_before_alert = stoi(file_content["CHECKS_BEFORE_ALERT"]);

		// optional rule settings
		(file_content["NO_CHECK"] == "1") ? rule.no_check = true : rule.no_check = false;
		(file_content["FREEZE"] == "1") ? rule.freeze = true : rule.freeze = false;
		(file_content["OOM_KILL_ENABLED"] == "1") ? rule.oom_kill_enabled = true : rule.oom_kill_enabled = false;
		(file_content["PID_KILL_ENABLED"] == "1") ? rule.pid_kill_enabled = true : rule.pid_kill_enabled = false;
		(file_content["SEND_PROCESS_FILES"] == "1") ? rule.send_process_files = true : rule.send_process_files = false;

		// register this rule to the global rulemanager
		this->rules.insert(std::pair<string, Rule>(rule.command, rule));

		return true;

	} catch (...) {
		return false;
	}

}

bool RuleManager::checkIfRuleIsValid(map<string, string> file_content) {

	// check if all mandatory_rule_settings are set, otherwise discard this rule
	for (auto s : this->mandatory_rule_settings) {
		if (file_content[s].empty())
			return false;
	}

	// check that all settings do have the correct datatype
	set<string> boolean_settings = {file_content["NO_CHECK"], file_content["FREEZE"], file_content["OOM_KILL_ENABLED"], file_content["PID_KILL_ENABLED"], file_content["SEND_PROCESS_FILES"]};
	for (auto b : boolean_settings) {
		if ((!b.empty()) && (b != "1" && b != "0")) {
			return false;
		}
	}

	// check if value is double
	set<string> double_settings = {file_content["CPU_TRIGGER_THRESHOLD"], file_content["MEM_TRIGGER_THRESHOLD"]};
	for (auto d : double_settings) {
		if ((!d.empty()) && (d.find_first_not_of(".0123456789") != std::string::npos)) {
			return false;
		}
	}

	// check if value is int
	set<string> int_settings = {file_content["CHECKS_BEFORE_ALERT"]};
	for (auto i : int_settings) {
		if ((!i.empty()) && (i.find_first_not_of("0123456789") != std::string::npos)) {
			return false;
		}
	}

	return true;
}

// read the file and return a map object with read values
RuleManager::ruleReturn RuleManager::readRuleFile(string filename) {
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
void RuleManager::showRuleContent(map<string, string> rule) {
	for (auto s : rule)
		std::cout << s.first << " -> " << s.second << '\n';
}