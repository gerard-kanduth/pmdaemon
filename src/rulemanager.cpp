#include "rulemanager.h"

RuleManager::RuleManager(Settings*& settings) {
	this->rules_directory = settings->getRulesDir().c_str();
	Logger::logInfo("Loading available rules from " + std::string(this->rules_directory));
	this->loadRules();
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
	Logger::logInfo("Loading rule " +filename);
	ruleReturn rule_content = readRuleFile(filename);

	// check if the rule file was readable and present
	if (!rule_content.success) {
		Logger::logError("Unable to read this file! Please have a look at this rule.");
	}
	else {
		if (checkIfRuleIsValid(rule_content.rule)) {
			showRuleContent(rule_content.rule);
			Logger::logInfo("Register rule " +filename);
			registerRule(rule_content.rule);
			Logger::logInfo("Done!");
		}
		else {
			Logger::logError("Incomplete rule! Make sure all mandatory rule settings are set.");
		}
	}
}

bool RuleManager::registerRule(map<string, string> rule) {
	Rule rrule;

	// mandatory rule settings first
	rrule.command = rule["COMMAND"];
	rrule.cpu_trigger_threshold = stoi(rule["CPU_TRIGGER_THRESHOLD"]);
	rrule.mem_trigger_threshold = stoi(rule["MEM_TRIGGER_THRESHOLD"]);

	// optional rule settings
	(rule["NO_CHECK"] == "1") ? rrule.no_check = true : rrule.no_check = false;
	(rule["FREEZE"] == "1") ? rrule.freeze = true : rrule.freeze = false;
	(rule["OOM_KILL_ENABLED"] == "1") ? rrule.oom_kill_enabled = true : rrule.oom_kill_enabled = false;
	(rule["PID_KILL_ENABLED"] == "1") ? rrule.pid_kill_enabled = true : rrule.pid_kill_enabled = false;
	(rule["SEND_PROCESS_FILES"] == "1") ? rrule.send_process_files = true : rrule.send_process_files = false;

	cout << rrule.command << "\n";
	this->rules.insert(std::pair<string, Rule>(rrule.command, rrule));
}

// check if all mandatory_rule_settings are set, otherwise discard this rule
bool RuleManager::checkIfRuleIsValid(map<string, string> rule) {
	for (auto s : this->mandatory_rule_settings) {
		if (rule[s].empty())
			return false;
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