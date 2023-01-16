#include "rulemanager.h"

RuleManager::RuleManager(const char* dname, string rdirectory) {
	this->daemon_name = dname;
	this->rules_directory = rdirectory.c_str();
	Logger::logNotice("Loading available rules from " + std::string(this->rules_directory));
	loadRules();
}

void RuleManager::loadRules() {

	const std::filesystem::path rules_dir{this->rules_directory};

	// load all files in this->rules_directory ending with ".conf"
	for(auto& file: fs::directory_iterator(rules_dir)) {
		if (file.path().u8string().find(".conf", 0) != string::npos) {
			generateRuleFromFile(std::string(file.path()));
		}
	}
}

// check if read values are valid
bool RuleManager::generateRuleFromFile(string filename) {
	Logger::logInfo("Loading file " +filename);
	RuleReturn file_content = readRuleFile(filename);

	// check if the rule file was readable and present
	if (!file_content.success) {
		Logger::logError("Unable to read this file! Please have a look at this rule.");
	}
	else {
		Logger::logInfo("  |-> Validating file ...");
		if (checkIfRuleIsValid(file_content.rule)) {


			Logger::logInfo("  |-> Registering rule ...");
			if (registerRule(file_content.rule)) {

				// register cgroups if enabled
				if (this->rules[file_content.rule["COMMAND"]].enable_limiting) {
					Logger::logInfo("  |-> Registering cgroup ...");
					createCgroup(&this->rules[file_content.rule["COMMAND"]]);
				}
			}
			else {
				Logger::logError(" '-> Unable to register rule! Error parsing rule settings.");
				return false;
			}

		}
		else {
			Logger::logError(" '-> Broken or incomplete rule! Skipping.");
			Logger::logDebug("Make sure all mandatory settings are present and correct datatypes are used.");
			return false;
		}
	}

	// showRuleContent(file_content.rule);
	Logger::logInfo("  '-> Done!");
	return true;
}

bool RuleManager::registerRule(unordered_map<string, string> file_content) {

	try {

		Rule rule;

		// mandatory rule settings first
		rule.rule_name = file_content["RULE_NAME"];
		rule.command = file_content["COMMAND"];
		rule.cpu_trigger_threshold = stod(file_content["CPU_TRIGGER_THRESHOLD"]);
		rule.mem_trigger_threshold = stod(file_content["MEM_TRIGGER_THRESHOLD"]);

		// check if values are valid (e.g. not negative values)
		if (!file_content["CHECKS_BEFORE_ALERT"].empty()) {
			rule.checks_before_alert = stoi(file_content["CHECKS_BEFORE_ALERT"]);
			if (rule.checks_before_alert < 0)
				return false;
		}

		if (!file_content["LIMIT_CPU_PERCENT"].empty()) {
			rule.limit_cpu_percent = stoi(file_content["LIMIT_CPU_PERCENT"]);
			if (rule.limit_cpu_percent < 0 || rule.limit_cpu_percent > 100)
				return false;
		}

		if (!file_content["LIMIT_MEMORY_VALUE"].empty()) {
			rule.limit_memory_value = stoi(file_content["LIMIT_MEMORY_VALUE"]);
			if (rule.limit_memory_value < 0)
				return false;
		}

		// optional rule settings
		(file_content["NO_CHECK"] == "1") ? rule.no_check = true : rule.no_check = false;
		(file_content["FREEZE"] == "1") ? rule.freeze = true : rule.freeze = false;
		(file_content["OOM_KILL_ENABLED"] == "1") ? rule.oom_kill_enabled = true : rule.oom_kill_enabled = false;
		(file_content["PID_KILL_ENABLED"] == "1") ? rule.pid_kill_enabled = true : rule.pid_kill_enabled = false;
		(file_content["SEND_PROCESS_FILES"] == "0") ? rule.send_process_files = false : rule.send_process_files = true;
		(file_content["ENABLE_LIMITING"] == "1") ? rule.enable_limiting = true : rule.enable_limiting = false;
		(file_content["INCLUDE_BINARY_FOLDER_CHECK"] == "1") ? rule.include_binary_folder_check = true : rule.include_binary_folder_check = false;

		// cgroup name (daemon_name+'-'+rule_name)
		std::string cgroup_name = this->daemon_name;
		cgroup_name += "-";
		cgroup_name += rule.rule_name;
		rule.cgroup_name = cgroup_name;

		// cgroup root dir
		std::string cgrprdir = this->cgroup_root_dir;
		cgrprdir += "/";
		cgrprdir += cgroup_name;
		rule.cgroup_root_dir = cgrprdir;

		// create all needed file references for this cgroup
		rule.cgroup_subtree_control_file = cgrprdir+"/"+this->subtree_control_file;
		rule.cgroup_cpu_max_file = cgrprdir+"/"+this->cpu_max_file;
		rule.cgroup_procs_file = cgrprdir+"/"+this->procs_file;
		rule.cgroup_memory_high_file = cgrprdir+"/"+this->memory_high_file;
		rule.cgroup_memory_max_file = cgrprdir+"/"+this->memory_max_file;
		rule.cgroup_freezer_file = cgrprdir+"/"+this->freezer_file;
		rule.cgroup_kill_file = cgrprdir+"/"+this->kill_file;

		// register this rule to the global rulemanager
		this->rules.insert(std::pair<string, Rule>(rule.command, rule));

		return true;

	} catch (...) {
		return false;
	}

}

bool RuleManager::removeCgroupRules() {
	for (auto& r : this->rules) {
		if (std::filesystem::remove(r.second.cgroup_root_dir)) {
			Logger::logInfo("Removed parent cgroup "+r.second.cgroup_root_dir);
		}
		else {
			Logger::logError("Unable to remove parent cgroup "+r.second.cgroup_root_dir);
			return false;
		}
	}
	return true;
}

bool RuleManager::checkIfRuleIsValid(unordered_map<string, string> file_content) {

	// check if all mandatory_rule_settings are set, otherwise discard this rule
	for (auto& s : this->mandatory_rule_settings) {
		if (file_content[s].empty())
			return false;
	}

	// check that all settings do have the correct datatype
	set<string> boolean_settings = {
		file_content["NO_CHECK"],
		file_content["FREEZE"],
		file_content["OOM_KILL_ENABLED"],
		file_content["PID_KILL_ENABLED"],
		file_content["SEND_PROCESS_FILES"],
		file_content["ENABLE_LIMITING"],
		file_content["INCLUDE_BINARY_FOLDER_CHECK"]
	};
	for (auto& b : boolean_settings) {
		if ((!b.empty()) && (b != "1" && b != "0")) {
			return false;
		}
	}

	// check if value is double
	set<string> double_settings = {
		file_content["CPU_TRIGGER_THRESHOLD"],
		file_content["MEM_TRIGGER_THRESHOLD"]
	};
	for (auto& d : double_settings) {
		if ((!d.empty()) && (d.find_first_not_of(".0123456789") != std::string::npos)) {
			return false;
		}
	}

	// check if value is int
	set<string> int_settings = {
		file_content["CHECKS_BEFORE_ALERT"],
		file_content["LIMIT_MEMORY_VALUE"],
		file_content["LIMIT_CPU_PERCENT"]
	};
	for (auto& i : int_settings) {
		if ((!i.empty()) && (i.find_first_not_of("0123456789") != std::string::npos)) {
			return false;
		}
	}

	// return true if all checks are passed
	return true;
}

bool RuleManager::createCgroup(Rule* rule) {

	// at least one cgroup setting must be set otherwise rule is broken
	if ( rule->limit_cpu_percent >= 0 || rule->limit_memory_value >= 0 ||  rule->freeze || rule->oom_kill_enabled || rule->pid_kill_enabled) {
		if (Logger::getLogLevel() == "debug") {
			Logger::logDebug("limit_cpu_percent: "+to_string(rule->limit_cpu_percent));
			Logger::logDebug("limit_memory_value: "+to_string(rule->limit_memory_value));
			Logger::logDebug("oom_kill_enabled: "+to_string(rule->oom_kill_enabled));
			Logger::logDebug("pid_kill_enabled: "+to_string(rule->pid_kill_enabled));
			Logger::logDebug("freezer: "+to_string(rule->freeze));
		}

		// check if the cgroup already exists, otherwise create it
		if (fs::exists(rule->cgroup_root_dir.c_str())) {
			Logger::logInfo("  |-> Cgroup "+rule->cgroup_root_dir+" already exists!");
		}
		else {

			if (mkdir(rule->cgroup_root_dir.c_str(), 0755) != -1) {
				Logger::logInfo("  |-> Created cgroup "+rule->cgroup_root_dir);
			}
			else {
				Logger::logError("Unable to create cgroup "+rule->cgroup_root_dir);
				return false;
			}
		}

		// prepare the freezer file for the given cgroup
		string freeze;
		if (rule->freeze) {	freeze = "1"; }
		else { freeze = "0"; }
		if (!Utils::writeToFile(rule->cgroup_freezer_file, freeze)) {
			Logger::logError("Something went wrong while modifying "+rule->cgroup_freezer_file);
			return false;
		}

		// prepare the cpu.max file for the given cgroup
		string cpu_max;
		if (rule->limit_cpu_percent > 0) {
			cpu_max = to_string(rule->limit_cpu_percent)+"000 100000";
		} else { cpu_max += "max 100000"; }
		if (!Utils::writeToFile(rule->cgroup_cpu_max_file, cpu_max)) {
			Logger::logError("Something went wrong while modifying "+rule->cgroup_cpu_max_file);
			return false;
		}

		// prepare the memory.high and memory.max file for the given cgroup
		string memory_value;
		if (rule->limit_memory_value > 0) { memory_value = to_string(rule->limit_memory_value); }
		else { memory_value = "max"; }
		if (!Utils::writeToFile(rule->cgroup_memory_high_file, memory_value)) {
			Logger::logError("Something went wrong while modifying "+rule->cgroup_memory_high_file);
			return false;
		}
		if (rule->oom_kill_enabled) {
			if (!Utils::writeToFile(rule->cgroup_memory_max_file, memory_value)) {
				Logger::logError("Something went wrong while modifying "+rule->cgroup_memory_max_file);
				return false;
			}
		}
	}

	return true;
}

Rule* RuleManager::loadIfRuleExists(string command) {

	// iterate all available rules
	for (auto& r : this->rules) {

		if (r.second.include_binary_folder_check) {
			// check if the command starts with the command-string from rule with all possible binary-folder prefixes
			if (command.rfind(r.first, 0) == 0
				|| command.rfind("/bin/"+r.first, 0) == 0
				|| command.rfind("/sbin/"+r.first, 0) == 0
				|| command.rfind("/usr/bin/"+r.first, 0) == 0
				|| command.rfind("/usr/sbin/"+r.first, 0) == 0
				|| command.rfind("/usr/local/bin/"+r.first, 0) == 0
				|| command.rfind("/usr/local/sbin/"+r.first, 0) == 0
			){
				return &this->rules[r.first];
			}
		}
		else {
			// check if the command starts with the command-string from rule
			if (command.rfind(r.first, 0) == 0){
				return &this->rules[r.first];
			}
		}

	}

	return nullptr;
}

// read the file and return a map object with read values
RuleManager::RuleReturn RuleManager::readRuleFile(string filename) {
	RuleReturn current_rule_content;
	unordered_map<string, string> rule;
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
void RuleManager::showRuleContent(Rule rule) {
	Logger::logInfo("-----------------");
	Logger::logInfo(rule.rule_name);
	Logger::logInfo("-----------------");
	Logger::logInfo("command: "+rule.command);
	Logger::logInfo("no_check: "+to_string(rule.no_check));
	Logger::logInfo("cpu_trigger_threshold: "+to_string(rule.cpu_trigger_threshold));
	Logger::logInfo("mem_trigger_threshold: "+to_string(rule.mem_trigger_threshold));
	Logger::logInfo("freeze: "+to_string(rule.freeze));
	Logger::logInfo("oom_kill_enabled: "+to_string(rule.oom_kill_enabled));
	Logger::logInfo("pid_kill_enabled: "+to_string(rule.pid_kill_enabled));
	Logger::logInfo("send_process_files: "+to_string(rule.send_process_files));
	Logger::logInfo("enable_limiting: "+to_string(rule.enable_limiting));
	Logger::logInfo("checks_before_alert: "+to_string(rule.checks_before_alert));
	Logger::logInfo("limit_cpu_percent: "+to_string(rule.limit_cpu_percent));
	Logger::logInfo("limit_memory_value: "+to_string(rule.limit_memory_value));
	Logger::logInfo("cgroup_root_dir: "+rule.cgroup_root_dir);
	Logger::logInfo("cgroup_subtree_control_file: "+rule.cgroup_subtree_control_file);
	Logger::logInfo("cgroup_name: "+rule.cgroup_name);
	Logger::logInfo("cgroup_cpu_max_file: "+rule.cgroup_cpu_max_file);
	Logger::logInfo("cgroup_procs_file: "+rule.cgroup_procs_file);
	Logger::logInfo("cgroup_memory_high_file: "+rule.cgroup_memory_high_file);
	Logger::logInfo("cgroup_memory_max_file: "+rule.cgroup_memory_max_file);
	Logger::logInfo("cgroup_freezer_file: "+rule.cgroup_freezer_file);
	Logger::logInfo("include_binary_folder_check: "+rule.include_binary_folder_check);
	Logger::logInfo("-----------------");
}

void RuleManager::showRules() {
	for (auto& r : this->rules) {
		showRuleContent(r.second);
	}
}