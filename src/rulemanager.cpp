#include "rulemanager.h"

RuleManager::RuleManager(string rdirectory) {

    logger = Logger::getInstance();

    rules_directory = rdirectory.c_str();
    logger->logNotice("Loading available rules from " + string(rules_directory));
	loadRules();
}

void RuleManager::loadRules() {

    const filesystem::path rules_dir{rules_directory};

    // load all files in rules_directory ending with ".conf"
	for(auto& file: fs::directory_iterator(rules_dir)) {
        if (regex_match(file.path().u8string(), regex("^.*.conf$||.*.rule$"))) {
            generateRuleFromFile(string(file.path()));
		}
	}
}

// check if read values are valid
bool RuleManager::generateRuleFromFile(string filename) {
    logger->logInfo("Loading file " +filename);
	RuleReturn file_content = readRuleFile(filename);

	// check if the rule file was readable and present
	if (!file_content.success) {
        logger->logError("Unable to read this file! Please have a look at this rule.");
	}
	else {
        logger->logInfo("Validating file " + filename);
		if (checkIfRuleIsValid(file_content.rule)) {


            logger->logInfo("Registering rule " + file_content.rule["RULE_NAME"]);
			if (registerRule(file_content.rule)) {

				// register cgroups if enabled
                if (rules[file_content.rule["RULE_NAME"]].enable_limiting) {
                    logger->logInfo("Registering cgroup " + rules[file_content.rule["RULE_NAME"]].cgroup_name);
                    createCgroup(&rules[file_content.rule["RULE_NAME"]]);
				}
			}
			else {
                logger->logError("Unable to register rule! Error parsing rule settings.");
				return false;
			}

		}
		else {
            logger->logError("Broken or incomplete rule! Skipping.");
			return false;
		}
	}

    logger->logInfo("Successfully registered rule " + file_content.rule["RULE_NAME"]);
	return true;
}

bool RuleManager::checkIfRuleIsValid(unordered_map<string, string> file_content) {

    // either COMMAND or REGEX_SEARCH_PATTERN must be set in order to be valid
    if (file_content["COMMAND"].empty() && file_content["REGEX_SEARCH_PATTERN"].empty()) {
        logger->logError("COMMAND and REGEX_SEARCH_PATTERN are empty");
        return false;
    }

    // check if all mandatory_rule_settings are set, otherwise discard this rule
    for (auto& s : mandatory_rule_settings) {
        if (file_content[s].empty()) {
            logger->logError("Mandadtory Settings are missing");
            return false;
        }
    }

    // check if memory-threshold is given in percentage or as absolute value
    string mem_trigger_threshold = file_content["MEM_TRIGGER_THRESHOLD"];
    if (!mem_trigger_threshold.empty()
            && !Utils::isMemValue(&mem_trigger_threshold)
            && !Utils::isDisableValue(&mem_trigger_threshold)) {
        logger->logError("Invalid or missing MEM_TRIGGER_THRESHOLD value");
        return false;
    }

    // check if memory-threshold is given in percentage
    string cpu_trigger_threshold = file_content["CPU_TRIGGER_THRESHOLD"];
    if (!cpu_trigger_threshold.empty()
            && !Utils::isPercentValue(&cpu_trigger_threshold)
            && !Utils::isDisableValue(&cpu_trigger_threshold)) {
        logger->logError("Invalid or missing CPU_TRIGGER_THRESHOLD value");
        return false;
    }

    // check that all boolean settings do have the correct datatype
    set<string> boolean_settings = {
        file_content["NO_CHECK"],
        file_content["FREEZE"],
        file_content["OOM_KILL_ENABLED"],
        file_content["PID_KILL_ENABLED"],
        file_content["REGEX_SEARCH_ENABLED"],
        file_content["SEND_PROCESS_FILES"],
        file_content["ENABLE_LIMITING"],
        file_content["INCLUDE_BINARY_FOLDER_CHECK"],
        file_content["WILDCARD_MATCH"]
    };
    for (auto b : boolean_settings) {
        if (!b.empty() && !Utils::isZeroOneValue(&b)) {
            logger->logError("Expected Integer '1' or '2' instead of '" + b + "'");
            return false;
        }
    }

    // check if memory-limit is absolut Mem Value
    if (!file_content["ENABLE_LIMITING"].empty()) {
        if (stoi(file_content["ENABLE_LIMITING"]) > 0) {

            string mem_limit_setting = file_content["LIMIT_MEMORY_VALUE"];
            if (!Utils::isMemValue(&mem_limit_setting)) {
                logger->logError("Invalid or missing LIMIT_MEMORY_VALUE value");
                return false;
            }

            string cpu_limit_setting = file_content["LIMIT_CPU_PERCENT"];
            if (!Utils::isPercentValue(&cpu_limit_setting)) {
                logger->logError("Invalid or missing LIMIT_CPU_PERCENT value");
                return false;
            }
        }
    }

    // check if value is int
    set<string> int_settings = {
        file_content["CHECKS_BEFORE_ALERT"]
    };
    for (auto i : int_settings) {
        if (!i.empty() && !Utils::isIntegerValue(&i) && !Utils::isDisableValue(&i)) {
            logger->logError("Expected Integer Value instead of '" + i + "'");
            return false;

        }
    }

    // return true if all checks are passed
    return true;
}

bool RuleManager::registerRule(unordered_map<string, string> file_content) {

	try {

		Rule rule;

		// mandatory rule settings first
		rule.rule_name = file_content["RULE_NAME"];

        if (!file_content["COMMAND"].empty()) rule.command = file_content["COMMAND"];
        if (!file_content["REGEX_SEARCH_PATTERN"].empty()) rule.regex_search_pattern = file_content["REGEX_SEARCH_PATTERN"];

        // CPU_TRIGGER_THRESHOLD can either be a percent value ('.' and '%' signs are not mandatory) or a 0 to disable the check
        // the default-value from settings-file will be used if no value for this setting was provided
        string cpu_trigger_threshold = file_content["CPU_TRIGGER_THRESHOLD"];
        if (!cpu_trigger_threshold.empty() && !Utils::isDisableValue(&cpu_trigger_threshold)) {

            cpu_trigger_threshold.erase(remove_if(cpu_trigger_threshold.begin(), cpu_trigger_threshold.end(), ::isspace), cpu_trigger_threshold.end());
            rule.cpu_trigger_threshold = stod(cpu_trigger_threshold);

            // check if the value is in percent and above 100%
            if (rule.cpu_trigger_threshold > 100) {
                logger->logError("Value for CPU_TRIGGER_THRESHOLD must be between 0% - 100% or disabled with '0'");
                return false;
            }

        // value is set to '0' and therefore the check is deactivated
        } else if (!cpu_trigger_threshold.empty() && Utils::isDisableValue(&cpu_trigger_threshold)) {
            rule.cpu_trigger_threshold = 0;

        // CPU_TRIGGER_THRESHOLD is not set in this rule, therefore value from global settings-file should be used
        } else {
            rule.cpu_trigger_threshold = -1;
        }

        // MEM_TRIGGER_THRESHOLD can either be a percent value ('.' and '%' signs are not mandatory), an absolute value
        // (which can be set e.g. 1024B, 512K, 1M, etc.) or a 0 to disable the check
        string mem_trigger_threshold = file_content["MEM_TRIGGER_THRESHOLD"];
        if (!mem_trigger_threshold.empty() && !Utils::isDisableValue(&mem_trigger_threshold)) {

            mem_trigger_threshold.erase(remove_if(mem_trigger_threshold.begin(), mem_trigger_threshold.end(), ::isspace), mem_trigger_threshold.end());

            // check if value is percent-value
            if (Utils::isPercentValue(&mem_trigger_threshold)) {

                // check if the value is in percent and above 100% of the total amount of RAM on the system
                if (stod(mem_trigger_threshold) > 100) {
                    logger->logError("Value for MEM_TRIGGER_THRESHOLD must be between 0% - 100%, an absolute value or disabled with '0'");
                    return false;
                }
                rule.mem_trigger_threshold = static_cast<long long> (Utils::total_ram * stod(mem_trigger_threshold)) / 100;

            // value is not an percent-value and is therefore an absolute-value
            } else {

                string mem_trigger_threshold_unit;
                mem_trigger_threshold_unit = mem_trigger_threshold.back();

                // remove the unit at the end
                mem_trigger_threshold = mem_trigger_threshold.substr(0, mem_trigger_threshold.size()-1);
                rule.mem_trigger_threshold = Utils::convertToBytes(mem_trigger_threshold_unit, mem_trigger_threshold);

                // check if the RAM limit is higher than the total amount of RAM on the system
                if (rule.mem_trigger_threshold > Utils::total_ram) {
                    logger->logError("Value for MEM_TRIGGER_THRESHOLD is above the total amount of RAM of this system");
                    return false;
                }
            }

        // value is set to '0' and therefore the check is deactivated
        } else if (!mem_trigger_threshold.empty() && Utils::isDisableValue(&mem_trigger_threshold)) {
            rule.mem_trigger_threshold = 0;

        // MEM_TRIGGER_THRESHOLD is not set in this rule, therefore value from global settings-file should be used
        } else {
            rule.mem_trigger_threshold = -1;
        }

		// check if values are valid (e.g. not negative values)
        string checks_before_alert = file_content["CHECKS_BEFORE_ALERT"];
        if (!checks_before_alert.empty() && Utils::isIntegerValue(&checks_before_alert)) {
            rule.checks_before_alert = stoi(checks_before_alert);
            if (rule.checks_before_alert <= 0) {
                logger->logError("Value for CHECKS_BEFORE_ALERT must be higher than 0");
				return false;
            }
        } else {
            rule.checks_before_alert = -1;
        }

        // LIMIT_CPU_PERCENT
		if (!file_content["LIMIT_CPU_PERCENT"].empty()) {
			rule.limit_cpu_percent = stoi(file_content["LIMIT_CPU_PERCENT"]);
            if ((rule.limit_cpu_percent < 0) || (rule.limit_cpu_percent > 100)) {
                logger->logError("Value for LIMIT_CPU_PERCENT must be between 0% - 100%");
				return false;
            }
        } else {
            rule.limit_cpu_percent = -1;
        }

        // LIMIT_MEMORY_VALUE
		if (!file_content["LIMIT_MEMORY_VALUE"].empty()) {

            string limit_memory_value = file_content["LIMIT_MEMORY_VALUE"];
            string limit_memory_value_unit;

            // remove all whitespaces
            limit_memory_value.erase(remove_if(limit_memory_value.begin(), limit_memory_value.end(), ::isspace), limit_memory_value.end());

            // retrieve the unit for this value
            limit_memory_value_unit = limit_memory_value.back();
            transform(limit_memory_value_unit.begin(), limit_memory_value_unit.end(), limit_memory_value_unit.begin(), ::tolower);

            rule.limit_memory_value = Utils::convertToBytes(limit_memory_value_unit, limit_memory_value);

            if (rule.limit_memory_value < 0) {
                logger->logError("Value for LIMIT_MEMORY_VALUE must be higher than 0");
				return false;
            }
        } else {
            rule.limit_memory_value = -1;
        }

		// optional rule settings
		(file_content["NO_CHECK"] == "1") ? rule.no_check = true : rule.no_check = false;
		(file_content["FREEZE"] == "1") ? rule.freeze = true : rule.freeze = false;
        (file_content["REGEX_SEARCH_ENABLED"] == "1") ? rule.regex_search_enabled = true : rule.regex_search_enabled = false;
		(file_content["OOM_KILL_ENABLED"] == "1") ? rule.oom_kill_enabled = true : rule.oom_kill_enabled = false;
		(file_content["PID_KILL_ENABLED"] == "1") ? rule.pid_kill_enabled = true : rule.pid_kill_enabled = false;
        (file_content["SEND_NOTIFICATIONS"] == "1") ? rule.send_notifications = true : rule.send_notifications = false;
		(file_content["ENABLE_LIMITING"] == "1") ? rule.enable_limiting = true : rule.enable_limiting = false;
		(file_content["INCLUDE_BINARY_FOLDER_CHECK"] == "1") ? rule.include_binary_folder_check = true : rule.include_binary_folder_check = false;
		(file_content["WILDCARD_MATCH"] == "1") ? rule.wildcard_match = true : rule.wildcard_match = false;

        // make sure that a valid regex search pattern is given if REGEX_SEARCH_ENABLED is enabled
        if (rule.regex_search_enabled && rule.regex_search_pattern.empty()) {
            logger->logError("REGEX_SEARCH_PATTERN must be set if REGEX_SEARCH_ENABLED is set");
            return false;
        }

        // the rule would be useless if no COMMAND is set and REGEX_SEARCH_ENABLED is disabled, therefore simply drop it
        if (!rule.regex_search_enabled && !rule.regex_search_pattern.empty() && rule.command.empty()) {
            logger->logError("REGEX_SEARCH_ENABLED must be enabled if REGEX_SEARCH_PATTERN is set but no COMMAND is set");
            return false;
        }

        // a rule should only contain either a valid REGEX_SEARCH_PATTERN or COMMAND
        if (rule.regex_search_enabled && !rule.regex_search_pattern.empty() && !rule.command.empty()) {
            logger->logError("REGEX_SEARCH_PATTERN and COMMAND is set, only one option is allowed per rule");
            return false;
        }

        // inform the user that WILDCARD_MATCH and INCLUDE_BINARY_FOLDER_CHECK have no effect if REGEX_SEARCH_ENABLED is set
        if (rule.regex_search_enabled && (rule.include_binary_folder_check || rule.wildcard_match)) {
            logger->logInfo("REGEX_SEARCH_ENABLED is set, therefore WILDCARD_MATCH and INCLUDE_BINARY_FOLDER_CHECK have no effect");
            rule.include_binary_folder_check = 0;
            rule.wildcard_match = 0;
        }

        // cgroup name
        rule.cgroup_name = DAEMON_NAME "-" + rule.rule_name;

		// cgroup root dir
        rule.cgroup_root_dir = CGROUP_ROOT + rule.cgroup_name;

		// create all needed file references for this cgroup
        rule.cgroup_subtree_control_file = rule.cgroup_root_dir + CGROUP_SUBCONTR_FILE;
        rule.cgroup_cpu_max_file = rule.cgroup_root_dir + CGROUP_CPU_MAX_FILE;
        rule.cgroup_procs_file = rule.cgroup_root_dir + CGROUP_PROCS_FILE;
        rule.cgroup_memory_high_file = rule.cgroup_root_dir + CGROUP_MEM_HIGH_FILE;
        rule.cgroup_memory_max_file = rule.cgroup_root_dir + CGROUP_MEM_MAX_FILE;
        rule.cgroup_freezer_file = rule.cgroup_root_dir + CGROUP_FREEZE_FILE;

		// register this rule to the global rulemanager
        rules.insert(pair<string, Rule>(rule.rule_name, rule));

        if (logger->getLogLevel() >= DEBUG1) {
            logger->logDebug(logger->SEPARATOR_LINE);
            if (rule.regex_search_enabled) logger->logDebug("regex_search_pattern: " +rule.regex_search_pattern);
            else {
                logger->logDebug("command: " + rule.command);
                logger->logDebug("wildcard_match: " + to_string(rule.wildcard_match));
                logger->logDebug("include_binary_folder_check: " + to_string(rule.include_binary_folder_check));
            }
            logger->logDebug("checks_before_alert: " + to_string(rule.checks_before_alert));
            logger->logDebug("cpu_trigger_threshold: " + to_string(rule.cpu_trigger_threshold));
            logger->logDebug("mem_trigger_threshold: " + to_string(rule.mem_trigger_threshold));
            logger->logDebug("limit_cpu_percent: " + to_string(rule.limit_cpu_percent));
            logger->logDebug("limit_memory_value: " + to_string(rule.limit_memory_value));
            logger->logDebug("enable_limiting: " + to_string(rule.enable_limiting));
            logger->logDebug("oom_kill_enabled: " + to_string(rule.oom_kill_enabled));
            logger->logDebug("pid_kill_enabled: " + to_string(rule.pid_kill_enabled));
            logger->logDebug("freezer: " + to_string(rule.freeze));
            logger->logDebug("no_check: " + to_string(rule.no_check));
            logger->logDebug("send_notifications: " + to_string(rule.send_notifications));
            logger->logDebug(logger->SEPARATOR_LINE);
        }

		return true;

	} catch (...) {
		return false;
	}

}

bool RuleManager::createCgroup(Rule* rule) {

	// at least one cgroup setting must be set otherwise rule is broken
	if ( rule->limit_cpu_percent >= 0 || rule->limit_memory_value >= 0 ||  rule->freeze || rule->oom_kill_enabled || rule->pid_kill_enabled) {

		// check if the cgroup already exists, otherwise create it
		if (fs::exists(rule->cgroup_root_dir.c_str())) {
            logger->logInfo("Cgroup " + rule->cgroup_root_dir + " already exists!");
		}
		else {

			if (mkdir(rule->cgroup_root_dir.c_str(), 0755) != -1) {
                logger->logInfo("Created cgroup " + rule->cgroup_root_dir);
			}
			else {
                logger->logError("Unable to create cgroup " + rule->cgroup_root_dir);
				return false;
			}
		}

		// prepare the freezer file for the given cgroup
		string freeze;
		if (rule->freeze) {	freeze = "1"; }
		else { freeze = "0"; }
		if (!Utils::writeToFile(rule->cgroup_freezer_file, freeze)) {
            logger->logError("Something went wrong while modifying " + rule->cgroup_freezer_file);
			return false;
		}

        if (rule->limit_cpu_percent > 0) {
            // prepare the cpu.max file for the given cgroup
            string cpu_max = Utils::generateMaxCPU(rule->limit_cpu_percent, rule->cgroup_cpu_max_file);

            if (!Utils::writeToFile(rule->cgroup_cpu_max_file, cpu_max)) {
                logger->logError("Something went wrong while modifying " + rule->cgroup_cpu_max_file);
                return false;
            }
        }

        if (rule->limit_memory_value > 0) {
            // prepare the memory.high and memory.max file for the given cgroup
            string memory_value;
            if (rule->limit_memory_value > 0) { memory_value = to_string(rule->limit_memory_value); }
            else { memory_value = "max"; }
            if (!Utils::writeToFile(rule->cgroup_memory_high_file, memory_value)) {
                logger->logError("Something went wrong while modifying " + rule->cgroup_memory_high_file);
                return false;
            }
            if (rule->oom_kill_enabled) {
                if (!Utils::writeToFile(rule->cgroup_memory_max_file, memory_value)) {
                    logger->logError("Something went wrong while modifying " + rule->cgroup_memory_max_file);
                    return false;
                }
            }
        }
	}

	return true;
}

Rule* RuleManager::loadIfRuleExists(string command) {

	// iterate all available rules
    for (auto& r : rules) {

        if (r.second.include_binary_folder_check && !r.second.wildcard_match && !r.second.regex_search_enabled) {
			// check if the command starts with the command-string from rule with all possible binary-folder prefixes
            if (command.rfind(r.second.command, 0) == 0
                || command.rfind("/bin/" + r.second.command, 0) == 0
                || command.rfind("/sbin/" + r.second.command, 0) == 0
                || command.rfind("/usr/bin/" + r.second.command, 0) == 0
                || command.rfind("/usr/sbin/" + r.second.command, 0) == 0
                || command.rfind("/usr/local/bin/" + r.second.command, 0) == 0
                || command.rfind("/usr/local/sbin/" + r.second.command, 0) == 0
            ) {
                return &rules[r.first];
			}
        } else if (r.second.wildcard_match && !r.second.regex_search_enabled) {

            // check for command wildcard-match against the rule
            if (command.find(r.second.command) != string::npos) return &rules[r.first];

        } else if (r.second.regex_search_enabled) {

            // check command against regex-pattern from rule
            if (regex_match(command, regex(r.second.regex_search_pattern))) return &rules[r.first];

        } else if (!r.second.regex_search_enabled) {
			// check if the command starts with the command-string from rule
            if (command.rfind(r.second.command, 0) == 0) return &rules[r.first];
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
        logger->logError("Rule file " + filename + " is not present or readable!");
		current_rule_content.success = false;
		current_rule_content.rule = rule;
	}
	else {
		if (rules_file.is_open()) {
			string line;
			while(getline(rules_file, line)) {
                if (available_rule_settings.find(line.substr(0, line.find("="))) != available_rule_settings.end()) {
                    rule.insert(pair<string,string>(line.substr(0, line.find("=")),line.substr(line.find("=")+1)));
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
    logger->logInfo(logger->SEPARATOR_LINE);
    logger->logInfo(rule.rule_name);
    logger->logInfo(logger->SEPARATOR_LINE);
    logger->logInfo("command: " + rule.command);
    logger->logInfo("regex_search_pattern: " + rule.regex_search_pattern);
    logger->logInfo("regex_search_enabled: " + to_string(rule.regex_search_enabled));
    logger->logInfo("no_check: " + to_string(rule.no_check));
    logger->logInfo("cpu_trigger_threshold: " + to_string(rule.cpu_trigger_threshold));
    logger->logInfo("mem_trigger_threshold: " + to_string(rule.mem_trigger_threshold));
    logger->logInfo("freeze: " + to_string(rule.freeze));
    logger->logInfo("oom_kill_enabled: " + to_string(rule.oom_kill_enabled));
    logger->logInfo("pid_kill_enabled: " + to_string(rule.pid_kill_enabled));
    logger->logInfo("send_notifications: " + to_string(rule.send_notifications));
    logger->logInfo("enable_limiting: " + to_string(rule.enable_limiting));
    logger->logInfo("checks_before_alert: " + to_string(rule.checks_before_alert));
    logger->logInfo("limit_cpu_percent: " + to_string(rule.limit_cpu_percent));
    logger->logInfo("limit_memory_value: " + to_string(rule.limit_memory_value));
    logger->logInfo("cgroup_root_dir: " + rule.cgroup_root_dir);
    logger->logInfo("cgroup_subtree_control_file: " + rule.cgroup_subtree_control_file);
    logger->logInfo("cgroup_name: " + rule.cgroup_name);
    logger->logInfo("cgroup_cpu_max_file: " + rule.cgroup_cpu_max_file);
    logger->logInfo("cgroup_procs_file: " + rule.cgroup_procs_file);
    logger->logInfo("cgroup_memory_high_file: " + rule.cgroup_memory_high_file);
    logger->logInfo("cgroup_memory_max_file: " + rule.cgroup_memory_max_file);
    logger->logInfo("cgroup_freezer_file: " + rule.cgroup_freezer_file);
    logger->logInfo("include_binary_folder_check: " + to_string(rule.include_binary_folder_check));
    logger->logInfo("wildcard_match: " + to_string(rule.wildcard_match));
    logger->logInfo(logger->SEPARATOR_LINE);
}

void RuleManager::showRules() {
    for (auto& r : rules) {
		showRuleContent(r.second);
	}
}
