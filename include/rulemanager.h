#ifndef RULES
#define RULES

#include <filesystem>
#include <fstream>
#include <unordered_map>
#include <regex>
#include <set>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <typeinfo>
#include <unistd.h>
#include "logger.h"
#include "utils.h"
#include "rule.h"
#include "settings.h"

namespace fs = std::filesystem;
using namespace std;

class RuleManager {

    private:

        // Logger Instance
        Logger* logger = nullptr;

        struct RuleReturn {
            bool success;
            unordered_map<string, string> rule;
        };

        const set<string> mandatory_rule_settings {
            "RULE_NAME"
        };

        const set<string> available_rule_settings {
            "RULE_NAME",
            "COMMAND",
            "REGEX_SEARCH_ENABLED",
            "REGEX_SEARCH_PATTERN",
            "NO_CHECK",
            "FREEZE",
            "OOM_KILL_ENABLED",
            "PID_KILL_ENABLED",
            "SEND_NOTIFICATIONS",
            "CPU_TRIGGER_THRESHOLD",
            "MEM_TRIGGER_THRESHOLD",
            "ENABLE_LIMITING",
            "LIMIT_CPU_PERCENT",
            "LIMIT_MEMORY_VALUE",
            "INCLUDE_BINARY_FOLDER_CHECK",
            "WILDCARD_MATCH",
            "CHECKS_BEFORE_ALERT"
        };

        const char* rules_directory = nullptr;

        unordered_map<string, Rule> rules;

        bool createCgroup(Rule&);
        bool checkIfRuleIsValid(unordered_map<string, string>);
        bool generateRuleFromFile(string);
        bool registerRule(unordered_map<string, string>);
        void loadRules();
        void showRuleContent(Rule);
        RuleReturn readRuleFile(string);

    public:

        RuleManager(string);
        Rule* loadIfRuleExists(string);
        void showRules();

};

#endif
