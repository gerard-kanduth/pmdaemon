#include "settings.h"

Settings *Settings::settingsinstance = nullptr;

Settings::Settings() {

    settingsinstance = nullptr;
    logger = Logger::getInstance();
    config_success = readSettings();

}

Settings *Settings::getInstance() {
    if (!settingsinstance) settingsinstance = new Settings();
    return settingsinstance;
}

bool Settings::configAvailable() {
    return config_success;
}

void Settings::logTotalRAM() {
    logger->logInfo("Total System RAM: " + to_string(Utils::total_ram) + " Bytes");
}

bool Settings::readSettings() {
    settings_file.open(SETTINGS_FILE, ios::in);
    if (!settings_file) {
        logger->logError("Settings file " SETTINGS_FILE " is not present or readable!");
        return false;
    }
    else {
        if (settings_file.is_open()) {
            string line;
            while(getline(settings_file, line)) {
                if (available_settings.find(line.substr(0, line.find("="))) != available_settings.end()) settings.insert(std::pair<string,string>(line.substr(0, line.find("=")),line.substr(line.find("=")+1)));
            }
            settings_file.close();
        }
    }
    return true;
}

bool Settings::getSendNotifications() {
    try {

        string sn = settings["SEND_NOTIFICATIONS"];
        if (!Utils::isZeroOneValue(sn)) throw 2;

        int send_notifications = stoi(sn);
        logger->logInfo("Setting SEND_NOTIFICATIONS to \'" + to_string(send_notifications) + "\'");
        if (send_notifications == 1) return true;
        else return false;

    } catch (...) {
        logger->logError("Invalid SEND_NOTIFICATIONS value in configuration!");
        logger->logDebug("Allowed Values: [ '1' (ON), '0' (OFF) ]");
        exit(EXIT_FAILURE);
    }
}

bool Settings::getGraylogEnabled() {
    try {

        string ge = settings["GRAYLOG_ENABLED"];
        if (!Utils::isZeroOneValue(ge)) throw 2;

        int graylog_enabled = stoi(ge);
        logger->logInfo("Setting GRAYLOG_ENABLE to \'" + to_string(graylog_enabled) + "\'");
        if (graylog_enabled == 1) return true;
        else return false;

    } catch (...) {
        logger->logError("Invalid GRAYLOG_ENABLED value in configuration!");
        logger->logDebug("Allowed Values: [ '1' (ON), '0' (OFF) ]");
        exit(EXIT_FAILURE);
    }
}

bool Settings::getLogstashEnabled() {
    try {

        string le = settings["LOGSTASH_ENABLED"];
        if (!Utils::isZeroOneValue(le)) throw 2;

        int logstash_enabled = stoi(le);
        logger->logInfo("Setting LOGSTASH_ENABLE to \'" + to_string(logstash_enabled) + "\'");
        if (logstash_enabled == 1) return true;
        else return false;

    } catch (...) {
        logger->logError("Invalid LOGSTASH_ENABLE value in configuration!");
        logger->logDebug("Allowed Values: [ '1' (ON), '0' (OFF) ]");
        exit(EXIT_FAILURE);
    }
}

bool Settings::getGraylogHTTPSecure() {
    try {

        string ghs = settings["GRAYLOG_HTTP_SECURE"];
        if (!Utils::isZeroOneValue(ghs)) throw 2;

        int graylog_http_secure = stoi(ghs);
        logger->logInfo("Setting GRAYLOG_HTTP_SECURE to \'" + to_string(graylog_http_secure) + "\'");
        if (graylog_http_secure == 1) return true;
        else return false;

    } catch (...) {
        logger->logError("Invalid GRAYLOG_HTTP_SECURE value in configuration!");
        logger->logDebug("Allowed Values: [ '1' (ON), '0' (OFF) ]");
        exit(EXIT_FAILURE);
    }
}

bool Settings::getLogstashHTTPSecure() {
    try {

        string lhs = settings["LOGSTASH_HTTP_SECURE"];
        if (!Utils::isZeroOneValue(lhs)) throw 2;

        int logstash_http_secure = stoi(lhs);
        logger->logInfo("Setting LOGSTASH_HTTP_SECURE to \'" + to_string(logstash_http_secure) + "\'");
        if (logstash_http_secure == 1) return true;
        else return false;

    } catch (...) {
        logger->logError("Invalid LOGSTASH_HTTP_SECURE value in configuration!");
        logger->logDebug("Allowed Values: [ '1' (ON), '0' (OFF) ]");
        exit(EXIT_FAILURE);
    }
}

bool Settings::getStateTrigger() {
    try {

        string st = settings["STATE_TRIGGER"];
        if (!Utils::isZeroOneValue(st)) throw 2;

        int state_trigger = stoi(st);
        logger->logInfo("Setting STATE_TRIGGER to \'" + to_string(state_trigger) + "\'");
        if (state_trigger == 1) return true;
        else return false;

    } catch (...) {
        logger->logError("Invalid STATE_TRIGGER value in configuration!");
        logger->logDebug("Allowed Values: [ '1' (ON), '0' (OFF) ]");
        exit(EXIT_FAILURE);
    }
}

bool Settings::getLoadRules() {
    try {

        string lr = settings["LOAD_RULES"];
        if (!Utils::isZeroOneValue(lr)) throw 2;

        int load_rules = stoi(lr);
        logger->logInfo("Setting LOAD_RULES to \'" + to_string(load_rules) + "\'");
        if (load_rules == 1) return true;
        else return false;

    } catch (...) {
        logger->logError("Invalid LOAD_RULES value in configuration!");
        logger->logDebug("Allowed Values: [ '1' (ON), '0' (OFF) ]");
        exit(EXIT_FAILURE);
    }
}

bool Settings::getSpecificRulesCheckOnly() {
    try {
        string srco = settings["SPECIFIC_RULES_CHECK_ONLY"];
        if (!Utils::isZeroOneValue(srco)) throw 2;

        int specific_rules_check_only = stoi(srco);
        logger->logInfo("Setting SPECIFIC_RULES_CHECK_ONLY to \'" + to_string(specific_rules_check_only) + "\'");
        if (specific_rules_check_only == 1) return true;
        else return false;

    } catch (...) {
        logger->logError("Invalid SPECIFIC_RULES_CHECK_ONLY value in configuration!");
        logger->logDebug("Allowed Values: [ '1' (ON), '0' (OFF) ]");
        exit(EXIT_FAILURE);
    }
}

bool Settings::getTermCgroupCleanup() {
    try {

        string tcc = settings["TERM_CGROUP_CLEANUP"];
        if (!Utils::isZeroOneValue(tcc)) throw 2;

        int term_cgroup_cleanup = stoi(tcc);
        logger->logInfo("Setting TERM_CGROUP_CLEANUP to \'" + to_string(term_cgroup_cleanup) + "\'");
        if (term_cgroup_cleanup == 1) return true;
        else return false;

    } catch (...) {
        logger->logError("Invalid TERM_CGROUP_CLEANUP value in configuration!");
        logger->logDebug("Allowed Values: [ '1' (ON), '0' (OFF) ]");
        exit(EXIT_FAILURE);
    }
}

bool Settings::getGlobalActionEnabled() {
    try {

        string gae = settings["GLOBAL_ACTION_ENABLED"];
        if (!Utils::isZeroOneValue(gae)) throw 2;

        int global_action_enabled = stoi(gae);
        logger->logInfo("Setting GLOBAL_ACTION_ENABLED to \'" + to_string(global_action_enabled) + "\'");
        if (global_action_enabled == 1) return true;
        else return false;

    } catch (...) {
        logger->logError("Invalid GLOBAL_ACTION_ENABLED value in configuration!");
        logger->logDebug("Allowed Values: [ '1' (ON), '0' (OFF) ]");
        exit(EXIT_FAILURE);
    }
}

set<string> Settings::getWhitelistedUsers() {
    try {

        string wuser_string = settings["WHITELISTED_USERS"];
        if (!Utils::isCommaSepStringValue(wuser_string)) throw 2;

        set<string> whitelisted_users;
        whitelisted_users = Utils::generateStringSet(wuser_string);

        if (!whitelisted_users.empty()) logger->logInfo("Setting WHITELISTED_USERS to \'" + Utils::setToComSepString(whitelisted_users) + "\'");
        else logger->logInfo("Setting WHITELISTED_USERS to \'\'");
        return whitelisted_users;

    } catch (...) {
        logger->logError("Invalid WHITELISTED_USERS value in configuration!");
        logger->logDebug("Userlist must be comma-separated if multiple users should be set. Example Values: [ 'root,dbus,daemon', 'root' ]");
        exit(EXIT_FAILURE);
    }
}

double Settings::getCpuTriggerThreshold() {
    try {

        string ctt = settings["CPU_TRIGGER_THRESHOLD"];
        if (!Utils::isPercentValue(ctt) && !Utils::isDisableValue(ctt)) throw 2;

        // CPU_TRIGGER_THRESHOLD is percentage value
        if (Utils::isPercentValue(ctt)) {

            ctt.erase(std::remove_if(ctt.begin(), ctt.end(), ::isspace), ctt.end());

            double cpu_trigger_threshold = stod(ctt.c_str());
            char buffer[16]; snprintf(buffer, 16, "%.2f", cpu_trigger_threshold);
            string cpu_trigger_threshold_string(buffer);
            logger->logInfo("Setting CPU_TRIGGER_THRESHOLD to \'" + cpu_trigger_threshold_string + "%\'");
            return cpu_trigger_threshold;

        // CPU_TRIGGER_THRESHOLD is set to 0, therefore no global cpu monitoring will be performed
        } else {
            logger->logInfo("Setting CPU_TRIGGER_THRESHOLD to '0' (CPU check disabled)");
            return 0;
        }

    } catch (...) {
        logger->logError("Invalid CPU_TRIGGER_THRESHOLD value in configuration!");
        logger->logDebug("Allowed Values: [ '0%' - '100%', '0.0%' - '100.0%', '0' (disable CPU check) ]");
        exit(EXIT_FAILURE);
    }
}

double Settings::getJailCPULimit() {
    try {

        string jcl = settings["JAIL_CPU_LIMIT"];
        if (!Utils::isPercentValue(jcl)) throw 2;

        jcl.erase(std::remove_if(jcl.begin(), jcl.end(), ::isspace), jcl.end());

        double jail_cpu_limit = stod(jcl.c_str());
        char buffer[16]; snprintf(buffer, 16, "%.2f", jail_cpu_limit);
        string jail_cpu_limit_string(buffer);
        logger->logInfo("Setting JAIL_CPU_LIMIT to \'" + jail_cpu_limit_string + "%\'");
        return jail_cpu_limit;

    } catch (...) {
        logger->logError("Invalid JAIL_CPU_LIMIT value in configuration!");
        logger->logDebug("Allowed Values: [ '0%' - '100%', '0.0%' - '100.0%', '0' (disable CPU limit) ]");
        exit(EXIT_FAILURE);
    }
}

long long Settings::getMemTriggerThreshold() {

    long long mv;

    try {

        string mtt = settings["MEM_TRIGGER_THRESHOLD"];
        string mtt_unit;

        if (!Utils::isMemValue(mtt) && !Utils::isDisableValue(mtt)) throw 2;

        mtt.erase(std::remove_if(mtt.begin(), mtt.end(), ::isspace), mtt.end());
        mtt_unit = mtt.back();
        transform(mtt_unit.begin(), mtt_unit.end(), mtt_unit.begin(), ::tolower);

        if (Utils::isPercentValue(mtt)) {
            mv = (Utils::total_ram * stod(mtt)) / 100;

        } else if (Utils::isAbsoluteMemValue(mtt)) {
            mv = Utils::convertToBytes(mtt_unit, mtt.substr(0, mtt.size()-1));

        } else {
            logger->logInfo("Setting MEM_TRIGGER_THRESHOLD to '0' (memory check disabled)");
            return 0;
        }

        char mtt_percent[32];
        snprintf(mtt_percent, 32, "%.2f", ((mv / (double) Utils::total_ram) * 100));

        logger->logInfo("Setting MEM_TRIGGER_THRESHOLD to \'" + to_string(mv) + " Bytes\' (" + mtt_percent + "% of total system memory)");

        return mv;

    } catch (...) {
        mv = (Utils::total_ram * 50) / 100;
        logger->logError("Invalid MEM_TRIGGER_THRESHOLD value in configuration!");
        logger->logDebug("Allowed Values: [ '0%' - '100%', '0.0%' - '100.0%', 1 - 1E+32 (B|K|M|G|T|P), '0' (disable memory check) ]");
        exit(EXIT_FAILURE);
    }

}

long long Settings::getJailMEMLimit() {
    try {

        string jml = settings["JAIL_MEM_LIMIT"];
        if (!Utils::isMemValue(jml)) throw 2;

        string jml_unit;
        long long jml_bytes;

        // remove all whitespaces
        jml.erase(std::remove_if(jml.begin(), jml.end(), ::isspace), jml.end());

        jml_unit = jml.back();
        transform(jml_unit.begin(), jml_unit.end(), jml_unit.begin(), ::tolower);

        if (Utils::isPercentValue(jml)) {

            // remove percent sign
            jml.erase(jml.find_first_of('%'));
            jml_bytes = static_cast<long>((Utils::total_ram * stod(jml)) / 100);

        } else if (Utils::isAbsoluteMemValue(jml)) {
            jml_bytes = Utils::convertToBytes(jml_unit, jml.substr(0, jml.size()-1));

        } else {
            logger->logInfo("Setting JAIL_MEM_LIMIT to '0' (Memory Limit disabled)");
            return 0;
        }

        logger->logInfo("Setting JAIL_MEM_LIMIT to \'" + to_string(jml_bytes) + " Bytes\'");
        return static_cast<long long>(jml_bytes);

    } catch (...) {
        logger->logError("Invalid JAIL_MEM_LIMIT value in configuration!");
        logger->logDebug("Allowed Values: [ '0%' - '100%', '0.0%' - '100.0%', 1 - 1E+32 (B|K|M|G|T|P), '0' (disable memory limit) ]");
        exit(EXIT_FAILURE);
    }
}

int Settings::getGraylogPort() {
    try {

        string gp = settings["GRAYLOG_PORT"];
        if (!Utils::isIntegerValue(gp)) throw 2;

        int graylog_port = stoi(gp);
        if (graylog_port > 0) {
            logger->logInfo("Setting GRAYLOG_PORT to \'" + to_string(graylog_port) + "\'");
            return graylog_port;
        }
        else throw 2;

    } catch (...) {
        logger->logError("Invalid GRAYLOG_PORT value in configuration!");
        logger->logDebug("Allowed Values: [ '1' - '1E+32' ]");
        exit(EXIT_FAILURE);
    }
}

int Settings::getLogstashPort() {
    try {

        string lp = settings["LOGSTASH_PORT"];
        if (!Utils::isIntegerValue(lp)) throw 2;

        int logstash_port = stoi(lp);
        if (logstash_port > 0) {
            logger->logInfo("Setting LOGSTASH_PORT to \'" + to_string(logstash_port) + "\'");
            return logstash_port;
        }
        else throw 2;

    } catch (...) {
        logger->logError("Invalid LOGSTASH_PORT value in configuration!");
        logger->logDebug("Allowed Values: [ '1' - '1E+32' ]");
        exit(EXIT_FAILURE);
    }
}

int Settings::getCheckInterval() {
    try {

        string ci = settings["CHECK_INTERVAL"];
        if (!Utils::isIntegerValue(ci)) throw 2;

        int check_interval = stoi(ci);
        if (check_interval > 0) {
            logger->logInfo("Setting CHECK_INTERVAL to \'" + to_string(check_interval) + "\'");
            return check_interval;
        }
        else throw 2;

    } catch (...) {
        logger->logError("Invalid CHECK_INTERVAL value in configuration!");
        logger->logDebug("Allowed Values: [ '1' - '1E+32' ]");
        exit(EXIT_FAILURE);
    }
}

int Settings::getChecksBeforeAlert() {
    try {

        string cba = settings["CHECKS_BEFORE_ALERT"];
        if (!Utils::isIntegerValue(cba)) throw 2;

        int checks_before_alert = stoi(cba);
        if (checks_before_alert > 0) {
            logger->logInfo("Setting CHECKS_BEFORE_ALERT to \'" + to_string(checks_before_alert) + "\'");
            return checks_before_alert;
        }
        else throw 2;

    } catch (...) {
        logger->logError("Invalid CHECKS_BEFORE_ALERT value in configuration!");
        logger->logDebug("Allowed Values: [ '1' - '1E+32' ]");
        exit(EXIT_FAILURE);
    }
}

int Settings::getChecksCooldown() {
    try {

        string cc = settings["CHECKS_COOLDOWN"];
        if (!Utils::isIntegerValue(cc)) throw 2;

        int checks_cooldown = stoi(cc);
        if (checks_cooldown > 0) {
            logger->logInfo("Setting CHECKS_COOLDOWN to \'" + to_string(checks_cooldown) + "\'");
            return checks_cooldown;
        }
        else throw 2;

    } catch (...) {
        logger->logError("Invalid CHECKS_COOLDOWN value in configuration!");
        logger->logDebug("Allowed Values: [ '1' - '1E+32' ]");
        exit(EXIT_FAILURE);
    }
}

int Settings::getMaxErrors() {
    try {

        string me = settings["MAX_ERRORS"];
        if (!Utils::isIntegerValue(me)) throw 2;

        int max_errors = stoi(me);
        if (max_errors >= 0) {
            logger->logInfo("Setting MAX_ERRORS to \'" + to_string(max_errors) + "\'");
            return max_errors;
        }
        else throw 2;

    } catch (...) {
        logger->logError("Invalid MAX_ERRORS value in configuration!");
        logger->logDebug("Allowed Values: [ '1' - '1E+32' ]");
        exit(EXIT_FAILURE);
    }
}

int Settings::getMaxAlertGlobalAction() {
    try {

        string maga = settings["MAX_ALERTS_GLOBAL_ACTION"];
        if (!Utils::isIntegerValue(maga)) throw 2;

        int max_alert_global_action = stoi(maga);
        if (max_alert_global_action > 0) {
            logger->logInfo("Setting MAX_ALERTS_GLOBAL_ACTION to \'" + to_string(max_alert_global_action) + "\'");
            return max_alert_global_action;
        }
        else throw 2;

    } catch (...) {
        logger->logError("Invalid MAX_ALERTS_GLOBAL_ACTION value in configuration!");
        logger->logDebug("Allowed Values: [ '1' - '1E+32' ]");
        exit(EXIT_FAILURE);
    }
}

int Settings::getDebugLevel() {
    try {

        string dl = settings["DEBUG_LEVEL"];
        if (!Utils::isIntegerValue(dl)) throw 2;

        int debug_level = stoi(dl);
        if (debug_level > 0 && debug_level <= 2) {
            return debug_level;
        }
        else throw 2;

    } catch (...) {
        logger->logError("Invalid DEBUG_LEVEL value in configuration!");
        logger->logDebug("Allowed Values: [ '1', '2' ]");
        exit(EXIT_FAILURE);
    }
}

string Settings::getGraylogFQDN() {
    try {

        string graylog_fqdn = settings["GRAYLOG_FQDN"];
        if (!Utils::isFQDNValue(graylog_fqdn)) throw 2;

        transform(graylog_fqdn.begin(), graylog_fqdn.end(), graylog_fqdn.begin(), ::tolower);
        graylog_fqdn.erase(std::remove_if(graylog_fqdn.begin(), graylog_fqdn.end(), ::isspace), graylog_fqdn.end());

        logger->logInfo("Setting GRAYLOG_FQDN to \'" + graylog_fqdn + "\'");
        return graylog_fqdn;

    } catch (...) {
        logger->logError("Invalid GRAYLOG_FQDN value in configuration!");
        logger->logDebug("Allowed Values: [ a-z, A-Z, 0-9, '-', '.' ]");
        exit(EXIT_FAILURE);
    }
}

string Settings::getLogstashFQDN() {
    try {

        string logstash_fqdn = settings["LOGSTASH_FQDN"];
        if (!Utils::isFQDNValue(logstash_fqdn)) throw 2;

        transform(logstash_fqdn.begin(), logstash_fqdn.end(), logstash_fqdn.begin(), ::tolower);
        logstash_fqdn.erase(std::remove_if(logstash_fqdn.begin(), logstash_fqdn.end(), ::isspace), logstash_fqdn.end());

        logger->logInfo("Setting LOGSTASH_FQDN to \'" + logstash_fqdn + "\'");
        return logstash_fqdn;

    } catch (...) {
        logger->logError("Invalid LOGSTASH_FQDN value in configuration!");
        logger->logDebug("Allowed Values: [ a-z, A-Z, 0-9, '-', '.' ]");
        exit(EXIT_FAILURE);
    }
}

string Settings::getGraylogHTTPPath() {
    try {

        string graylog_http_path = settings["GRAYLOG_HTTP_PATH"];
        transform(graylog_http_path.begin(), graylog_http_path.end(), graylog_http_path.begin(), ::tolower);
        if (!graylog_http_path.empty() && graylog_http_path.find('/') != std::string::npos) {
            logger->logInfo("Setting GRAYLOG_HTTP_PATH to \'" + graylog_http_path + "\'");
            return graylog_http_path;
        }
        else throw 2;

    } catch (...) {
        logger->logError("Invalid GRAYLOG_HTTP_PATH value in configuration!");
        logger->logDebug("Path must start with '/'. Allowed Values: [ a-z, A-Z, 0-9, '-', '.' ]");
        exit(EXIT_FAILURE);
    }
}

string Settings::getLogstashHTTPPath() {
    try {

        string logstash_http_path = settings["LOGSTASH_HTTP_PATH"];
        transform(logstash_http_path.begin(), logstash_http_path.end(), logstash_http_path.begin(), ::tolower);
        if (!logstash_http_path.empty() && logstash_http_path.find('/') != std::string::npos) {
            logger->logInfo("Setting LOGSTASH_HTTP_PATH to \'" + logstash_http_path + "\'");
            return logstash_http_path;
        }
        else throw 2;

    } catch (...) {
        logger->logError("Invalid LOGSTASH_HTTP_PATH value in configuration!");
        logger->logDebug("Path must start with '/'. Allowed Values: [ a-z, A-Z, 0-9, '-', '.' ]");
        exit(EXIT_FAILURE);
    }
}

TransportType Settings::getGraylogTransportMethod() {
    try {

        TransportType tt;
        string graylog_transport_method = settings["GRAYLOG_TRANSFER_METHOD"];
        transform(graylog_transport_method.begin(), graylog_transport_method.end(), graylog_transport_method.begin(), ::tolower);
        graylog_transport_method.erase(std::remove_if(graylog_transport_method.begin(), graylog_transport_method.end(), ::isspace), graylog_transport_method.end());

        if (graylog_transport_method == "http") tt = HTTP;
        else if (graylog_transport_method == "udp") tt = UDP;
        else if (graylog_transport_method == "tcp") tt = TCP;
        else throw 2;

        logger->logInfo("Setting GRAYLOG_TRANSFER_METHOD to \'" + graylog_transport_method + "\'");
        return tt;

    } catch (...) {
        logger->logError("Invalid GRAYLOG_TRANSFER_METHOD value in configuration!");
        logger->logDebug("Allowed Values: [ 'http', 'tcp', 'udp' ]");
        exit(EXIT_FAILURE);
    }
}

TransportType Settings::getLogstashTransportMethod() {
    try {

        TransportType tt;
        string logstash_transport_method = settings["LOGSTASH_TRANSFER_METHOD"];
        transform(logstash_transport_method.begin(), logstash_transport_method.end(), logstash_transport_method.begin(), ::tolower);
        logstash_transport_method.erase(std::remove_if(logstash_transport_method.begin(), logstash_transport_method.end(), ::isspace), logstash_transport_method.end());

        if (logstash_transport_method == "http") tt = HTTP;
        else if (logstash_transport_method == "udp") tt = UDP;
        else if (logstash_transport_method == "tcp") tt = TCP;
        else throw 2;

        logger->logInfo("Setting LOGSTASH_TRANSFER_METHOD to \'" + logstash_transport_method + "\'");
        return tt;

    } catch (...) {
        logger->logError("Invalid LOGSTASH_TRANSFER_METHOD value in configuration!");
        logger->logDebug("Allowed Values: [ 'http', 'tcp', 'udp' ]");
        exit(EXIT_FAILURE);
    }
}

GlobalAction Settings::getGlobalAction() {
    try {

        GlobalAction ga;
        string global_action = settings["GLOBAL_ACTION"];
        transform(global_action.begin(), global_action.end(), global_action.begin(), ::tolower);
        global_action.erase(std::remove_if(global_action.begin(), global_action.end(), ::isspace), global_action.end());

        if (global_action == "kill") ga = ACTION_KILL;
        else if (global_action == "freeze") ga = ACTION_FREEZE;
        else if (global_action == "jail") ga = ACTION_JAIL;
        else throw 2;

        logger->logInfo("Setting GLOBAL_ACTION to \'" + global_action + "\'");
        return ga;

    } catch (...) {
        logger->logError("Invalid GLOBAL_ACTION value in configuration!");
        logger->logDebug("Allowed Values: [ 'kill', 'freeze', 'jail' ]");
        exit(EXIT_FAILURE);
    }
}

string Settings::getLogLevel() {
    try {

        string log_level = settings["LOGLEVEL"];
        transform(log_level.begin(), log_level.end(), log_level.begin(), ::tolower);

        if (log_level == "info" || log_level == "notice" || log_level == "debug" || log_level == "error") return log_level;
        else throw 2;

    } catch (...) {
        logger->logError("Invalid LOGLEVEL value in configuration!");
        logger->logDebug("Allowed Values: [ 'info', 'notice', 'error', 'debug' ]");
        exit(EXIT_FAILURE);
    }
}

string Settings::getRulesDir() {
    try {

        if (settings["RULES_DIRECTORY"].empty()) return "/etc/pmdaemon/rules.d";
        else return settings["RULES_DIRECTORY"];

    } catch (...) {
        logger->logError("Invalid RULES_DIRECTORY value in configuration!");
        logger->logDebug("Path must start with '/'. Allowed Values: [ a-z, A-Z, 0-9, '-', '.' ]");
        exit(EXIT_FAILURE);
    }
}

// for debug purpose only
void Settings::showSettings() {
    for (auto s : settings) std::cout << s.first << "\t-> " << s.second << '\n';
}
