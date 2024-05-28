#include "controller.h"

// UNUSED macro for hiding "unused parameter" warnings due to future TODO's
#define UNUSED(object) (void)(object)

Controller::Controller() {

    settings = Settings::getInstance();
    logger = Logger::getInstance();

    logger->logNotice("Initializing the controller");
    logger->logInfo("Loading configuration file " SETTINGS_FILE);
    gethostname(hostname_buffer, sizeof(hostname_buffer));
    hostname = hostname_buffer;

    settings->logTotalRAM();

    // load available settings
    max_errors = settings->getMaxErrors();
    default_cpu_trigger_threshold = settings->getCpuTriggerThreshold();
    default_mem_trigger_threshold = settings->getMemTriggerThreshold();
    default_checks_before_alert = settings->getChecksBeforeAlert();
    default_send_notifications = settings->getSendNotifications();
    state_trigger = settings->getStateTrigger();
    checks_cooldown = settings->getChecksCooldown();
    graylog_enabled = settings->getGraylogEnabled();
    logstash_enabled = settings->getLogstashEnabled();
    load_rules = settings->getLoadRules();
    specific_rules_check_only = settings->getSpecificRulesCheckOnly();
    term_cgroup_cleanup = settings->getTermCgroupCleanup();
    global_action_enabled = settings->getGlobalActionEnabled();
    global_action = settings->getGlobalAction();
    max_alerts_global_action = settings->getMaxAlertGlobalAction();
    whitelisted_users = settings->getWhitelistedUsers();

    if (graylog_enabled) {
        graylog_transport_method = settings->getGraylogTransportMethod();
        graylog_port = settings->getGraylogPort();
        graylog_fqdn = settings->getGraylogFQDN();
        graylog_http_path = settings->getGraylogHTTPPath();
        graylog_http_secure = settings->getGraylogHTTPSecure();

        if (graylog_transport_method == HTTP) {

            if (graylog_http_secure)
                graylog_http_protocol_prefix = "https://";
            else
                graylog_http_protocol_prefix = "http://";
            graylog_final_url = graylog_http_protocol_prefix + graylog_fqdn + ":" + to_string(graylog_port) + graylog_http_path;

            logger->logInfo("Alerts will be forwarded to " + graylog_final_url);
        }
    }

    if (logstash_enabled) {
        logstash_transport_method = settings->getLogstashTransportMethod();
        logstash_port = settings->getLogstashPort();
        logstash_fqdn = settings->getLogstashFQDN();
        logstash_http_path = settings->getLogstashHTTPPath();
        logstash_http_secure = settings->getLogstashHTTPSecure();

        if (logstash_transport_method == HTTP) {

            if (logstash_http_secure)
                logstash_http_protocol_prefix = "https://";
            else
                logstash_http_protocol_prefix = "http://";
            logstash_final_url = logstash_http_protocol_prefix+logstash_fqdn + ":" + to_string(logstash_port)+logstash_http_path;

            logger->logInfo("Alerts will be forwarded to " + logstash_final_url);
        }
    }

    if ((graylog_enabled || logstash_enabled) && (graylog_transport_method == HTTP || logstash_transport_method == HTTP)) {
        // setup the curl environment
        // libcurl, see: https://curl.se/libcurl/c/curl_global_init.html
        curl_global_init(CURL_GLOBAL_ALL);
    }

    // controllers for cgroupv2 needs to be enabled for jail and/or cgroup rules
    if (global_action == ACTION_JAIL || load_rules) {
        if (!enableCgroupControllers())    exit(EXIT_FAILURE);
    }

    if (global_action == ACTION_JAIL) {
        if (!createJailCgroup(settings->getJailCPULimit(), settings->getJailMEMLimit())) {
            logger->logError("Unable to create jail-cgroup " JAIL_CGROUP "! Action 'jail' will not function properly without jail-cgroup, therefore please check.");
            exit(EXIT_FAILURE);
        }
    }

    // load rules if not deactivated in the settings
    if (load_rules) {
        rulemanager = new RuleManager(settings->getRulesDir());
    }

}

Controller::~Controller() {
    logger->logInfo("Terminating the controller");

    // cleanup of curl environment
    // libcurl, see: https://curl.se/libcurl/c/curl_global_cleanup.html
    curl_global_cleanup();
}

bool Controller::doCheck() {
    logger->logDebug("[ Checking processes ]");
    try {

        // iterate over process-list and check processes
        if (!iterateProcessList()) throw 1;

        // penalty list needs to be cleaned
        if (!cleanupPenaltyList()) throw 1;

    // catch if an error occurs during check-cycle
    } catch (...) {
        logger->logError("Unable to iterate process list!");
        error_checks++;

        // terminate if number of failed checks exceeded
        if (error_checks >= max_errors){
            logger->logError("More than " + to_string(max_errors)+ " errors during check-routine! Terminating Daemon ...");
            return false;
        }
    }
    return true;
}

bool Controller::enableCgroupControllers() {
    logger->logInfo("Enabling needed cgroup2 controllers");

    if (Utils::writeToFile(CGROUP_SUBCONT_FILE, "+cpu +cpuset +memory +pids\n")) {
        return true;
    } else {
        logger->logError("Unable to enable controllers! Terminating.");
        return false;
    }

}

// only fetch needed information for further checkProcess() function
bool Controller::fetchProcessInfo(long pid) {

    // start always in false state to ensure that all process-information is available
    c_process.valid = false;

    // set the /proc/<pid> directory for the process
    c_process.proc_pid_dir = PROC_DIR "/" + to_string(pid);

    // set the pid for the process
    c_process.pid = pid;

    // fetch the UID/username of the given process
    stat(c_process.proc_pid_dir.c_str(), &stat_buf);
    c_process.uid = stat_buf.st_uid;

    if ((pwd = getpwuid(c_process.uid)) != NULL) {
        c_process.user = pwd->pw_name;

        // no check if the process is running as one of the global whitelisted users
        if (whitelisted_users.find(c_process.user) != whitelisted_users.end()) {
            return false;
        }
    }

    // read the /proc/<pid>/cmdline or (if daemon/service) the /proc/<pid>/comm file
    out_cmdline = Utils::readFromFile(c_process.proc_pid_dir + "/cmdline", true);
    if (out_cmdline.empty()) {
        out_cmdline = Utils::readFromFile(c_process.proc_pid_dir + "/comm", true);
    }

    // read and parse the process'es /proc/<pid>/stat file
    c_process.proc_pid_stat = Utils::parsePIDStatFile(pid);

    // calculate overall cpu-time
    c_process.proc_pid_stat.total_time = c_process.proc_pid_stat.utime + c_process.proc_pid_stat.stime;

    if (c_process.proc_pid_stat.valid)
    {

        // populate the pcpu_pid_list (needed for pcpu calculation)
        if (pcpu_pid_list.find(c_process.pid) != pcpu_pid_list.end()) {
            c_process.proc_pid_stat.delta_total_time = POSDIFF(c_process.proc_pid_stat.total_time, pcpu_pid_list[c_process.pid]);
            pcpu_pid_list[c_process.pid] = c_process.proc_pid_stat.total_time;
        } else {
            c_process.proc_pid_stat.delta_total_time = 0;
            pcpu_pid_list.insert({c_process.pid, c_process.proc_pid_stat.total_time});
        }

        // calculate pcpu
        c_process.pcpu = Utils::calcPercentCPU(&system_stat.delta_total_time, &c_process.proc_pid_stat.delta_total_time);

    } else {
        // process could already be terminated
        return false;
    }

    // command (either cmdline or comm if kernel-thread)
    c_process.command = out_cmdline;

    // state of process
    c_process.state = c_process.proc_pid_stat.state;

    // amount of pages multiplied by page_size in Bytes
    c_process.rss = c_process.proc_pid_stat.rss * page_size;

    // calculate the percent of memory for this pid compared to total memory
    c_process.pmem = ((double) c_process.rss / Utils::total_ram) * 100;

    // process will only be monitored if valid
    c_process.valid = true;

    return true;
}

bool Controller::iterateProcessList() {
    try {

        // need to be done since a new object will be created
        if (system_stat.total_time != 0) sys_last_total_time = system_stat.total_time;

        // system time-delta is used for pcpu calculation
        system_stat = Utils::parseStatFile();
        system_stat.last_total_time = sys_last_total_time;
        system_stat.delta_total_time = (system_stat.total_time - system_stat.last_total_time) / system_stat.active_cores;

        // current pid list needs to be cleared each cycle
        current_pids.clear();

        // further processing is only possible if system_stat is available
        if (system_stat.valid) {

            logger->logDebug(logger->SEPARATOR_LINE);

            // retrieve all process-directories of /proc
            for (auto& file: fs::directory_iterator(PROC_DIR)) {

                proc_pid_file = file.path().filename().string();

                if (is_directory(file.path()) && regex_match(proc_pid_file, regex_pid_value)) {

                    c_process_pid = stol(proc_pid_file);
                    current_pids.insert(c_process_pid);

                    // don't check daemon's own pid
                    if (c_process_pid == daemon_pid) continue;

                    // check the current process
                    if (fetchProcessInfo(c_process_pid)) checkProcess(&c_process);

                }
            }

            if (logger->getLogLevel() == DEBUG2) {
                showInformation(false);
            }

        }

    } catch (...) {
        logger->logError("Something went wrong while iterating the process list!");
        return false;
    }

    // erase PIDs from the monitoring which are no longer alive
    for (auto it = pcpu_pid_list.begin(); it != pcpu_pid_list.end();)
    {
        if (current_pids.find(it->first) == current_pids.end()) it = pcpu_pid_list.erase(it);
        else ++it;
    }

    return true;
}

bool Controller::checkProcess(Process* process) {

    if (logger->getLogLevel() >= DEBUG1) {
        stringstream ss;
        ss << "PID: " << to_string(process->pid);
        ss << " STATE: " << process->state;
        ss << " USER: " << process->user;
        ss << " RSS: " << to_string(process->rss);
        ss << " PMEM: " << to_string(process->pmem);
        ss << " PCPU: " << to_string(process->pcpu);
        ss << " COMM: " << process->command;
        logger->logDebug(ss.str());
    }

    // check if a specific rule for the command is available if LOAD_RULES is enabled
    if (load_rules) {

        specific_rule = rulemanager->loadIfRuleExists(process->command);

        if (specific_rule != nullptr) {

            specific_proc_rule = true;

            // skip command if the NO_CHECK setting is set in rule
            if (specific_rule->no_check) {
                if (logger->getLogLevel() >= DEBUG1) logger->logDebug("Skipping PID '" + to_string(process->pid) + "' due to NO_CHECK in rule " + specific_rule->rule_name);
                return true;

            } else {

                // load all available settings from specific rule
                // default values from settings-file will be used if value is '-1'
                (specific_rule->cpu_trigger_threshold != -1) ? cpu_trigger_threshold = &specific_rule->cpu_trigger_threshold : cpu_trigger_threshold = &default_cpu_trigger_threshold;
                (specific_rule->mem_trigger_threshold != -1) ? mem_trigger_threshold = &specific_rule->mem_trigger_threshold : mem_trigger_threshold = &default_mem_trigger_threshold;
                (specific_rule->checks_before_alert != -1) ? checks_before_alert = &specific_rule->checks_before_alert : checks_before_alert = &default_checks_before_alert;
                send_notifications = &specific_rule->send_notifications;

                if (logger->getLogLevel() == DEBUG2) logger->logDebug("Checking '" + process->command + "' with PID '" + to_string(process->pid) + "' using rule '" + specific_rule->rule_name + "'");

            }

        } else {

            // needs to be set before dropping out if SPECIFIC_RULES_CHECK_ONLY is enabled
            cpu_trigger_threshold = &default_cpu_trigger_threshold;
            mem_trigger_threshold = &default_mem_trigger_threshold;
            checks_before_alert = &default_checks_before_alert;
            send_notifications = &default_send_notifications;
            specific_proc_rule = false;

            // do not check processes if SPECIFIC_RULES_CHECK_ONLY is enabled
            if (specific_rules_check_only) return true;

        }
    }

    // check if threshold is reached, add the PID to penalty list if so
    // value of '0' will disable the CPU monitoring
    if (*cpu_trigger_threshold > 0 && process->pcpu > *cpu_trigger_threshold) {
        logger->logDebug("PID " + to_string(process->pid)+ " has a load of " + to_string(process->pcpu)
                         + " [Limit: " + to_string(*cpu_trigger_threshold) + " %]");
         return checkPenaltyList(process, "cpu");
    }

    // memory can either be compared in percent or absolute values but will always be compared with RSS value of PID
    // value of '0' will disable the memory monitoring
    if (*mem_trigger_threshold > 0 && process->rss > *mem_trigger_threshold) {
        logger->logDebug("PID " + to_string(process->pid)+ " uses "
                         + to_string(process->rss) + " Bytes of RAM (" + to_string(process->pmem)
                         + "% of Total System RAM) [Limit: " + to_string(*mem_trigger_threshold) + " Bytes]");
        return checkPenaltyList(process, "mem");
    }

    // check the status of the process if STATE_TRIGGER is enabled
    if (state_trigger) {
        if (process->state == "Z") {
            logger->logDebug("PID " + to_string(process->pid) + " state changed to ZOMBIE (" + process->state + ")");
            return checkPenaltyList(process, "zombie");
        }

        if (process->state == "D") {
            logger->logDebug("PID " + to_string(process->pid) + " state changed to UNINTERRUPTIBLE SLEEP (" + process->state + ")");
            return checkPenaltyList(process, "dstate");
        }
    }

    return true;

}

// check if PID is on penalty list, if not add it
bool Controller::checkPenaltyList(Process *process, string penalty_cause) {

    // if pid is in penalty list raise counter
    penalty_list_it = penalty_list.begin();
    penalty_list_it = penalty_list.find(process->pid);
    if (penalty_list_it != penalty_list.end()
            && penalty_list_it->second.penalty_cause == penalty_cause
            && penalty_list_it->second.start_time == process->proc_pid_stat.start_time) {

        logger->logDebug("PID " + to_string(process->pid) + " is already on penalty list.");

        if (!penalty_list_it->second.in_cgroup && !penalty_list_it->second.alerted) penalty_list_it->second.penalty_counter++;

        // alert if not already alerted
        if (penalty_list_it->second.penalty_counter >= *checks_before_alert
                && !penalty_list_it->second.alerted
                && !penalty_list_it->second.in_cgroup) {

            penalty_list_it->second.penalty_counter = 0;

            if (*send_notifications) {
                if (graylog_enabled || logstash_enabled) SendMessage(collectProcessInfo(process, penalty_cause), ALERT);
            }

            // check if pid is on global_penalty_list if enabled
            if (!specific_proc_rule && global_action_enabled) {

                stringstream ss;
                ss  << " PID: "   << to_string(process->pid)
                    << " UID: "   << to_string(process->uid)
                    << " USER: "  << process->user
                    << " CAUSE: " << penalty_cause
                    << " PCPU: "  << to_string(process->pcpu)
                    << " PMEM: "  << to_string(process->pmem)
                    << " RSS: "   << to_string(process->rss);

                // check if pid is on global penalty list
                global_penalty_list_it = global_penalty_list.begin();
                global_penalty_list_it = global_penalty_list.find(process->pid);

                // pid is on list
                if (global_penalty_list_it != global_penalty_list.end()
                        && global_penalty_list_it->second.penalty_cause == penalty_cause
                        && global_penalty_list_it->second.start_time == process->proc_pid_stat.start_time
                        && !global_penalty_list_it->second.in_cgroup) {

                    logger->logDebug("PID " + to_string(process->pid) + " is already on global penalty list.");
                    if (global_penalty_list_it->second.alert_counter < max_alerts_global_action) global_penalty_list_it->second.alert_counter++;

                    // perform desired action if max_alerts was reached
                    if (global_penalty_list_it->second.alert_counter == max_alerts_global_action) {

                        switch (global_action) {
                        case ACTION_KILL:
                            if (pidKill(process->pid)) {
                                global_penalty_list.erase(global_penalty_list_it);
                                logger->logInfo("ACTION: global-kill" + ss.str());
                                if (*send_notifications && (graylog_enabled || logstash_enabled))
                                    SendMessage(collectProcessInfo(process, penalty_cause), GLOBAL_KILL);
                            }
                            break;
                        case ACTION_FREEZE:
                            if (pidPause(process->pid)) {
                                global_penalty_list.erase(global_penalty_list_it);
                                logger->logInfo("ACTION: global-freeze" + ss.str());
                                if (*send_notifications && (graylog_enabled || logstash_enabled))
                                    SendMessage(collectProcessInfo(process, penalty_cause), GLOBAL_FREEZE);
                            }
                            break;
                        case ACTION_JAIL:
                            if (addPidToJail(process->pid)) {
                                global_penalty_list[process->pid].in_cgroup = true;
                                global_penalty_list[process->pid].cgroup_name = JAIL_CGROUP CGROUP_PID_PREFIX + to_string(process->pid);
                                logger->logInfo("ACTION: jail" + ss.str());
                                if (*send_notifications && (graylog_enabled || logstash_enabled))
                                    SendMessage(collectProcessInfo(process, penalty_cause), JAIL);
                            }
                            break;
                        default:
                            break;
                        }
                    }

                } else if (global_penalty_list_it != global_penalty_list.end() && global_penalty_list_it->second.in_cgroup) {

                    // simply continue if PID was already limited
                    return true;

                } else {
                    // add the pid to the global penalty list if not found
                    GlobalPenaltyListItem global_penalty_pid;
                    global_penalty_pid.pid = process->pid;
                    global_penalty_pid.start_time = process->proc_pid_stat.start_time;
                    global_penalty_pid.alert_counter = 1;
                    global_penalty_pid.penalty_cause = penalty_cause;
                    global_penalty_pid.cgroup_name = "none";
                    global_penalty_list[process->pid] = global_penalty_pid;
                    logger->logDebug("Added PID " + to_string(process->pid) + " (" + process->user + ") to global penalty list due to " + penalty_cause + ".");
                }

            }

            penalty_list_it->second.alerted = true;

            if (specific_rule != nullptr) {

                stringstream ss;
                ss  << " RULE: "  << specific_rule->rule_name
                    << " PID: "   << to_string(process->pid)
                    << " UID: "   << to_string(process->uid)
                    << " CAUSE: " << penalty_cause
                    << " PCPU: "  << to_string(process->pcpu)
                    << " PMEM: "  << to_string(process->pmem)
                    << " RSS: "   << to_string(process->rss);

                // if ENABLE_LIMITING is set to 1 limit the process and add it to the corresponding cgroup
                if (specific_rule->enable_limiting) {
                    if (doLimit(process)) {
                            penalty_list_it->second.in_cgroup = true;
                            logger->logInfo("ACTION: limit" + ss.str());
                            if (*send_notifications && (graylog_enabled || logstash_enabled))
                                SendMessage(collectProcessInfo(process, penalty_cause), LIMIT);
                    } else {
                        logger->logError("[" + specific_rule->rule_name + "] Unable to add PID " + to_string(process->pid) + " to cgroup " + specific_rule->cgroup_name);
                    }
                }

                // if PID_KILL_ENABLED is set to 1 simply kill the process
                if (specific_rule->pid_kill_enabled) {
                    if (!pidKill(process->pid)) {
                        logger->logError("Unable to terminate PID " + to_string(process->pid));
                        return false;
                    }
                    logger->logInfo("ACTION: kill" + ss.str());
                    if (*send_notifications && (graylog_enabled || logstash_enabled))
                        SendMessage(collectProcessInfo(process, penalty_cause), KILL);
                    return true;
                }

                // if FREEZE is set to 1 simply pause the process
                if (specific_rule->freeze) {
                    if (!pidPause(process->pid)) {
                        logger->logError("Unable to pause PID " + to_string(process->pid));
                        return false;
                    }
                    logger->logInfo("ACTION: freeze" + ss.str());
                    if (*send_notifications && (graylog_enabled || logstash_enabled))
                        SendMessage(collectProcessInfo(process, penalty_cause), FREEZE);
                    return true;
                }
            }

        } else if (penalty_list_it->second.in_cgroup) {
            // pid is already in cgroup, therefore only discard pid from penalty_list if cgroup is no longer present
            if (!fs::exists(penalty_list_it->second.cgroup_name)) {
                penalty_list.erase(penalty_list_it);
                penalty_list_it = penalty_list.end();
            }
            return true;

        } else {
            // decrease cooldown-counter if already alerted
            // check if cooldown-counter not 0, otherwise remove pid from list
            if (penalty_list_it->second.penalty_cause != "zombie" && penalty_list_it->second.penalty_cause != "dstate") {

                if (penalty_list_it->second.cooldown_counter > 0 && penalty_list_it->second.alerted) {
                    penalty_list_it->second.cooldown_counter--;
                } else if (penalty_list_it->second.cooldown_counter <= 0)
                    penalty_list.erase(penalty_list_it);
            }
        }

    } else {
        // add the pid to the penalty list if not found
        PenaltyListItem penalty_pid;
        penalty_pid.pid = process->pid;
        penalty_pid.start_time = process->proc_pid_stat.start_time;
        penalty_pid.penalty_counter = 1;
        penalty_pid.cooldown_counter = checks_cooldown;
        penalty_pid.penalty_cause = penalty_cause;

        penalty_list[process->pid] = penalty_pid;
        logger->logDebug("Added PID " + to_string(process->pid) + " (" + process->user + ") to penalty list due to " + penalty_cause + ".");
    }

    return true;
}

bool Controller::pidPause(long pid) {
    if (kill(pid, SIGSTOP) == 0) return true;
    else return false;
}

bool Controller::pidKill(long pid) {
    if (kill(pid, SIGKILL) == 0) return true;
    else return false;
}

bool Controller::cleanupPenaltyList() {

    // penalty list cleanup
    if (!penalty_list.empty()) {

        penalty_list_it = penalty_list.begin();
        while (penalty_list_it != penalty_list.end()) {

            if (fs::exists(PROC_DIR "/" + to_string(penalty_list_it->first))) {
                penalty_list_it++;
            } else {
                penalty_list_it = penalty_list.find(penalty_list_it->first);

                if (penalty_list_it->second.limited) {
                    removeCgroup(penalty_list_it->second.cgroup_name);
                }

                logger->logInfo("Removing PID " + to_string(penalty_list_it->first) + " from penalty list");
                penalty_list.erase(penalty_list_it);
                penalty_list_it = penalty_list.end();
                break;
            }
        }
    }

    // global penalty list cleanup
    if (global_action_enabled && !global_penalty_list.empty()) {

        global_penalty_list_it = global_penalty_list.begin();
        while (global_penalty_list_it != global_penalty_list.end()) {

            if (fs::exists(PROC_DIR "/" + to_string(global_penalty_list_it->first))) {
                global_penalty_list_it++;
            } else {
                global_penalty_list_it = global_penalty_list.find(global_penalty_list_it->first);

                if (global_penalty_list_it->second.in_cgroup) removeCgroup(global_penalty_list_it->second.cgroup_name);

                logger->logInfo("Removing PID " + to_string(global_penalty_list_it->first) + " from global penalty list");
                global_penalty_list.erase(global_penalty_list_it);
                global_penalty_list_it = global_penalty_list.end();
                break;
            }
        }
    }

    return true;
}

bool Controller::addPIDToCgroup(string* cgroup_parent_group, long* pid) {

    stringstream cgroup;
    stringstream cgroup_procs_file;
    cgroup << *cgroup_parent_group << CGROUP_PID_PREFIX << to_string(*pid);
    cgroup_procs_file << cgroup.str() << CGROUP_PROCS_FILE;

    if (!fs::exists(cgroup.str())) createPIDCgroup(cgroup_parent_group, pid);

    return Utils::writeToFile(cgroup_procs_file.str(), to_string(*pid));

}

bool Controller::addPidToJail(long pid) {

    stringstream jail_cgrp;
    jail_cgrp << JAIL_CGROUP CGROUP_PID_PREFIX << to_string(pid);

    if (!fs::exists(jail_cgrp.str())) createJailPIDCgroup(jail_cgrp.str());

    return Utils::writeToFile(jail_cgrp.str() + CGROUP_PROCS_FILE, to_string(pid));

}

bool Controller::checkIfCgroupEmpty(string* cgroup_parent_group, long* pid) {

    stringstream proc_file_name;
    proc_file_name << *cgroup_parent_group << CGROUP_PID_PREFIX << to_string(*pid) << CGROUP_CUR_PIDS_FILE;

    fstream proc_file;
    proc_file.open(proc_file_name.str(), ios::in);

    if (proc_file.is_open()) {
        string line;
        getline(proc_file, line);
        proc_file.close();

        if (stoi(line) == 0) return true;
        else return false;

    } else {
        logger->logError("Unable to read file " + proc_file_name.str());
        proc_file.close();
        return false;
    }

}

bool Controller::cleanupCgroups(bool remove_cgroups) {

    logger->logNotice("Starting cgroup cleanup. Jailed PIDs will be freed.");

    bool cleanup_successful = true;
    long pid;

    // remove all PIDs from created cgroups
    for (auto& dir: fs::directory_iterator(CGROUP_ROOT)) {
        string cgroup_root_dir = dir.path().filename().string();
        if (is_directory(dir.path()) && regex_match(cgroup_root_dir, regex_daemon_cgroup)) {
            for (auto& sub_dir: fs::directory_iterator(dir)) {
                if (is_directory(sub_dir.path())) {
                    string cgroup_sub_dir = sub_dir.path().filename().string();
                    ifstream infile(sub_dir.path().string() + CGROUP_PROCS_FILE);
                    while (infile >> pid)
                    {
                        logger->logDebug("Removing PID " + to_string(pid) + " from cgroup " + cgroup_sub_dir);
                        if (!removePidFromCgroup(pid)) {
                            logger->logError("Unable to remove " + to_string(pid) + " from penalty list.");
                            cleanup_successful = false;
                        }
                    }
                    // remove the sub-dirs in cgroups if true parameter
                    if (remove_cgroups) cleanup_successful = removeCgroup(sub_dir.path().string());
                }
            }
            // remove the parent cgroup if true parameter
            if (remove_cgroups) cleanup_successful = removeCgroup(dir.path().string());
        }
    }

    // remove all currently monitored PIDs from penalty list
    for (auto it = penalty_list.begin(); it != penalty_list.end();)
    {
        if (it != penalty_list.end()) it = penalty_list.erase(it);
        else ++it;
    }

    // remove all currently monitored PIDs from global penalty list
    for (auto it = global_penalty_list.begin(); it != global_penalty_list.end();)
    {
        if (it != global_penalty_list.end()) it = global_penalty_list.erase(it);
        else ++it;
    }

    return cleanup_successful;
}

bool Controller::createPIDCgroup(string* cgroup_parent_group, long* pid) {

    stringstream cgroup;
    cgroup << *cgroup_parent_group << CGROUP_PID_PREFIX << to_string(*pid);

    if (mkdir(cgroup.str().c_str(), 0755) != -1) {
        logger->logInfo("Created cgroup " + cgroup.str());
        return true;
    }
    else {
        logger->logError("Unable to create cgroup " + cgroup.str());
        return false;
    }
}

bool Controller::createJailPIDCgroup(string cgroup_name) {

    if (mkdir(cgroup_name.c_str(), 0755) != -1) {
        logger->logInfo("Created cgroup " + cgroup_name);
        return true;
    }
    else {
        logger->logError("Unable to create jail-cgroup " + cgroup_name);
        return false;
    }
}

bool Controller::createJailCgroup(double cpu_limit, long long mem_limit) {

    if (logger->getLogLevel() >= DEBUG1) {
        logger->logDebug(logger->SEPARATOR_LINE);
        logger->logDebug("jailed-pids-cgroup: " JAIL_CGROUP);
        logger->logDebug("jail_mem_limit: " + to_string(mem_limit));
        logger->logDebug("jail_cpu_limit: " + to_string(cpu_limit));
        logger->logDebug(logger->SEPARATOR_LINE);
    }

    // check if the cgroup already exists, otherwise create it
    if (!fs::exists(JAIL_CGROUP)) {

        if (mkdir(JAIL_CGROUP, 0755) != -1) {
            logger->logInfo("Created " DAEMON_NAME "-jailed-pids cgroup " JAIL_CGROUP);
        }
        else {
            logger->logError("Unable to create cgroup " DAEMON_NAME "-jailed-pids cgroup " JAIL_CGROUP);
            return false;
        }
    }

    // prepare the cpu.max file
    string cpu_jail_max = Utils::generateJailMaxCPU(cpu_limit);

    logger->logDebug("Adding '" + cpu_jail_max + "' to file " JAIL_CGROUP_CPU_MAX_FILE);

    if (!Utils::writeToFile(JAIL_CGROUP_CPU_MAX_FILE, cpu_jail_max)) {
        logger->logError("Something went wrong while modifying " JAIL_CGROUP_CPU_MAX_FILE);
        return false;
    }

    // prepare the memory.max file
    string memory_jail_value;
    if (mem_limit > 0) { memory_jail_value = to_string(mem_limit); }
    else { memory_jail_value = "max"; }

    logger->logDebug("Adding '" + memory_jail_value + "' to file " JAIL_CGROUP_MEM_MAX_FILE);

    if (!Utils::writeToFile(JAIL_CGROUP_MEM_MAX_FILE, memory_jail_value)) {
        logger->logError("Something went wrong while modifying " JAIL_CGROUP_MEM_MAX_FILE);
        return false;
    }

    return true;

}

bool Controller::doLimit(Process* process) {
    return addPIDToCgroup(&specific_rule->cgroup_root_dir, &process->pid);
}

bool Controller::removeCgroup(string cgroup) {

    if (fs::exists(cgroup)) {
        if (filesystem::remove(cgroup)) {
            logger->logInfo("Removed cgroup " + cgroup);
            return true;
        }
        else {
            logger->logError("Unable to remove cgroup " + cgroup);
            return false;
        }
    }
    return true;
}

bool Controller::removePidFromCgroup(long pid) {
    return Utils::writeToFile(CGROUP_MAIN_PROCS_FILE, to_string(pid));
}

// collect information about the process
ProcessInfo Controller::collectProcessInfo(Process* process, string cause) {

    ProcessInfo process_info;
    process_info._process = *process;
    process_info._cause = cause;

    // read /proc/<pid>/status
    process_info._status = readProcFile("status", &process->pid);

    // read /proc/<pid>/io
    process_info._io = readProcFile("io", &process->pid);

    // read /proc/<pid>/limits
    process_info._limits = readProcFile("limits", &process->pid);

    // read /proc/<pid>/syscall
    process_info._syscall = readProcFile("syscall", &process->pid);

    // read /proc/<pid>/cgroup
    process_info._cgroup = readProcFile("cgroup", &process->pid);

    // read /proc/<pid>/loginuid
    process_info._loginuid = readProcFile("loginuid", &process->pid);

    // read /proc/<pid>/stack
    process_info._stack = readProcFile("stack", &process->pid);

    // read /proc/<pid>/environ
    process_info._environ = readProcFile("environ", &process->pid);

    return process_info;
}

// used to read files from pseudo-filesystem from /proc/<pid>/ - see https://linux.die.net/man/5/proc
string Controller::readProcFile(string filename, long* pid) {
    try {
        string proc_file_content;
        ifstream proc_file(PROC_DIR "/" + to_string(*pid) + "/" + filename);
        if (proc_file.is_open()) {
            string line;
            while(getline(proc_file, line)){
                proc_file_content += line + "\n";
            }
        }
        proc_file.close();
        return proc_file_content;
    } catch (...) {
        logger->logError("Unable to read from " PROC_DIR "/" + to_string(*pid) + "/" + filename);
        return "no data";
    }
}

void Controller::SendMessage(ProcessInfo process_info, MessageType mtype) {

    Process *proc = &process_info._process;

    string short_message;
    string json_data;
    string message_type;

    // remove trailing zeroes on measured values
    snprintf(limit_pcpu, 32, "%.2f", proc->pcpu);
    snprintf(limit_pmem, 32, "%.2f", proc->pmem);

    switch(mtype) {
        case ALERT:
            message_type = "alert";
            if (process_info._cause == "cpu")
                short_message = "[ ALERT ] Process with PID " + to_string(proc->pid) + " produces a load of " + limit_pcpu + "!";
            else if (process_info._cause == "mem")
                short_message = "[ ALERT ] Process with PID " + to_string(proc->pid) + " is using " + limit_pmem + "% of RAM!";
            else if (process_info._cause == "zombie")
                short_message = "[ ALERT ] Process with PID " + to_string(proc->pid) + " has changed the state to ZOMBIE!";
            else if (process_info._cause == "dstate")
                short_message = "[ ALERT ] Process with PID " + to_string(proc->pid) + " has changed the state to UNINTERRUPTIBLE SLEEP!";
            else
                short_message = "[ ERROR ] No short-message!";
            break;
        case KILL:
            message_type = "kill";
            short_message = "[ KILL ] Process with PID " + to_string(proc->pid) + " was killed!";
            break;
        case GLOBAL_KILL:
            message_type = "global_kill";
            short_message = "[ KILL ] Process with PID " + to_string(proc->pid) + " was killed!";
            break;
        case LIMIT:
            message_type = "limit";
            short_message = "[ LIMIT ] Process with PID " + to_string(proc->pid) + " was added to cgroup!";
            break;
        case FREEZE:
            message_type = "freeze";
            short_message = "[ FREEZE ] Process with PID " + to_string(proc->pid) + " was paused!";
            break;
        case GLOBAL_FREEZE:
            message_type = "global_freeze";
            short_message = "[ FREEZE ] Process with PID " + to_string(proc->pid) + " was paused!";
            break;
        case JAIL:
            message_type = "jail";
            short_message = "[ JAIL ] Process with PID " + to_string(proc->pid) + " was put to jail!";
            break;
    }

    if (graylog_enabled) {

        // the json-body which will be send
        stringstream ss;
        ss << "{"
        << "\"version\":\"" << to_string(graylog_message_version) << "\","
        << "\"host\":\"" << string(hostname) << "\","
        << "\"short_message\":\"" << short_message << "\","
        << "\"level\":\"" << to_string(graylog_message_level) << "\","
        << "\"_service\":\"" << DAEMON_NAME << "\","
        << "\"_server\":\"" << string(hostname) << "\","
        << "\"_mtype\":\"" << message_type << "\","
        << "\"_pid\":" << to_string(proc->pid) << ","
        << "\"_user\":\"" << proc->user << "\","
        << "\"_pcpu\":" << limit_pcpu << ","
        << "\"_pmem\":" << to_string(proc->pmem) << ","
        << "\"_status\": \"" << process_info._status << "\","
        << "\"_loginuid\": " << process_info._loginuid << ","
        << "\"_io\": \"" << process_info._io << "\","
        << "\"_limits\": \"" << process_info._limits << "\","
        << "\"_syscall\": \"" << process_info._syscall << "\","
        << "\"_cgroup\": \"" << process_info._cgroup << "\","
        << "\"_cause\": \"" << process_info._cause << "\","
        << "\"_state\": \"" << proc->state << "\","
        << "\"_command\": \"" << proc->command <<"\""
        << "}";

        // the json-body which will be send
        json_data = ss.str();

        if (graylog_transport_method == HTTP) {
            // send it via curl library command
            curlPostJSON(json_data.c_str(), GRAYLOG);
        } else if (graylog_transport_method == UDP) {
            // TODO
            UNUSED(process_info);
        } else if (graylog_transport_method == TCP) {
            // TODO
            UNUSED(process_info);
        }
    }

    if (logstash_enabled) {

        // the json-body which will be send
        stringstream ss;
        ss << "{"
        << "\"service\":\"" << DAEMON_NAME << "\","
        << "\"server\":\"" << string(hostname) << "\","
        << "\"short_message\":\"" << short_message << "\","
        << "\"mtype\":\"" << message_type << "\","
        << "\"pid\":" << to_string(proc->pid) << ","
        << "\"user\":\"" << proc->user << "\","
        << "\"pcpu\":" << limit_pcpu << ","
        << "\"pmem\":" << to_string(proc->pmem) << ","
        << "\"status\": \"" << process_info._status << "\","
        << "\"loginuid\": " << process_info._loginuid << ","
        << "\"io\": \"" << process_info._io << "\","
        << "\"limits\": \"" << process_info._limits << "\","
        << "\"syscall\": \"" << process_info._syscall << "\","
        << "\"cgroup\": \"" << process_info._cgroup << "\","
        << "\"cause\": \"" << process_info._cause << "\","
        << "\"state\": \"" << proc->state << "\","
        << "\"command\": \"" << proc->command <<"\""
        << "}";

        json_data = ss.str();
        json_data.erase(remove_if(json_data.begin(), json_data.end(), [](unsigned char c) { return iscntrl(c); }), json_data.end());

        if (logstash_transport_method == HTTP) {
            // send it via curl library command
            curlPostJSON(json_data.c_str(), LOGSTASH);
        } else if (logstash_transport_method == UDP) {
            // TODO
            UNUSED(process_info);
        } else if (logstash_transport_method == TCP) {
            // TODO
            UNUSED(process_info);
        }
    }

}

bool Controller::curlPostJSON(const char* json_data, MessageCollector message_collector) {
    // create a curl handle
    // libcurl, see: https://curl.se/libcurl/c/curl_easy_init.html
    curl = curl_easy_init();

    CURLcode curl_result;

    if (curl) {

        // headers with mime-type for the curl posts
        // libcurl, see: https://curl.se/libcurl/c/curl_slist_append.html
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "charset: utf-8");

        // set all needed options for the curl post
        // libcurl, see: https://curl.se/libcurl/c/curl_easy_setopt.html
        FILE *devnull = fopen("/dev/null", "w");
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, devnull);
        curl_easy_setopt (curl, CURLOPT_VERBOSE, 0L);
        if (message_collector == GRAYLOG) curl_easy_setopt(curl, CURLOPT_URL, graylog_final_url.c_str());
        if (message_collector == LOGSTASH) curl_easy_setopt(curl, CURLOPT_URL, logstash_final_url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);

        // send the post and retrieve result
        // libcurl, see: https://curl.se/libcurl/c/curl_easy_perform.html
        curl_result = curl_easy_perform(curl);

        fclose(devnull);

        // check if the post was successful
        if (curl_result != CURLE_OK) {
            if (message_collector == GRAYLOG) logger->logError("Unable to perform a POST request to " + graylog_final_url);
            if (message_collector == LOGSTASH) logger->logError("Unable to perform a POST request to " + logstash_final_url);
            logger->logDebug("libcurl: Unable to post: " + string(curl_easy_strerror(curl_result)));
            return false;
        }

        // cleanup after post
        // libcurl, see: https://curl.se/libcurl/c/curl_easy_cleanup.html
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    return true;
}

bool Controller::controllerShutdown() {

    bool exit_code = true;

    logger->logNotice("Shutting down the controller");

    if (term_cgroup_cleanup) {
        logger->logInfo("Removing created cgroups");
        exit_code = cleanupCgroups(true);
    }

    return exit_code;
}

void Controller::showInformation(bool show_rules) {

    if (show_rules) {
        // show all available rules
        logger->logInfo("[ Loaded Rules ]");
        logger->logInfo(logger->SEPARATOR_LINE);

        if (load_rules) {
            rulemanager->showRules();
        } else {
            logger->logInfo("LOAD_RULES is set to '0'");
        }

        logger->logInfo(logger->SEPARATOR_LINE);
    }

    // show the current global penalty list
    logger->logInfo("[ PIDs on Global Penalty List ]");
    logger->logInfo(logger->SEPARATOR_LINE);
    for (auto& r : global_penalty_list) {

        stringstream global_penalty_list_item;
        global_penalty_list_item
            << "pid: " << to_string(r.second.pid)
            << " penalty_cause: " << r.second.penalty_cause
            << " alert_counter: " << r.second.alert_counter
            << " in_cgroup: " << r.second.in_cgroup;

        logger->logInfo(global_penalty_list_item.str());
    }
    logger->logInfo(logger->SEPARATOR_LINE);

    // show the current penalty list
    logger->logInfo("[ PIDs on Penalty List ]");
    logger->logInfo(logger->SEPARATOR_LINE);
    for (auto& r : penalty_list) {

        stringstream penalty_list_item;
        penalty_list_item
            << "pid: " << to_string(r.second.pid)
            << " penalty_cause: " << r.second.penalty_cause
            << " penalty_counter: " << to_string(r.second.penalty_counter)
            << " cooldown_counter: " << to_string(r.second.cooldown_counter)
            << " alerted: " << r.second.alerted
            << " in_cgroup: " << r.second.in_cgroup;

        logger->logInfo(penalty_list_item.str());
    }
    logger->logInfo(logger->SEPARATOR_LINE);

}
