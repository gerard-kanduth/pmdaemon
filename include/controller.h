#ifndef CONTROLLER
#define CONTROLLER

#include <curl/curl.h>
#include <limits>
#include <pwd.h>
#include <unordered_map>
#include <unordered_set>
#include <signal.h>
#include <stdio.h>
#include "logger.h"
#include "rulemanager.h"
#include "settings.h"
#include "datatypes.h"
#include "utils.h"

using namespace std;

class Controller {

    private:

        // Logger Instance
        Logger* logger = nullptr;

        // Settings Instance
        Settings* settings = nullptr;

        // retrieve the page-size (needed for RAM calculation)
        const long page_size = sysconf(_SC_PAGESIZE);

        // retrieve the daemon's PID
        const pid_t daemon_pid = getpid();

        // penalty list
        unordered_map<long, PenaltyListItem> penalty_list;
        unordered_map<long, PenaltyListItem>::iterator penalty_list_it;

        // global penalty list
        unordered_map<long, GlobalPenaltyListItem> global_penalty_list;
        unordered_map<long, GlobalPenaltyListItem>::iterator global_penalty_list_it;

        // pid list (needed for pcpu calculation)
        unordered_map<long, unsigned long long> pcpu_pid_list;
        unordered_set<long> current_pids;

        // rules object (contains all loaded rules)
        RuleManager* rulemanager = nullptr;

        // pointer for specific rule
        Rule* specific_rule = nullptr;

        // curl instance used for http logging
        // libcurl, see: https://curl.se/libcurl
        CURL* curl = nullptr;

        // current PID file of /proc directory
        string proc_pid_file;

        // number of failed checks
        int error_checks = 0;

        // max number of chars which should be read from command
        int max_cmd_chars_read;

        // max number of fails before daemon terminates
        int max_errors;

        // variable for hostname
        char hostname_buffer[128];
        const char* hostname = nullptr;

        // file output
        string out_cmdline;

        // current process which will be handled
        Process c_process;
        long c_process_pid;

        // parsed /proc/stat file
        ProcSysStat system_stat;
        unsigned long long sys_last_total_time;

        // helper variables
        struct passwd *pwd;
        struct stat stat_buf;

        // used to limit trailing zeroes on measured values
        char limit_pcpu[32];
        char limit_pmem[32];

        // default limits (if no specific rule is set for process)
        bool state_trigger;
        bool load_rules;
        bool specific_rules_check_only;
        bool term_cgroup_cleanup;
        bool global_action_enabled;
        bool specific_proc_rule;

        int checks_cooldown;
        int max_alerts_global_action;
        GlobalAction global_action;
        set<string> whitelisted_users;

        // defaults which will be used, can be overwritten by specific rule
        int default_checks_before_alert;
        int checks_before_alert = default_checks_before_alert;

        double default_cpu_trigger_threshold;
        double cpu_trigger_threshold;

        long long default_mem_trigger_threshold;
        long long mem_trigger_threshold;

        bool default_send_notifications;
        bool send_notifications;

        // graylog related variables
        bool graylog_enabled;
        bool graylog_http_secure;
        int graylog_port;
        string graylog_fqdn;
        string graylog_http_path;
        string graylog_http_protocol_prefix;
        string graylog_final_url;
        TransportType graylog_transport_method;

        // graylog message variables
        double graylog_message_version = 1.1;
        int graylog_message_level = 1;

        // logstash related variables
        bool logstash_enabled;
        bool logstash_http_secure;
        int logstash_port;
        string logstash_fqdn;
        string logstash_http_path;
        string logstash_http_protocol_prefix;
        string logstash_final_url;
        TransportType logstash_transport_method;

        // private functions
        ProcessInfo collectProcessInfo(Process&, string);
        bool fetchProcessInfo(long);
        bool addPIDToCgroup(string&, long&);
        bool addPIDToJail(long&);
        bool checkProcess(Process&);
        bool curlPostJSON(const char*, MessageCollector);
        bool checkIfCgroupEmpty(string&, long&);
        bool checkPenaltyList(Process&, string);
        bool cleanupPenaltyList();
        bool createPIDCgroup(string&, long&);
        bool createJailPIDCgroup(string);
        bool createJailCgroup(double, long long);
        bool enableCgroupControllers();
        bool iterateProcessList();
        bool pausePID(long);
        bool killPID(long);
	bool removeAllPIDsFromCgroup(string);
        bool removeCgroup(string);
        bool removePIDFromCgroup(long);
        string readProcFile(string, long&);
        void SendMessage(ProcessInfo, MessageType);

    public:

        // public functions
        Controller();
        ~Controller();
        bool cleanupCgroups(bool);
        bool doCheck();
        bool controllerShutdown();
        void showInformation(bool);

};

#endif
