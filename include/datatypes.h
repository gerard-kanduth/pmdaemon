#ifndef DATATYPES_H
#define DATATYPES_H

#include <cctype>
#include <string>
#include <stdlib.h>

#define DAEMON_NAME                 "pmdaemon"

#define PROC_DIR                    "/proc"
#define PROC_STAT_FILE              PROC_DIR "/stat"
#define PROC_UPTIME_FILE            PROC_DIR "/uptime"
#define PROC_MEMINFO_FILE           PROC_DIR "/meminfo"
#define CGROUP_ROOT                 "/sys/fs/cgroup/"
#define CGROUP_PROCS_FILE           "/cgroup.procs"
#define CGROUP_CUR_PIDS_FILE        "/pids.current"
#define CGROUP_CPU_MAX_FILE         "/cpu.max"
#define CGROUP_MEM_MAX_FILE         "/memory.max"
#define CGROUP_MEM_HIGH_FILE        "/memory.high"
#define CGROUP_FREEZE_FILE          "/cgroup.freeze"
#define CGROUP_SUBCONTR_FILE        "/cgroup.subtree_control"
#define CGROUP_PID_PREFIX           "/pid-"
#define CGROUP_MAIN_PROCS_FILE      CGROUP_ROOT CGROUP_PROCS_FILE
#define CGROUP_SUBCONT_FILE         CGROUP_ROOT "cgroup.subtree_control"
#define JAIL_CGROUP                 CGROUP_ROOT DAEMON_NAME "-jailed-pids"
#define JAIL_CGROUP_PROCS           JAIL_CGROUP CGROUP_PROCS_FILE
#define JAIL_CGROUP_CPU_MAX_FILE    JAIL_CGROUP CGROUP_CPU_MAX_FILE
#define JAIL_CGROUP_MEM_MAX_FILE    JAIL_CGROUP CGROUP_MEM_MAX_FILE

#define REGEX_PID_VALUE             "^[0-9]{1,}$"
#define REGEX_DISABLE_VALUE         "^\\s{0,}0{1,1}\\s{0,}$"
#define REGEX_PERCENT_VALUE         "^\\s{0,}\\d{1,3}(\\.\\d{0,3}){0,1}\\s{0,}\\%{1,1}\\s{0,}$"
#define REGEX_INT_VALUE             "^\\s{0,}\\d{1,32}\\s{0,}$"
#define REGEX_ZERO_ONE_VALUE        "^\\s{0,}1|0\\s{0,}$"
#define REGEX_COMMA_SEP_STRINGS     "^(\\s{0,}[a-zA-Z0-9\\_\\.][a-zA-Z0-9\\_\\.\\-]{0,30}[a-zA-Z0-9\\_\\.\\$\\-]?\\s{0,}\\,{0,}){0,}$"
#define REGEX_FQDN_VALUE            "^\\s{0,}(\\w|\\d|\\.|\\-){1,}\\s{0,}$"
#define REGEX_ABS_MEM_VALUE         "^\\s{0,}\\d{1,32}\\s{0,}[B|K|M|G|T|P]{1,1}\\s{0,}$"
#define REGEX_DAEMON_CGROUP         "^" DAEMON_NAME "\\-.*$"

using namespace std;

enum MessageCollector {
    GRAYLOG,
    LOGSTASH
};

enum GlobalAction {
    ACTION_KILL,
    ACTION_FREEZE,
    ACTION_JAIL
};

enum LogLevel {
    INFO,
    NOTICE,
    ERROR,
    DEBUG1,
    DEBUG2
};

enum MessageType {
    LIMIT,
    ALERT,
    KILL,
    GLOBAL_KILL,
    FREEZE,
    GLOBAL_FREEZE,
    JAIL
};

enum TransportType {
    HTTP,
    UDP,
    TCP
};

// cgroup cpu.max values
struct CgroupCPUMax {
    char max_value[32];
    char period[32];
};

// cgroup list struct
struct CgroupListItem {
    long pid;
    string cgroup;
};

// global penalty list-item
struct GlobalPenaltyListItem {
    long pid;
    unsigned long long start_time;
    string penalty_cause;
    string cgroup_name;
    int alert_counter;
    bool in_cgroup = false;
};

// penalty list-item
struct PenaltyListItem {
    long pid;
    int penalty_counter;
    int cooldown_counter;
    unsigned long long start_time;
    string penalty_cause;
    string cgroup_name;
    bool alerted = false;
    bool in_cgroup = false;
    bool limited = false;
};

struct ProcSysStat {
    bool valid;
    int active_cores;
    unsigned long long int user_time,
        nice_time,
        system_time,
        idle_time,
        virtual_time,
        system_all_time,
        idle_all_time,
        period,
        total_time = 0,
        last_total_time = 0,
        delta_total_time,
        io_wait = 0,
        irq = 0,
        soft_irq = 0,
        steal = 0,
        guest = 0,
        guest_nice = 0;
};

// struct for the process'es /proc/<pid>/stat file
struct ProcPIDStat {
    bool valid;
    string comm;
    char state[5];
    int pid,
        ppid,
        pgrp,
        session,
        tty_nr,
        tpgid,
        exit_signal,
        processor,
        rt_priority,
        policy,
        exit_code;
    unsigned int flags;
    uint64_t cutime,
        cstime,
        priority,
        nice,
        num_threads,
        itrealvalue,
        guest_time;
    unsigned long minflt,
        cminflt,
        majflt,
        cmajflt,
        utime,
        stime,
        vsize,
        rss,
        rsslim,
        startcode,
        endcode,
        start_stack,
        kstkesp,
        kstkeip,
        signal,
        blocked,
        sigignore,
        sigcatch,
        wchan,
        nswap,
        cnswap,
        cguest_time,
        start_data,
        end_data,
        start_brk,
        arg_start,
        arg_end,
        env_start,
        env_end;
    unsigned long long start_time,
        delayacct_blkio_ticks,
        total_time,
        delta_total_time;

};

// struct for a process
struct Process {
    bool valid;
    long pid;
    int rss;
    long uid;
    double pcpu;
    double pmem;
    string state;
    string user;
    string command;
    string proc_pid_dir;
    ProcPIDStat proc_pid_stat;
};

// advanced process information
struct ProcessInfo {
    string _io;
    string _limits;
    string _syscall;
    string _status;
    string _cgroup;
    string _loginuid;
    string _cause;
    string _state;
    string _stack;
    string _environ;
    Process _process;
};

struct UptimeIdle {
    float uptime;
    long longUptime;
    float idletime;
};

#endif // DATATYPES_H
