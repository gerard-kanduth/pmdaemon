#include "utils.h"

long Utils::total_ram = Utils::getTotalMemory();

bool Utils::checkIfFileExists(string filename) {

    return (access(filename.c_str(), F_OK) != -1);

}

bool Utils::checkIfDirectoryExists(string directory) {

    return fs::exists(directory.c_str());

}

bool Utils::isZeroOneValue(string* input) {

    if (regex_match(*input, regex_zero_one_value)) return true;
    return false;

}

bool Utils::isPercentValue(string* input) {

    if (regex_match(*input, regex_percent_value)) return true;
    return false;

}

bool Utils::isIntegerValue(string* input) {

    if (regex_match(*input, regex_int_value)) return true;
    return false;

}

bool Utils::isCommaSepStringValue(string* input) {

    if (regex_match(*input, regex_comma_sep_strings)) return true;
    return false;

}

bool Utils::isFQDNValue(string* input) {

    if (regex_match(*input, regex_fqdn_value)) return true;
    return false;

}

bool Utils::isMemValue(string* input) {

    if (regex_match(*input, regex_abs_mem_value) || regex_match(*input, regex_percent_value)) return true;
    return false;

}

bool Utils::isDisableValue(string* input) {

    if (regex_match(*input, regex_disable_value)) return true;
    return false;

}

bool Utils::isAbsoluteMemValue(string* input) {

    if (regex_match(*input, regex_abs_mem_value)) return true;
    return false;

}

bool Utils::writeToFile(string filename, string text) {

    FILE* file = nullptr;

    file = fopen(filename.c_str(), "w");

    if (file) {
        fputs(text.c_str(), file);
    } else {
        Logger::getInstance()->logError("Unable to write to file " + filename + "!");
        return false;
    }

    fclose(file);
    return true;

}

int Utils::getActiveCoresCount(string *stat_output) {

    int active_cores = 0;

    try {

        string line;
        istringstream output_stream(*stat_output);
        while (getline(output_stream, line)) {
            if (regex_match(line, regex_cpu_stat)) active_cores++;
        }

    } catch (...) {
        Logger::getInstance()->logError("Unable to get active cores. Using default: 1 core.");
        active_cores = 1;
        return active_cores;
    }

    return active_cores;

}

long Utils::getTotalMemory() {

    long total_memory = 0;
    char unit[4];

    FILE* file;

    try {
        file = fopen(PROC_MEMINFO_FILE, "r");
        fscanf(file, "MemTotal: %ld %s", &total_memory, unit);
        fclose(file);
    }  catch (...) {
        Logger::getInstance()->logError("Unable to fetch total memory from " PROC_MEMINFO_FILE);
        fclose(file);
        return -1;
    }

    string u = lowerText(unit);

    // convert total memory to byte since the daemon will always compare in bytes
    if (u.find("kb") != string::npos) total_memory = total_memory * 1024;
    else if (u.find("mb") != string::npos) total_memory = total_memory * 1024 * 1024;
    else if (u.find("gb") != string::npos) total_memory = total_memory * 1024 * 1024 * 1024;
    else if (u.find("tb") != string::npos) total_memory = total_memory * 1024 * 1024 * 1024 * 1024;
    else if (u.find("pb") != string::npos) total_memory = total_memory * 1024 * 1024 * 1024 * 1024 * 1024;

    return total_memory;
}

long long Utils::convertToBytes(string unit, string value) {

    string u = lowerText(unit);
    long long v = strtoul(value.c_str(), nullptr, 10);

    // convert total memory to byte
    if (u.find("k") != string::npos) v = v * 1024;
    else if (u.find("m") != string::npos) v = v * 1024 * 1024;
    else if (u.find("g") != string::npos) v = v * 1024 * 1024 * 1024;
    else if (u.find("t") != string::npos) v = v * 1024 * 1024 * 1024 * 1024;
    else if (u.find("p") != string::npos) v = v * 1024 * 1024 * 1024 * 1024 * 1024;

    return v;

}

double Utils::calcPercentCPU(unsigned long long *sys_delta_total_time, unsigned long long *pid_delta_total_time) {
    return (double)(((float)*pid_delta_total_time / (float)*sys_delta_total_time) * 100.0);
}

string Utils::lowerText(char* txt) {

    string t(txt);

    return Utils::lowerText(t);
}

string Utils::lowerText(string txt) {

    stringstream u;

    for (auto x : txt) u << (char) tolower(x);
    return u.str();
}

string Utils::readFromFile(string filename) {
    return readFromFile(filename, false);
}

string Utils::readFromFile(string filename, bool null_terminated) {

    try {

        stringstream ss;

        if (!null_terminated) {
            ifstream f(filename, ifstream::in);
            while(f >> ss.rdbuf());
        } else {
            ifstream f(filename, ifstream::in);
            while(f >> ss.rdbuf());
            string output = ss.str();
            replace(output.begin(), output.end(), '\0', ' ');
            return output;
        }

        return ss.str();

    } catch (...) {
        Logger::getInstance()->logError("Unable to read from " + filename);
        return {};
    }

}

string Utils::setToComSepString(set<string> s) {

    string rstr;

    for (auto str : s) rstr.append(str + ",");
    rstr.erase(rstr.find_last_of(','));
    return rstr;
}

string Utils::generateJailMaxCPU(double cpu_percent) {
    return generateMaxCPU(cpu_percent, JAIL_CGROUP_CPU_MAX_FILE);
}

string Utils::generateMaxCPU(double cpu_percent, string cpu_max_file) {

    CgroupCPUMax cpu_max = parseCPUMaxFile(cpu_max_file);
    if (cpu_percent > 0 && cpu_percent < 100) return to_string( static_cast<long>((stol(cpu_max.period) / 100) * cpu_percent)) + " " + cpu_max.period;
    else return "max " + string(cpu_max.period);

}

UptimeIdle Utils::getSystemUptime() {

    UptimeIdle utit;

    FILE* file;
    try {
        file = fopen(PROC_UPTIME_FILE, "r");
        fscanf(file, "%f %f", &utit.uptime, &utit.idletime);
        fclose(file);
        utit.longUptime = static_cast<long>(utit.uptime);
    }  catch (...) {
        Logger::getInstance()->logError("Unable to fetch uptime from " PROC_UPTIME_FILE);
        utit.uptime = 0.0;
        utit.longUptime = 0;
        utit.idletime = 0.0;
        fclose(file);
        return utit;
    }
    return utit;
}

ProcPIDStat Utils::parsePIDStatFile(int pid) {

    ProcPIDStat proc_stat;

    try {

        string output = readFromFile(("/proc/" + to_string(pid) + "/stat"));

        size_t pos_first_comm_bracket = output.find_first_of('('),
                pos_last_comm_bracket = output.find_last_of(')');

        // *** pid ***
        proc_stat.pid = stoi(output.substr(0, pos_first_comm_bracket));

        // *** comm ***
        proc_stat.comm = output.substr(pos_first_comm_bracket, (pos_last_comm_bracket-pos_first_comm_bracket+1));
        // https://en.cppreference.com/w/cpp/string/byte/iscntrl#Notes
        proc_stat.comm.erase(remove_if(proc_stat.comm.begin(), proc_stat.comm.end(), [](unsigned char c) { return iscntrl(c); }), proc_stat.comm.end());

        // read all further infos from stat file with sscanf (only comm-field is unpredictable)
        output = output.substr(pos_last_comm_bracket+1);

        // "man 5 proc"
        // https://github.com/torvalds/linux/blob/master/fs/proc/array.c
        sscanf(output.c_str(),
               "%s %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld %ld %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %d %d %u %u %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %d",
               proc_stat.state,
               &proc_stat.ppid,
               &proc_stat.pgrp,
               &proc_stat.session,
               &proc_stat.tty_nr,
               &proc_stat.tpgid,
               &proc_stat.flags,
               &proc_stat.minflt,
               &proc_stat.cminflt,
               &proc_stat.majflt,
               &proc_stat.cmajflt,
               &proc_stat.utime,
               &proc_stat.stime,
               &proc_stat.cutime,
               &proc_stat.cstime,
               &proc_stat.priority,
               &proc_stat.nice,
               &proc_stat.num_threads,
               &proc_stat.itrealvalue,
               &proc_stat.start_time,
               &proc_stat.vsize,
               &proc_stat.rss,
               &proc_stat.rsslim,
               &proc_stat.startcode,
               &proc_stat.endcode,
               &proc_stat.start_stack,
               &proc_stat.kstkesp,
               &proc_stat.kstkeip,
               &proc_stat.signal,
               &proc_stat.blocked,
               &proc_stat.sigignore,
               &proc_stat.sigcatch,
               &proc_stat.wchan,
               &proc_stat.nswap,
               &proc_stat.cnswap,
               &proc_stat.exit_signal,
               &proc_stat.processor,
               &proc_stat.rt_priority,
               &proc_stat.policy,
               &proc_stat.delayacct_blkio_ticks,
               &proc_stat.guest_time,
               &proc_stat.cguest_time,
               &proc_stat.start_data,
               &proc_stat.end_data,
               &proc_stat.start_brk,
               &proc_stat.arg_start,
               &proc_stat.arg_end,
               &proc_stat.env_start,
               &proc_stat.env_end,
               &proc_stat.exit_code
        );

    } catch (...) {
        proc_stat.valid = false;
        return proc_stat;
    }

    proc_stat.valid = true;
    return proc_stat;
}

ProcSysStat Utils::parseStatFile() {

    ProcSysStat sys_stat;

    // only read total-values, no need to parse each core
    try {
        string output = readFromFile(PROC_STAT_FILE);
        sys_stat.active_cores = Utils::getActiveCoresCount(&output);

        sscanf(output.c_str(),
            "cpu  %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
            &sys_stat.user_time,
            &sys_stat.nice_time,
            &sys_stat.system_time,
            &sys_stat.idle_time,
            &sys_stat.io_wait,
            &sys_stat.irq,
            &sys_stat.soft_irq,
            &sys_stat.steal,
            &sys_stat.guest,
            &sys_stat.guest_nice
        );

        // calculate the total cpu time
        sys_stat.idle_all_time = sys_stat.idle_time + sys_stat.io_wait;
        sys_stat.system_all_time = sys_stat.system_time + sys_stat.irq + sys_stat.soft_irq;
        sys_stat.virtual_time = sys_stat.guest + sys_stat.guest_nice;

        sys_stat.total_time = sys_stat.user_time
            + sys_stat.nice_time
            + sys_stat.system_all_time
            + sys_stat.idle_all_time
            + sys_stat.steal
            + sys_stat.virtual_time;
        sys_stat.period = (double)sys_stat.total_time / sys_stat.active_cores;

    }  catch (...) {
        sys_stat.valid = false;
        return sys_stat;
    }

    sys_stat.valid = true;
    return sys_stat;

}

CgroupCPUMax Utils::parseCPUMaxFile(string file) {

    CgroupCPUMax cpu_max;

    try {
        string output = readFromFile(file);
        sscanf(output.c_str(), "%s %s", cpu_max.max_value, cpu_max.period);

    } catch(...) {
        strcpy(cpu_max.max_value, "max");
        strcpy(cpu_max.period, "100000");
    }

    return cpu_max;
}

set<string> Utils::generateStringSet(string s) {

    set<string> return_set;

    if (s.find(',') != s.npos) {

        string entry;

        size_t next_comma_pos = 0;
        size_t last_comma_pos = s.find_last_of(',');

        while (next_comma_pos <= last_comma_pos) {
            next_comma_pos = s.find(',');
            entry = s.substr(0, next_comma_pos);
            entry.erase(remove_if(entry.begin(), entry.end(), ::isspace), entry.end());
            s = s.substr(next_comma_pos + 1);
            if (!entry.empty())
                return_set.insert(entry);
        }
    } else if (s.find(',') == s.npos && !s.empty()) {
        return_set.insert(s);
    } else {
        return_set.clear();
    }

    return return_set;
}
