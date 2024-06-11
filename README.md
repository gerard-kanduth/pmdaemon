# Process Monitoring Daemon

## DESCRIPTION
This daemon-service can be used to monitor and limit misbehaving processes
on Linux-based systems. The aim of this project is to provide a tool which will
give administrators the possibillity to specify rules with desired thresholds
for any specific type of application. The daemon will constantly check all
running processes if values like CPU-, and/or RAM-Usage exceeds the set
maximum. A limitation of these applications can be performed by the help of
cgroup v2. Actions like killing or pausing the process can also be configured.
Additionally collected information regarding the process can be forwarded to
a datacollector (e.g. Graylog2 or Logstash) to further investigate the cause 
why it is utilizing higher system-resources.

## AUTHORS
Gerard Kanduth <gerardraffael.kanduth@edu.fh-kaernten.ac.at>

## BUILD REQUIREMENTS
+ Linux-based System with C++17 support
+ GNU Compiler Collection (g++) for compiling
+ GNU make utility for running Makefile
+ "libcurl" library with devel-packages
+ git-client for cloning this repository

## INSTALLATION

**Note:** The package "rpm-build" is needed to create RPM packages.

### Install needed packages

Fedora/RedHat:
```
dnf install git gcc gcc-c++ make rpm-build libcurl libcurl-devel
```

Debian/Ubuntu:
```
apt install git build-essential g++ libcurl4-gnutls-dev
```
**Note:** Currently only RPMs can be generated via "make all". Therefore only "make pmdaemon" is currently available for Debian-based Distributions.

### Clone the repository
```
if ! $(test -d /srv); then mkdir /srv; fi
cd /srv
git clone https://github.com/gerard-kanduth/pmdaemon.git
cd pmdaemon
```

### Build and package to RPM (Fedora/RedHat only)
**Note:** It is possible to simply build the project without packing by running "make pmdaemon" instead.
```
make all
```

### Install RPM on system (Fedora/RedHat only)
```
rpm -i $HOME/rpmbuild/RPMS/x86_64/pmdaemon*.rpm
```

## SETTINGS DESCRIPTION

The following section gives an overview on available configuration settings of this daemon.
However, it is possible to override some global setting values via specific rules.

### General settings

Set the loglevel of the daemon
>  Available Values: *error*, *notice*, *info*, *debug*
```
# Example(s)
LOGLEVEL=info
```

Set the debug level - higher number means more output.
This setting will only be needed if LOGLEVEL is set to debug.
> Available Values: *1*, *2*
```
# Example(s)
DEBUG_LEVEL=2
```

Number of faulty check-cycles before daemon terminates.
> Available Values: *1* - *2147483647* (*0* is not allowed)
```
# Example(s)
MAX_ERRORS=10
```

Max number of chars which should be read per command.
This setting is needed to trim and limit extremely large commands.
> Available Values: *1* - *2147483647* (*0* is not allowed)
```
MAX_CMD_CHARS_READ=5000
```

Set the check-interval for the daemon in seconds (0 is not allowed).
> Available Values: *1* - *2147483647* (*0* is not allowed)
```
# Example(s)
CHECK_INTERVAL=1
```

Number of check cycles a process-threshold needs to be exceeded before an alert is triggered.
> Available Values: *1* - *2147483647* (*0* is not allowed)
```
# Example(s)
CHECKS_BEFORE_ALERT=30
```

Number of checks after alert before PID gets removed from penatly-list.
> Available Values: *1* - *2147483647* (*0* is not allowed)
```
# Example(s)
CHECKS_COOLDOWN=60
```

A comma-seperated list of whitelisted users.
Processes of these users will not be monitored.
```
# Example(s)
WHITELISTED_USERS=root,dbus,daemon
```

The CPU threshold for a process (can be overvritten via specific rule).
**Note:** Setting this value to '0' will deactivate global CPU checking.
> Available Values: (Disable) *0*, (Percentage) *0%* - *100%*, *0.0%* - *100.0%*
```
# Example(s)
CPU_TRIGGER_THRESHOLD=80.0%
CPU_TRIGGER_THRESHOLD=0
```

The memory threshold for a process (can be overvritten via specific rule).
This value can either be set in percentage (in relation to total memory of system) or as absolute value.
**Note:** Setting this value to '0' will deactivate global memory checking.
> Available Values: (Disable) *0*, (Percentage) *0%* - *100%*, *0.0%* - *100.0%*, (Absolute) *1B*, *1024K*, *10M*, *2G*, etc.
```
# Example(s)
MEM_TRIGGER_THRESHOLD=10.0%
MEM_TRIGGER_THRESHOLD=1024K
MEM_TRIGGER_THRESHOLD=0
```

Global actions can be enabled for processes which exceed the maximum value of alerts set in MAX_ALERTS_GLOBAL_ACTION.
This setting simply enables or disables this functionality.
> Available Values: (off) *0*, (on) *1*
```
# Example(s)
GLOBAL_ACTION_ENABLED=1
```

Maximum numbers of alerts for a PID before the global action set in GLOBAL_ACTION will be performed.
> Available Values: *1* - *2147483647* (*0* is not allowed)
```
# Example(s)
MAX_ALERTS_GLOBAL_ACTION=5
```

Decide which global action should be performed if threshold was exceeded.
This action will only be performed if no specific rule is set for the given process.
- jail      = PID will put into a specific jail cgroup with global CPU and memory limits
- kill      = The PID will get terminated
- freeze    = The PID will be paused (SIGSTOP signal will be send)
> Available Values: *jail*, *kill*, *freeze*
```
# Example(s)
GLOBAL_ACTION=jail
```

The maximum number of core percentage which all PIDs in the jail-cgroup share.
> Available Values: (Percentage) *0%* - *100%*, *0.0%* - *100.0%*
```
# Example(s)
JAIL_CPU_LIMIT=25%
```

The maximum amount of RAM for PIDs in the jail-cgroup.
As soon as the total memory of the system is exceeded OOM-Killer will start killing processes in this group.
Value can either be set as percentage of total amount of RAM or as absolute value.
> Available Values: (Disable) *0*, (Percentage) *0%* - *100%*, *0.0%* - *100.0%*, (Absolute) *1B*, *1024K*, *10M*, *2G*, etc.
```
# Example(s)
JAIL_MEM_LIMIT=25%
JAIL_MEM_LIMIT=2G
JAIL_MEM_LIMIT=0
```

Decide if an alert should be triggered if the process changes it's state to Z or D.
> Available Values: (off) *0*, (on) *1*
```
STATE_TRIGGER=0
```

Only check processes which have a specific rule, all other processes will be skipped.
> Available Values: (off) *0*, (on) *1*
```
# Example(s)
SPECIFIC_RULES_CHECK_ONLY=0
```

Decide if possible available rules should be read from RULES_DIRECTORY.
> Available Values: (off) *0*, (on) *1*
```
# Example(s)
LOAD_RULES=1
```

Set the directory where the rules reside.
```
# Example(s)
RULES_DIRECTORY=/etc/pmdaemon/rules.d
```

Cleanup of created cgroups after termination.
All created specific cgroups will be erased and processes will be unlimited again.
> Available Values: (off) *0*, (on) *1*
```
# Example(s)
TERM_CGROUP_CLEANUP=1
```

Decide if notifications should be send (e.g. if process exeeds a threshold or was killed by the daemon).
Messages to data-collectors will only be send if this setting is enabled.
> Available Values: (off) *0*, (on) *1*
```
# Example(s)
SEND_NOTIFICATIONS=0
```


### Datacollector settings

Enable/Disable Graylog logging.
> Available Values: (off) *0*, (on) *1*
```
# Example(s)
GRAYLOG_ENABLED=0
```

Decide which method should be used to transfer data (http, TODO: udp and tcp will follow soon).
Information can be found here: https://docs.graylog.org/docs/gelf
> Available Values: *http*
```
# Example(s)
GRAYLOG_TRANSFER_METHOD=http
```

The FQDN of the Graylog instance.
```
# Example(s)
GRAYLOG_FQDN=graylog.local
```

The port of the graylog instance.
> Available Values: *1* - *2147483647* (*0* is not allowed)
```
# Example(s)
GRAYLOG_PORT=12201
```

Decide if HTTP or HTTPS should be used for transport.
> Available Values: (http) *0*, (https) *1*
```
# Example(s)
GRAYLOG_HTTP_SECURE=0
```

Only used when running in "http" mode, normally no need to alter this setting.
Leading '/' is mandatory.
```
# Example(s)
GRAYLOG_HTTP_PATH=/gelf
```

Enable/Disable Logstash logging.
> Available Values: (off) *0*, (on) *1*
```
# Example(s)
LOGSTASH_ENABLED=0
```

Decide which method should be used to transfer data (http, TODO: udp and tcp will follow soon).
Information can be found here: https://www.elastic.co/guide/en/logstash/current/introduction.html
> Available Values: *http*
```
# Example(s)
LOGSTASH_TRANSFER_METHOD=http
```

The FQDN of the Logstash instance.
```
# Example(s)
LOGSTASH_FQDN=logstash.local
```

The port of the Logstash instance.
> Available Values: *1* - *2147483647* (*0* is not allowed)
```
# Example(s)
LOGSTASH_PORT=8080
```

Decide if HTTP or HTTPS should be used for transport.
> Available Values: (off) *0*, (on) *1*
```
# Example(s)
LOGSTASH_HTTP_SECURE=0
```

Only used when running in "http" mode, normally no need to alter this setting.
Leading '/' is mandatory for the path.
```
# Example(s)
LOGSTASH_HTTP_PATH=/
```

## RULE SETTINGS WITH DESCRIPTION

This sections shows an example for a specific rule and all possible settings.
In some cases (e.g. CPU_TRIGGER_THRESHOLD, MEM_TRIGGER_THRESHOLD, or CHECKS_BEFORE_ALERT) global settings
will be inherited from settings file if not set in the specific rule.

Name of the rule
```
# Example(s)
RULE_NAME=stress-rule
```

Command which will be monitored (can either be "/usr/bin/stress" or simply "stress").
The command needs to start with this string to get monitored.
```
# Example(s)
COMMAND=stress
COMMAND=/usr/bin/stress
```

If you define the COMMAND e.g. "stress", only processes starting with exact "stress" will be monitored.
However, a user may start the command with "/bin/stress" or "/usr/bin/stress".
By enabling INCLUDE_BINARY_FOLDER_CHECK the following variations will also be checked:

- /bin/stress
- /sbin/stress
- /usr/bin/stress
- /usr/sbin/stress
- /usr/local/bin/stress
- /usr/local/sbin/stress
> Available Values: (off) *0*, (on) *1*
```
# Example(s)
INCLUDE_BINARY_FOLDER_CHECK=1
```

It is possible to enable a wildcard check by activating the WILDCARD_MATCH option.
The defined COMMAND string only needs to be a part of the actual command to trigger this rule.
e.g. "COMMAND=stress" would also trigger the rule if the command would be "/home/user/bin/aliased_stress --cpu 1"
> Available Values: (off) *0*, (on) *1*
```
# Example(s)
WILDCARD_MATCH=0
```

A regex pattern can be set instead of COMMAND to filter the specific command.
This setting needs to be enabled in order to activate this feature.
COMMAND will not be used if this setting is enabled and the rule is only valid if REGEX_SEARCH_PATTERN is set.
> Available Values: (off) *0*, (on) *1*
```
# Example(s)
REGEX_SEARCH_ENABLED=0
```

The regex search pattern which is used to apply actions from this rule for all process-commands which match this pattern.
This Setting only has an effect if REGEX_SEARCH_ENABLED is set to '1'
```
# Example(s)
REGEX_SEARCH_PATTERN=^.*stress.*--cpu.*1.*$
```

Set a threshold for CPU usage (in percent, floating-point).
As soon as the process is above this values it will be added to the penalty list (monitoring).
**Note:** Setting this value to '0' will disable the CPU check for all processes which are matching.
```
# Example(s)
CPU_TRIGGER_THRESHOLD=20.0%
```

Set a threshold for memory usage (in percent, absolute value).
**Note:** Setting this value to '0' will disable the memory check for all processes which are matching.
```
# Example(s)
MEM_TRIGGER_THRESHOLD=20.0%
MEM_TRIGGER_THRESHOLD=4096M
```

The CHECK_INTERVAL (in seconds) and the default CHECKS_BEFORE_ALERT is set in the settings.conf file.
This setting can be overwritten for specific commands by simply setting CHECKS_BEFORE_ALERT here.
```
# Example(s)
CHECKS_BEFORE_ALERT=10
```

Decide if limiting on the given process should be performed, otherwise only alerting and data-collecting will be done.
> Available Values: (off) *0*, (on) *1*
```
# Example(s)
ENABLE_LIMITING=1
```

Limit the given process to the following core limit (in percent).
**Note:** No CPU limiting will be performed if this setting was not added in a rule.
> Available Values: (Percentage) *0%* - *100%*, *0.0%* - *100.0%*
```
/* Examples */
LIMIT_CPU_PERCENT=5
```

Limit the given process to the following memory limit.
**Note:** No memory limitation will be done if this setting is not set in a rule.
> Available Values: (Percentage) *0%* - *100%*, *0.0%* - *100.0%*, (Absolute) *1B*, *1024K*, *10M*, *2G*, etc., (*0* is not allowed)
```
# Example(s)
LIMIT_MEMORY_VALUE=10%
LIMIT_MEMORY_VALUE=5M
```

Decide if the OOM-Killer should be invoked if the memory limit is reached.
If this setting is set, processes of such rules will be killed first if total system memory is exceeded.
> Available Values: (off) *0*, (on) *1*
```
# Example(s)
OOM_KILL_ENABLED=1
```

Decide if the process should be checked, otherwise no limiting and alerting will be performed.
> Available Values: (off) *0*, (on) *1*
```
# Example(s)
NO_CHECK=0
```

This option will put the process'es PID to the freezer - process will be "paused".
**Note:** PID_KILL_ENABLED will override this setting since the PID will be killed.
> Available Values: (off) *0*, (on) *1*
```
# Example(s)
FREEZE=0
```

This option activates the termination of a process as soon as it was above the threshold limits for CHECK_INTERVAL * CHECKS_BEFORE_ALERT (in seconds).
> Available Values: (off) *0*, (on) *1*
```
# Example(s)
PID_KILL_ENABLED=0
```

Decide if notifications and collected data should be send to data collectors for further analysis.
> Available Values: (off) *0*, (on) *1*
```
# Example(s)
SEND_NOTIFICATIONS=1
```

## CHANGELOG

### pmdaemon v1.1

#### Features and Improvements
- Rules in rule-directory can now have ".rule" or ".conf" ending to be read (".rule" is prefered)
- WHITELISTED_USERS (list) can now be set in settings file to whitelist users, processes of such users will not be monitored
- Improved the monitoring-routine for systems with higher amount of rules and processes
- REGEX_SEARCH_ENABLED and REGEX_SEARCH_PATTERN can now be used to search with Regex-Patterns for processes instead of COMMAND
- Added MAX_CMD_CHARS_READ to limit amount of chars which should be read from command
- Additional Debug log-levels (1, 2) are now possible
- Improved check-routine for reading settings and specific rules (changed to regex-patterns)
- SEND_PROCESS_FILES is now called SEND_NOTIFICATIONS and will decide if in general notifications should be send
- CPU_TRIGGER_THRESHOLD and MEM_TRIGGER_THRESHOLD will now be inherited from settings file if not set in specific rule
- Values like LIMIT_MEMORY_VALUE, MEM_TRIGGER_THRESHOLD and JAIL_MEM_LIMIT can now be set as percentage- and absolute value
- Deactivation of CPU and/or memory monitoring is now be possible by setting values to '0'
- Improvement of Logger Singleton Class
- Specific rules with wrong values will now simply be discarded instead of setting best-possible value to fix the error
- Packages "procps-ng" or "procps" are no longer needed because pcpu and pmem calculations are now done manually
- GLOBAL_ACTION is now available to trigger actions for PIDs without specific rules
- MAX_ALERTS_GLOBAL_ACTION can now be used to set a limit of alerts before a GLOBAL_ACTION is triggerd if PID has no specific rule
- Jail cgroup is now available to limit processes without specific rule with GLOBAL_ACTION
- The daemon now supports Logstash as data-collector
- Improved log-messages in syslog (better readable and additional information) 
- Percentage values now need the symbol '%' at the end and can be either integer or floating-point values
- Absolute values are now recogniced by symbols B, K, M, G, T, or P at the end of the value
- Whitespaces of settings will now be trimmed properly
- Utils class got additional functions for proper operation of the daemon
- Added this changelog section to the README.md file :)
- Improved documentation of settings in README.md, now with "Available Values" for settings
- Sending USR1 signal to the daemon's PID will remove all already limited processes from their cgroups
- Sending USR2 signal to the daemon's PID will output all loaded rules, settings and the current penalty list(s) in syslog
- More debug-output will now be written (depending on debug log-level)

#### Bugfixes
- Issue with cgroup cleanup was fixed
- Fixed an race-condition issue (PID's were left in the penalty list)


### pmdaemon v1.0

- Initial version of this process monitoring service
