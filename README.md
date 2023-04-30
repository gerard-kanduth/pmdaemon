# Process Monitoring Daemon

## DESCRIPTION
This daemon-service can be used to monitor and limit misbehaving processes
on Linux-based systems. The aim of this project is to provide a tool which will
give administrators the possibillity to specify rules with desired thresholds
for any specific type of application. The daemon will constantly check all
running processes if values like CPU-, and/or RAM-Usage exceeds the set
maximum. A Limitation of these applications can be performed by the help of
cgroup v2. Actions like killing or pausing the process can also be configured.
Additionally information can be forwarded to a datacollector (e.g. Graylog2)
to further analyze the cause why the task is utilizing that much
system-resources.

## AUTHORS
Gerard Kanduth <gerardraffael.kanduth@edu.fh-kaernten.ac.at>

## REQUIREMENTS
+ Linux-based System
+ GNU Compiler Collection (g++) for compiling
+ "procps-ng" or "procps" package installed

## INSTALLATION

**Note:** The package "rpm-build" is needed to create RPM packages.

### Install needed packages

On Fedora/RedHat:
```
dnf install gcc gcc-c++ rpm-build libcurl libcurl-devel
```

### Clone the repository
```
if ! $(test -d /srv); then mkdir /srv; fi
cd /srv
git clone https://github.com/gerard-kanduth/pmdaemon.git
cd pmdaemon
```

### Build and package to RPM
**Note:** It is possible to simply build the project without packing by running "make pmdaemon" instead.
```
make all
```

### Install RPM on system
```
rpm -i $HOME/rpmbuild/RPMS/x86_64/pmdaemon*.rpm
```

## SETTINGS DESCRIPTION

In the following section the default-configuration is described.
However, it is possible to override some global setting-values via
specific rules.

### General settings

Set the loglevel: [error, notice, info, debug]
```
LOGLEVEL=info
```

Number of faulty check-cycles before daemon terminates
```
MAX_ERRORS=10
```

Set the check-interval for the daemon in seconds (0 is not allowed)
```
CHECK_INTERVAL=1
```

Number of check cycles a process-threshold needs to be exceeded before an alert is triggered
```
CHECKS_BEFORE_ALERT=30
```

Number of checks after alert before PID gets removed from penatly-list
```
CHECKS_COOLDOWN=60
```

The CPU threshold for a process (can be overvritten via specific rule)
```
CPU_TRIGGER_THRESHOLD=80.0
```

The memory threshold for a process (can be overvritten via specific rule)
```
MEM_TRIGGER_THRESHOLD=50.0
```

Decide if an alert should be triggered if the process is a zombie or in D-state (0=off, 1=on)
```
STATE_TRIGGER=0
```

Only check processes which have a specific rule, all other processes will be skipped (0=off, 1=on)
```
SPECIFIC_RULES_CHECK_ONLY=0
```

Decide if possible available rules should be read from RULES_DIRECTORY (0=off, 1=on)
```
LOAD_RULES=1
```

Set the directory where the rules reside
```
RULES_DIRECTORY=/etc/pmdaemon/rules.d
```

Cleanup of created cgroups after termination (0=off, 1=on)
All created specific cgroups will be erased and processes will be unlimited again
```
TERM_CGROUP_CLEANUP=1
```

### Datacollector settings

Enable/Disable Graylog logging (0=off, 1=on)
```
GRAYLOG_ENABLED=0
```

Decide which method should be used to transfer data (http, TODO: udp and tcp will follow soon)
Information can be found here: https://docs.graylog.org/docs/gelf
```
GRAYLOG_TRANSFER_METHOD=http
```

The FQDN of the Graylog instance
```
GRAYLOG_FQDN=graylog.local
```

The port of the graylog instance
```
GRAYLOG_PORT=12201
```

Decide if HTTP or HTTPS should be used for transport (0=http, 1=https)
```
GRAYLOG_HTTP_SECURE=0
```

Only used when running in "http" mode, normally no need to alter this setting
Leading '/' is mandatory
```
GRAYLOG_HTTP_PATH=/gelf
```


## EXAMPLE-RULE WITH DESCRIPTION

This sections shows an example for a specific rule which will be deployed
when installing the package on a system.

Name of the rule
```
RULE_NAME=stress-rule
```

Command which will be monitored (can either be "/usr/bin/stress" or simply "stress")
The command needs to start with this string to get monitored
```
COMMAND=stress
```

If you define the COMMAND e.g. "stress", only processes starting with exact "stress" will be monitored
However, a user may start the command with "/bin/stress" or "/usr/bin/stress"
By enabling INCLUDE_BINARY_FOLDER_CHECK the following variations will also be checked:

- /bin/stress
- /sbin/stress
- /usr/bin/stress
- /usr/sbin/stress
- /usr/local/bin/stress
- /usr/local/sbin/stress

(0=off, 1=on)
```
INCLUDE_BINARY_FOLDER_CHECK=1
```

Set a threshold for CPU and MEM (in percent, floating-point)
As soon as the process is above this values it will be added to the penalty-list
```
CPU_TRIGGER_THRESHOLD=20.0
MEM_TRIGGER_THRESHOLD=20.0
```

The CHECK_INTERVAL (in seconds) and the default CHECKS_BEFORE_ALERT is set in the settings.conf file
This setting can be overwritten for specific commands by simply setting CHECKS_BEFORE_ALERT here
```
CHECKS_BEFORE_ALERT=10
```

Decide if limiting on the given process should be performed, otherwise only alerting and data-collecting will be done (0=off, 1=on)
```
ENABLE_LIMITING=1
```

Limit the given process to the following core-limit (in percent)
```
LIMIT_CPU_PERCENT=5
```

Limit the given process to the following mem-limit (in bytes)
```
LIMIT_MEMORY_VALUE=50000
```

Decide if the OOM-Killer should be invoked if the memory-limit is reached (0=off, 1=on)
```
OOM_KILL_ENABLED=1
```

Decide if the process should be checked, otherwise no limiting and/or alerting will be performed (0=off, 1=on)
```
NO_CHECK=0
```

This option will put the process'es PID to the freezer - process will be "paused" (0=off, 1=on)
```
FREEZE=0
```

This option will simply kill the process as soon as it was above the threshold limits for CHECK_INTERVAL * CHECKS_BEFORE_ALERT (in seconds, 0=off, 1=on)
```
PID_KILL_ENABLED=0
```

Decide if data from /proc/<PID> should be collected and send for further analysis (0=off, 1=on)
```
SEND_PROCESS_FILES=1
```
