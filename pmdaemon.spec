Name:     	pmdaemon
Version:  	1.0
Release:  	2%{?dist}
Summary:  	Process Monitoring Daemon package
License:  	GPLv3+
URL:      	https://github.com/gerard-kanduth/pmdaemon
BuildRoot: 	/srv/pmdaemon

%description
This package will install the Process Monitoring Daemon service "pmdaemon.service"
which can be used to monitor and limit processes via rules and the help of Cgroup v2.

%prep
# nothing to do here

%build
# the build will be controlled via Makefile

%install
cd %{buildroot}
cd ../../
mkdir -p %{buildroot}/usr/sbin
mkdir -p %{buildroot}/etc/pmdaemon
mkdir -p %{buildroot}/etc/pmdaemon/rules.d
mkdir -p %{buildroot}/usr/lib/systemd/system

install -m 755 build/usr/sbin/pmdaemon %{buildroot}/usr/sbin/pmdaemon
install -m 644 systemd/pmdaemon.service %{buildroot}/usr/lib/systemd/system/pmdaemon.service
install -m 644 settings.conf %{buildroot}/etc/pmdaemon/settings.conf
install -m 644 rules.d/stress-rule.conf %{buildroot}/etc/pmdaemon/rules.d/stress-rule.conf
systemctl daemon-reload

%files
/usr/sbin/pmdaemon
/usr/lib/systemd/system/pmdaemon.service
/etc/pmdaemon

%changelog
* Tue Jan 03 2023 Gerard Raffael Kanduth <gerardraffael.kanduth@edu.fh-kaernten.ac.at> - 1.0
- Initial version of the package

