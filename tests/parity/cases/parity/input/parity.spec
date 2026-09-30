Name:           parity
Version:        1.0
Release:        1
Summary:        Parity fixture for InitScriptCheck (rpmcrab issue #58 B2)
License:        MIT
BuildArch:      noarch

%description
One sysv init script plus %post/%preun scriptlets that have BOTH a body
and a -p interpreter. Reference rpmlint 2.10.0 (opensuse branch @ 84848c0)
computes `pkg[POSTIN] or pkg.scriptprog(POSTINPROG)`: the body (which calls
chkconfig) wins, so no postin-without-chkconfig / preun-without-chkconfig
is emitted. Preferring the -p interpreter instead would false-positive
both as E.

%install
mkdir -p %{buildroot}/etc/init.d
cat > %{buildroot}/etc/init.d/parity <<'EOF'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          parity
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:
# Default-Stop:      0 1 2 6
# Short-Description: parity fixture service
# Description:       Parity fixture for InitScriptCheck.
### END INIT INFO
# chkconfig: 345 85 15
case "$1" in
  start)
    touch /var/lock/subsys/parity
    ;;
  stop)
    rm -f /var/lock/subsys/parity
    ;;
  status)
    echo "parity is running"
    ;;
  reload)
    echo "reloading parity"
    ;;
  *)
    echo "Usage: $0 {start|stop|status|reload}"
    exit 1
    ;;
esac
EOF
chmod 755 %{buildroot}/etc/init.d/parity

%post -p /bin/sh
chkconfig --add parity

%preun -p /bin/sh
if [ "$1" = 0 ]; then
  chkconfig --del parity
fi

%files
%defattr(-,root,root,-)
/etc/init.d/parity

%changelog
* Wed Sep 30 2026 Tomas Chvatal <tomas.chvatal@gmail.com> - 1.0-1
- Parity fixture for InitScriptCheck.
