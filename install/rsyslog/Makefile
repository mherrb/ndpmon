install:
	cp 40-ndpmon.conf /etc/rsyslog.d/40-ndpmon.conf
	cp ndpmon.logrotate /etc/logrotate.d/ndpmon
	service rsyslog reload

uninstall:
	-rm /etc/rsyslog.d/40-ndpmon.conf
	-rm /etc/logrotate.d/ndpmon
	service rsyslog reload


