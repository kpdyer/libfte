#
# Regular cron jobs for the python-fte package
#
0 4	* * *	root	[ -x /usr/bin/python-fte_maintenance ] && /usr/bin/python-fte_maintenance
