include ../Makefile.inc

all:	snmp_daemon.pl

snmp_daemon.pl:	snmp_daemon.src.pl sedfile.install
	sed -f sedfile.install snmp_daemon.src.pl > snmp_daemon.pl
	chmod 755 snmp_daemon.pl

sedfile.install: Makefile ../Makefile.inc
	echo 's#@INSTALL_BINDIR@#${INSTALL_BINDIR}#g' > $@
	echo 's#@INSTALL_LIBDIR@#${INSTALL_LIBDIR}#g' >> $@
	echo 's#@INSTALL_LOGSDIR@#${INSTALL_LOGSDIR}#g' >> $@
	echo 's#@INSTALL_LOCKDIR@#${INSTALL_LOCKDIR}#g' >> $@
	echo 's#@INSTALL_OWNER@#${INSTALL_OWNER}#g' >> $@

clean:
	rm -f snmp_daemon.pl sedfile.install

install: all
	${INSTALL} -o ${INSTALL_OWNER} -d ${INSTALL_BINDIR}
	${INSTALL} -o ${INSTALL_OWNER} -d ${INSTALL_LIBDIR}
	${INSTALL} -o ${INSTALL_OWNER} -d ${INSTALL_LOCKDIR}
	${INSTALL} -o ${INSTALL_OWNER} -d ${INSTALL_LOGSDIR}
	${INSTALL} -o ${INSTALL_OWNER} snmp_daemon.pl ${INSTALL_BINDIR}
