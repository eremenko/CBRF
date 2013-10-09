
include ../Makefile.inc

all:    snmp_kos_daemon.pl

snmp_kos_daemon.pl: snmp_kos_daemon.src.pl sedfile.install
	$(SED) -f sedfile.install snmp_kos_daemon.src.pl > snmp_kos_daemon.pl
	chmod 755 snmp_kos_daemon.pl

sedfile.install: Makefile ../Makefile.inc perlpath
	echo 's#@INSTALL_BINDIR@#${INSTALL_BINDIR}#g' > $@
	echo 's#@INSTALL_LIBDIR@#${INSTALL_LIBDIR}#g' >> $@
	echo 's#@INSTALL_LOGSDIR@#${INSTALL_LOGSDIR}#g' >> $@
	echo 's#@INSTALL_LOCKDIR@#${INSTALL_LOCKDIR}#g' >> $@
	echo 's#@INSTALL_OWNER@#${INSTALL_OWNER}#g' >> $@
	echo "s#@PERL_PATH@#`cat perlpath`#g" >> $@

include ../Makefile.perl

clean:
	rm -f snmp_daemon.pl sedfile.install perlpath searchperl perlversion

install: all
	${INSTALL} -o ${INSTALL_OWNER} -d ${INSTALL_BINDIR}
	${INSTALL} -o ${INSTALL_OWNER} -d ${INSTALL_LIBDIR}
	${INSTALL} -o ${INSTALL_OWNER} -d ${INSTALL_LOCKDIR}
	${INSTALL} -o ${INSTALL_OWNER} -d ${INSTALL_LOGSDIR}
	${INSTALL} -o ${INSTALL_OWNER} snmp_kos_daemon.pl ${INSTALL_BINDIR}

