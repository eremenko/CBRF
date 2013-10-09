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

perlpath:       searchperl

searchperl:     perlversion
	echo 'find / -name perl -path "*/bin/*" -print 2>/dev/null | sh perlversion' > $@

perlversion:    perlversion.awk
	echo 'P_REV=0' > $@
	echo 'P_VER=0' >> $@
        echo 'P_SUB=0' >> $@
        echo 'while read perlbin ; do' >> $@
        echo '  "$perlbin" -V:PERL_REVISION -V:PERL_VERSION -V:PERL_SUBVERSION | awk -F\' -fperlversion.awk | read rev ver sub' >> $@
        echo '  if [ "$P_REV" -lt "$rev" ] ; then' >> $@
        echo '          P_REV="$rev"' >> $@
        echo '          P_VER="$ver"' >> $@
        echo '          P_SUB="$sub"' >> $@
        echo '          PERL_BIN="$perlbin"' >> $@
        echo '          continue' >> $@
        echo '  fi' >> $@
        echo '  if [ "$P_VER" -lt "$ver" ] ; then' >> $@
        echo '          P_VER="$ver"' >> $@
        echo '          P_SUB="$sub"' >> $@
        echo '          PERL_BIN="$perlbin"' >> $@
        echo '          continue' >> $@
        echo '  fi' >> $@
        echo '  if [ "$P_SUB" -lt "$sub" ] ; then' >> $@
        echo '          P_SUB="$sub"' >> $@
        echo '          PERL_BIN="$perlbin"' >> $@
        echo '          continue' >> $@
        echo '  fi' >> $@
        echo 'done' >> $@
        echo 'if [ x"$PERL_BIN" == x ] ; then' >> $@
        echo '  echo perl not found >&2' >> $@
        echo 'else' >> $@
        echo '  echo "$PERL_BIN"' >> $@
        echo 'fi' >> $@


clean:
	rm -f snmp_daemon.pl sedfile.install

install: all
	${INSTALL} -o ${INSTALL_OWNER} -d ${INSTALL_BINDIR}
	${INSTALL} -o ${INSTALL_OWNER} -d ${INSTALL_LIBDIR}
	${INSTALL} -o ${INSTALL_OWNER} -d ${INSTALL_LOCKDIR}
	${INSTALL} -o ${INSTALL_OWNER} -d ${INSTALL_LOGSDIR}
