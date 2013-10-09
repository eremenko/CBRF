#
# Copyright (C) 2008-2009 Sergey A.Eremenko (eremenko.s@gmail.com)
# Copyright (C) 2009 NetProbe, Llc (info@net-probe.ru)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

include ../Makefile.inc

all:    snmp_daemon.pl

snmp_daemon.pl: snmp_daemon.src.pl sedfile.install
	$(SED) -f sedfile.install snmp_daemon.src.pl > snmp_daemon.pl
	chmod 755 snmp_daemon.pl

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
	${INSTALL} -o ${INSTALL_OWNER} snmp_daemon.pl ${INSTALL_BINDIR}

