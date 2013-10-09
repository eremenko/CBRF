perlpath:	searchperl preffered.perl
	if [ -r preffered.perl -a -x "`cat preffered.perl`" ] ; then cat preffered.perl > $@ ; else sh searchperl > $@ ; fi

preffered.perl:
	echo /usr/sbin/perl > $@

searchperl:	perlversion ../Makefile.perl
	echo 'find / -name perl -path "*/bin/*" -print 2>/dev/null | sh perlversion' > $@

perlversion:	perlversion.awk ../Makefile.perl
	echo 'P_REV=0' > $@
	echo 'P_VER=0' >> $@
	echo 'P_SUB=0' >> $@
	echo 'while read perlbin ; do' >> $@
	echo "	(\"\$$perlbin\" -V:PERL_REVISION -V:PERL_VERSION -V:PERL_SUBVERSION 2>/dev/null ) | awk -F\"'\" -fperlversion.awk  | read rev ver sub" >> $@
	echo '	if [ "$$P_REV" -lt "$$rev" ] ; then' >> $@
	echo '		P_REV="$$rev"' >> $@
	echo '		P_VER="$$ver"' >> $@
	echo '		P_SUB="$$sub"' >> $@
	echo '		PERL_BIN="$$perlbin"' >> $@
	echo '		continue' >> $@
	echo '	fi' >> $@
	echo '	if [ "$$P_VER" -lt "$$ver" ] ; then' >> $@
	echo '		P_VER="$$ver"' >> $@
	echo '		P_SUB="$$sub"' >> $@
	echo '		PERL_BIN="$$perlbin"' >> $@
	echo '		continue' >> $@
	echo '	fi' >> $@
	echo '	if [ "$$P_SUB" -lt "$$sub" ] ; then' >> $@
	echo '		P_SUB="$$sub"' >> $@
	echo '		PERL_BIN="$$perlbin"' >> $@
	echo '		continue' >> $@
	echo '	fi' >> $@
	echo 'done' >> $@
	echo 'if [ x"$$PERL_BIN" = x ] ; then' >> $@
	echo '	echo perl not found >&2' >> $@
	echo '	exit 2' >> $@
	echo 'else' >> $@
	echo '	echo "$$PERL_BIN"' >> $@
	echo '	exit 0' >> $@
	echo 'fi' >> $@

