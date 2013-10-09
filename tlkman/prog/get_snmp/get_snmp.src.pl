#!@PERL_PATH@
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

use warnings ;
use Config ;

my $style ;

BEGIN {
if (exists($Config{installstyle})) {
        $style = $Config{installstyle} ;
        $style .= "/" ;
        $style =~ s{^lib\/}{} ;
}
else {
        $style = "" ;
}
}
use lib "@INSTALL_LIBDIR@/${style}site_perl/$Config{PERL_REVISION}.$Config{PERL_VERSION}.$Config{PERL_SUBVERSION}" ;
use lib "@INSTALL_LIBDIR@/${style}site_perl/$Config{PERL_REVISION}.$Config{PERL_VERSION}.$Config{PERL_SUBVERSION}/mach" ;

require Net::Daemon ;

use constant NETPROBE_BINDIR => '@INSTALL_BINDIR@' ;
use constant NETPROBE_LOCKDIR => '@INSTALL_LOCKDIR@' ;
use constant NETPROBE_LOGFILE => '@INSTALL_LOGSDIR@/%s.log' ;
use constant NETPROBE_PIDFILE => '@INSTALL_LOCKDIR@/%s.pid' ;

use constant NETPROBE_SOCKETFILE => '@INSTALL_LOCKDIR@/.snmp_daemon.socket' ;
use constant NETPROBE_IPC_SOCKETFILE => '@INSTALL_LOCKDIR@/.snmp_daemon.ipc_socket' ;
use constant NETPROBE_LOCKFILE => '@INSTALL_LOCKDIR@/.snmp_daemon.lock' ;

use IO::File ;
use IO::Socket::UNIX ;

my ($loop_sock) ;

$loop_sock = IO::Socket::UNIX->new (Type=>SOCK_STREAM) or
                die("$0: Can't create socket `".NETPROBE_SOCKETFILE."': $!") ;
$loop_sock->connect(pack_sockaddr_un(NETPROBE_SOCKETFILE)) or
                die("$0: Can't connect socket `".NETPROBE_SOCKETFILE."': $!") ;

#print $loop_sock "A23456789A1234567890\n" ;
#print $loop_sock "B23456789B1234567890B\n" ;

my ($full_string,@arg) ;

foreach my $arg (@ARGV) {
	$arg =~ s{\n}{ } ;
	push (@arg,$arg) ;
}

$full_string = join("|",@arg) ;
print $loop_sock "${full_string}\n" ;

$loop_sock->close() ;
undef $loop_sock ;
 
