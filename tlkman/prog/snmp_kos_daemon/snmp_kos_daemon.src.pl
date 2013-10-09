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

use strict ;
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

use constant NETPROBE_SOCKETFILE => '@INSTALL_LOCKDIR@/.snmp_kos_daemon.socket' ;
use constant NETPROBE_IPC_SOCKETFILE => '@INSTALL_LOCKDIR@/.snmp_kos_daemon.ipc_socket' ;
use constant NETPROBE_LOCKFILE => '@INSTALL_LOCKDIR@/.snmp_kos_daemon.lock' ;

package NetProbe::CBR::AVSU::KOS_Daemon ;

use IO::File ;
use LockFile::Simple ;
use IO::Socket::UNIX ;
#use POSIX qw (:sys_wait_h} ;
use Crypt::CBC ;
use Digest::SHA ;

use vars qw($VERSION @ISA) ;
@ISA = qw(Net::Daemon) ;


sub Version ($) { 'NetProbe::CBR::AVSU::KOS_Daemon version 1.00 (C) Sergey A.Eremenko and NetProbe Llc' ; }

sub new ($$;$) {
        my ($class,$attr,$args) = @_ ;

        my ($self) = $class->SUPER::new($attr,$args) ;

        $self->{'_short_program_name'} = exists ($self->{'np_short_program_name'}) ? $self->{'np_short_program_name'} : $0 ;
        delete $self->{'np_short_program_name'} ;

        $self->{'_ipc_socket'} = exists ($self->{'np_ipc_socket'}) ? $self->{'np_ipc_socket'} : '/tmp/.cae.snmp_daemon.ipc.socket' ;
        delete $self->{'np_ipc_socket'} ;

        $self->{'_lock_file'} = exists ($self->{'np_lock_file'}) ? $self->{'np_lock_file'} : '/tmp/.cae.snmp_daemon.error.lock' ;
        delete $self->{'np_lock_file'} ;

        $self->{'_retransmit_sleep_time'} = exists ($self->{'np_retransmit_sleep_time'}) ? $self->{'np_retransmit_sleep_time'} : 20 ;
        delete $self->{'np_retransmit_sleep_time'} ;

        $self ;
}

sub DESTROY {
        my ($self) = shift ;

        if (exists ($self->{'_need_delete_ipc_socket'})) {
                $self->Debug ("DESTROY[$$]: Delete `%s'",$self->{'_ipc_socket'}) ;
                unlink ($self->{'_ipc_socket'}) or
                        $self->Error ("DESTROY[$$]: Can't delete `%s': $!",$self->{'_ipc_socket'}) ;
                delete $self->{'_need_delete_ipc_socket'} ;
        }
}

sub Run ($) {
        my ($self) = @_ ;
	my ($line, $sock) ;
	my ($result,$error) ;
	my ($secret_password) = "Qui<k broWn foX jumps 0ver the lazY dog" ;

	$sock = $self->{'socket'} ;
	$result = "" ;
	$error = 0 ;
	while (1) {
		my $salt = unpack('H128',Crypt::CBC->random_bytes(32)) ;
# Посылаем либо результат предыдущей работы, либо пустую строку
# С сообщением об ошибке, конечно.
		my $rc = printf $sock ("%s %s%s\n",$error?"ERR":"OK",$salt,$result) ;
		if (!$rc) {
			$self->Error ("Client connection error %s",$sock->error()) ;
			$sock->close() ;
			return ;
		}

		$error = 0 ;
# Читаем команду от пользователя
		if (!defined ($line = $sock->getline())) {
			if ($sock->error()) {
				$self->Error ("Client connection error %s",$sock->error()) ;
			}
			$sock->close() ;
			return ;
		}
		$line =~ s{\s+$}{} ;	# удаляем переводы строки и пробелы
#
# SNMP Blowfish SHA Cryptsalt DATA
#
# Если команда не SNMP - в результат ERR Invalid command и next
		if ($line !~ /^SNMP (#NP#) (\S+) (\S+) (.*)$/) {
			$self->Error ("Invalid command `%s'",$line) ;
			$error = 1 ;
			$result = " Invalid command" ;
			next ;
		} 
		my ($magic,$sha,$crypt,$data) = ($1,$2,$3,$4) ;
		if ($magic ne "#NP#") {
			$self->Error ("Invalid magic `%s'",$line) ;
			$error = 1 ;
			$result = " Invalid magic" ;
			next ;
		}
		{
		my $cipher = Crypt::CBC->new (-key=>$secret_password,-cipher=>'Blowfish') ;
		my $decrypt_salt = $cipher->decrypt_hex($crypt) ;
		my $calc_sha = Digest::SHA->new(256) ;
		$calc_sha->add($decrypt_salt) ;

		if ($sha ne $calc_sha->hexdigest()) {
			$self->Error ("Invalid password `%s'",$line) ;
			$error = 1 ;
			$result = " Invalid password" ;
			next ;
		}
		undef $cipher ;
		undef $decrypt_salt ;
		undef $calc_sha ;
		}
		$self->Log("info",$data) ;
	}
}

package main ;

use POSIX 'setsid' ;

use Data::Dumper ;

my $short_program_name = $0 ;
$short_program_name =~ s{^.*/([^/]+)$}{$1} ;
$short_program_name =~ s{^(\w+).*$}{$1} ;

defined (my $log_file = IO::File->new(sprintf(NETPROBE_LOGFILE,$short_program_name),"a")) or
        die "Can't open log file: $!\n" ;
$log_file->autoflush (1) ;

my $lock = LockFile::Simple->make (
	-format => NETPROBE_LOCKFILE,
	-autoclean => 1,
	-max => 6,
	-delay => 1,
	-warn => 0,
	-hold => 0,
	-stale => 1,
	-efunc => undef,
	-wfunc => undef,

#       autoclean               keep track of locks and release pending one at END time
#   max                         max number of attempts
#       delay                   seconds to wait between attempts
#       format                  how to derive lockfile from file to be locked
#       hold                    max amount of seconds before breaking lock (0 for never)
#       ext                             lock extension
#       nfs                             true if lock must "work" on top of NFS
#       stale                   try to detect stale locks via SIGZERO and delete them
#       warn                    flag to turn warnings on
#       wmin                    warn once after that many waiting seconds
#       wafter                  warn every that many seconds after first warning
#       wfunc                   warning function to be called
#       efunc                   error function to be called

) ;

my $server = NetProbe::CBR::AVSU::KOS_Daemon->new ({
        'pidfile' => sprintf(NETPROBE_PIDFILE,$short_program_name),
        'user' => '@INSTALL_OWNER@',
#       'loop-child' => 1,
#       'loop-timeout' => 20,
        'mode' => 'fork',
        'logfile' => $log_file,
        'listen' => 1,
        'debug' => 1,
        'np_ipc_socket' => NETPROBE_IPC_SOCKETFILE,
        'np_short_program_name' => ${short_program_name},
        'np_lock_file' => NETPROBE_LOCKFILE,
        'np_retransmit_sleep_time' => 5,
	'catchint'=>1,
	'localport' => 3246,
             'clients' => [
                 # Accept the local
                 {
                     'mask' => '^10\.93\.64\.20$',
                     'accept' => 1
                 },
                 # Accept the local
                 {
                     'mask' => '^127\.0\.0\.1$',
                     'accept' => 1
                 },
                 # Deny everything else
                 {
                     'mask' => '.*',
                     'accept' => 0
                 }
	],
}) ;

$0 = "${short_program_name}: listen" ;

$SIG{'HUP'} = sub {
        my ($sig) = @_ ;

        return ;
} ;

$SIG{'__DIE__'} = sub {
        if (caller(0) ne "Net::Daemon::Log") {
                $server->Error("pid[$$]:%s",$_[0]) ;
        }
        exit 1 ;
} ;

$SIG{'__WARN__'} = sub {
        if (caller(0) ne "Net::Daemon::Log") {
                $server->Error("pid[$$]:%s",$_[0]) ;
        }
} ;

chdir '/'                       or die "Can't chdir to /: $!" ;
open STDIN,'/dev/null'          or die "Can't read /dev/null: $!" ;
open STDOUT,'>/dev/null'        or die "Can't write to /dev/null: $!" ;
defined (my $pid = fork())      or die "Can't fork: $!" ;
exit if $pid ;
setsid()                        or die "Can't start a new session: $!" ;
open STDERR,'>&STDOUT'          or die "Can't dup stdout: $!" ;

$SIG{'TERM'} = sub {
        kill 'TERM',-$$ ;
        exit 2 ;
} ;

if ($lock->lock (NETPROBE_LOCKFILE)) {
	$server->Log("start ${short_program_name}") ;
	$server->Bind() ;
	$server->Log("finish ${short_program_name}") ;
	$lock->unlock(NETPROBE_LOCKFILE) ;
}
else {
	$server->Error ("Can't obtain lock `".NETPROBE_LOCKFILE."', skip run") ;
}

exit 0 ;

__DATA__
#####################################################################################


sub Run ($) {
	my($self) = @_ ;
	my($line, $sock) ;
	my ($result,$error) ;
	my ($secret_password) = "Qui<k broWn foX jumps 0ver the lazY dog" ;

	$sock = $self->{'socket'} ;
	$result = "" ;
	$error = 0 ;
	while (1) {
# Вычисляем новый salt для нового шага
		my $salt = pack('H128',Crypt::CBC->random_bytes(32)) ;
# Посылаем либо результат предыдущей работы, либо пустую строку
# С сообщением об ошибке, конечно.
		my $rc = printf $sock ("%s %s%s\n",$error?"ERR":"OK",$salt,$result) ;
		if (!$rc) {
			$self->Error ("Client connection error %s",$sock->error()) ;
			$sock->close() ;
			return ;
		}

		$error = 0 ;
# Читаем команду от пользователя
		if (!defined ($line = $sock->getline())) {
			if ($sock->error()) {
				$self->Error ("Client connection error %s",$sock->error()) ;
			}
			$sock->close() ;
			return ;
		}
		$line =~ s{\s+$}{} ;	# удаляем переводы строки и пробелы
#
# STAT Blowfish CRC Cryptsalt ClientID Lport Stat begin_date end_date
#
# Если команда не STAT - в результат ERR Invalid command и next
		($line =~ /^STAT /) or do {
			$self->Error ("Invalid command `%s'",$line) ;
			$error = 1 ;
			$result = " Invalid command" ;
			next ;
		} ;
		my ($command,$cipher,$crc,$crypt,$client,$lport,$stat_type,$begin_date,$end_date) = split (m{\s+},$line) ;
# Если не хватает аргументов или они неверны - в результат ERR Invalid argumet и next
		if ($cipher ne "Blowfish" or
		    !defined ($crc) or
		    !defined ($crypt) or
		    !defined ($client) or
		    !defined ($lport) or
		    !defined ($stat_type) or
		    !defined ($begin_date) or
		    !defined ($end_date) or
		    $client !~ m{^\d+$} or
		    $lport !~ m{^\d+$} or
		    $begin_date !~ m{^\d\d-\d\d-\d\d\d\d$} or
		    $end_date !~ m{^\d\d-\d\d-\d\d\d\d$} or
		    $stat_type !~ m{c|d|n|o|t}) {
INVALID_ARG:
			$self->Error ("Invalid argument `%s'",$line) ;
			$error = 1 ;
			$result = " Invalid argument" ;
			next ;
		}
		$begin_date =~ m{^(\d\d)-(\d\d)-(\d\d\d\d)$} ;
		my $begin_month = $2 ;
		my $begin_year = $3 ;
		eval { timelocal (0,0,0,$1,$2-1,$3) ; } ;
		if ($@) {
			goto INVALID_ARG ;
		}
		$end_date =~ m{^(\d\d)-(\d\d)-(\d\d\d\d)$} ;
		my $end_month = $2 ;
		my $end_year = $3 ;
		eval { timelocal (0,0,0,$1,$2-1,$3) ; } ;
		if ($@) {
			goto INVALID_ARG ;
		}
		if ($begin_month ne $end_month or
		    $begin_year ne $end_year) {
			goto INVALID_ARG ;
		}
# Расшифровываем со своим паролем полученный отзыв
# Если не совпадает с salt - в результат ERR Invalid password и next
		$rc = CCTR::decrypt_str($secret_password,"${cipher} ${crc} ${crypt}") ;
		if (!defined ($rc) or ($rc ne $salt)) {
			$self->Error ("Invalid password `%s'",$line) ;
			$error = 1 ;
			$result = " Invalid password" ;
			next ;
		}
		
# Получили валидное что-то, 
# теперь читаем сам файлик и суммируем
		my $statfile = "${datapath}/".$statloc{$stat_type}."/${begin_year}${begin_month}/${client}" ;
		open (STAT,"${statfile}") || do {
			$self->Error ("Can't open `${statfile}' $!") ;
			$error = 1 ;
			$result = " Can't open `${statfile}' $!" ;
			next ;
		} ;
		my ($in,$out,$exceed_time) = (0.0,0.0,0) ;
		while (<STAT>) {
			chomp ;
			my @sl = split (m{\t}) ;
			($sl[0] eq $lport) || next ;
# проверим даты
			(make_epoch ($sl[1])>=make_epoch($begin_date) and
			 make_epoch ($sl[1])<=make_epoch($end_date)) or next ;
			if ($sl[$statfield{$stat_type}] ne "") {
				$in += $sl[$statfield{$stat_type}] * $statkoef{$stat_type} ;
			}
			if ($sl[$statoutfield{$stat_type}] ne "") {
				$out += $sl[$statoutfield{$stat_type}] * $statkoef{$stat_type} ;
			}
			if ($sl[$stattimefield{$stat_type}] ne "") {
				$exceed_time += $sl[$stattimefield{$stat_type}] ;
			}
		}
		close (STAT) ;
	
		$result = " $in $out $exceed_time" ;
	}
}

sub make_epoch {
	my ($date) = @_ ;

	$date =~ m{^(\d\d)-(\d\d)-(\d\d\d\d)$} ;
	return timelocal (0,0,0,$1,$2-1,$3) ;
}

package main ;

use POSIX 'setsid';

chdir '/'               or die "Can't chdir to /: $!";
open STDIN, '/dev/null' or die "Can't read /dev/null: $!";
open STDOUT, '>/dev/null' or die "Can't write to /dev/null: $!";
defined(my $pid = fork) or die "Can't fork: $!";
exit if $pid;
setsid                  or die "Can't start a new session: $!";
open STDERR, '>&STDOUT' or die "Can't dup stdout: $!";

my $server = Get_Stat->new({'pidfile' => '/var/run/get_stat_daemon.pid',
	'user'=>'asa',
	'catchint'=>1,
	'localport' => 3246,
             'clients' => [
                 # Accept the local
                 {
                     'mask' => '^195\.161\.0\.200$',
                     'accept' => 1
                 },
                 # Deny everything else
                 {
                     'mask' => '.*',
                     'accept' => 0
                 }
             ]
}) ;
$server->Bind() ;

__DATA__
