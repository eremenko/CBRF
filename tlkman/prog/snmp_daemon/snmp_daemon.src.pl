#!/opt/perl/bin/perl
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

use lib "@INSTALL_LIBDIR@/perl5/site_perl/$Config{PERL_REVISION}.$Config{PERL_VERSION}.$Config{PERL_SUBVERSION}" ;

require Net::Daemon ;

use constant NETPROBE_BINDIR => '@INSTALL_BINDIR@' ;
use constant NETPROBE_LOCKDIR => '@INSTALL_LOCKDIR@' ;
use constant NETPROBE_LOGFILE => '@INSTALL_LOGSDIR@/%s.log' ;
use constant NETPROBE_PIDFILE => '@INSTALL_LOCKDIR@/%s.pid' ;

use constant NETPROBE_SOCKETFILE => '@INSTALL_LOCKDIR@/.snmp_daemon.socket' ;
use constant NETPROBE_IPC_SOCKETFILE => '@INSTALL_LOCKDIR@/.snmp_daemon.ipc_socket' ;
use constant NETPROBE_LOCKFILE => '@INSTALL_LOCKDIR@/.snmp_daemon.lock' ;

package NetProbe::CBR::AVSU::Daemon ;

use IO::File ;
#use LockFile::Simple ;
use IO::Socket::UNIX ;
#use POSIX qw (:sys_wait_h} ;
use English ;

use vars qw($VERSION @ISA) ;
@ISA = qw(Net::Daemon) ;

sub Version ($) { 'NetProbe::CBR::AVSU::Daemon version 1.00 (C) Sergey A.Eremenko and NetProbe Llc' ; }

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
	my ($sock,$loop_sock) ;
	my ($rin,$win,$loop_state,@loop_queue,$rout,$wout) ;
	my ($sock_buf,$loop_read_buf,$loop_write_buf,$loop_write_buf_count) ;

	$0 = $self->{'_short_program_name'}. ": reading" ;
	$sock = $self->{'socket'} ;

	$self->Debug ("Run[$$]: making socket/connect") ;
	$loop_sock = IO::Socket::UNIX->new (Type=>SOCK_STREAM) or
		$self->Fatal("Run[$$]: Can't create socket `".$self->{'_ipc_socket'}."': $!") ;
	$loop_sock->connect(pack_sockaddr_un($self->{'_ipc_socket'})) or
		$self->Fatal("Run[$$]: Can't connect socket `".$self->{'_ipc_socket'}."': $!") ;
	
	$loop_state = 1 ;
	@loop_queue = () ;
	$SIG{'PIPE'} = sub {
		$self->Debug ("SIGPIPE,i dont know WTF") ;
	} ;
	$SIG{'TERM'} = sub {
		$self->DESTROY() ;
		exit 2 ;
	} ;

	while (defined($sock) or scalar(@loop_queue) or defined ($loop_write_buf) or $loop_state ==2) {
		my $chr ;

		$rin = $win = '' ;
		if (defined ($sock)) {
			vec($rin,fileno($sock),1) = 1 ;
		}
		if (defined ($loop_sock)) {
			if ($loop_state==1 and (scalar(@loop_queue) or defined ($loop_write_buf))) {
				vec($win,fileno($loop_sock),1) = 1 ;
			}
			vec($rin,fileno($loop_sock),1) = 1 ;
		}

		my $nfound = select ($rout=$rin,$wout=$win,undef,undef) ;

		if ($nfound<0) {
			if ($! == POSIX::EINTR() and $self->{'catchint'}) {
				next ;
			}
			$self->Fatal("Run[$$]: %s server failed to select(): $!",ref($self)) ;
		}
		else {
# reading from OVO snmp_script
			if (defined ($sock) and vec($rout,fileno($sock),1)==1) {
	
				my $rc = $sock->sysread($chr,1) ;
				if (!defined ($rc)) {
					if ($! == POSIX::EINTR() and $self->{'catchint'}) {
						next ;
					}
					$self->Error("Run[$$]: %s server failed to read(sock): %s",ref($self),$sock->error() || $!) ;
					undef $sock ;
				}
				elsif ($rc==0) {
# EOF
					$self->Debug ("Run[$$]: sock EOF") ;

					undef $sock ;
				}
				else {
					if ($chr eq chr(10)) {
						push (@loop_queue,$sock_buf) ;
						undef ($sock_buf) ;
					}
					else {
						$sock_buf .= $chr ;
					}
				}	
				#$self->Debug ("Run[$$]: read sock {%s}",defined($sock_buf)?$sock_buf:"(undef)") ;
			}
			if (defined ($loop_sock) and vec($rout,fileno($loop_sock),1)==1) {

				my $rc = $loop_sock->sysread($chr,$loop_state==2 ? 1 : 0) ;
				if (!defined ($rc)) {
					if ($! == POSIX::EINTR() and $self->{'catchint'}) {
						next ;
					}
					$self->Error("Run[$$]: %s server failed to read(loop_sock): %s",ref($self),$loop_sock->error() || $!) ;
					undef $loop_sock ;
					$loop_write_buf_count = 0 ;
				}
				elsif ($rc==0) {
					$self->Debug ("Run[$$]: loop_sock EOF") ;
					undef $loop_sock ;
					$loop_write_buf_count = 0 ;
				}
				else {
					if ($chr eq chr(10)) {
						if ($loop_read_buf ne "+OK" and $loop_read_buf ne "+ERR") {
							$self->Error("Run[$$]: %s server received from loop_sock: `%s', skip it",ref($self),$loop_read_buf) ;
						}
						undef ($loop_read_buf) ;
						$loop_state = 1 ;
					}
					else {
						$loop_read_buf .= $chr ;
					}
				}
				#$self->Debug ("Run[$$]: read ipc_sock {%s}",defined($loop_read_buf)?$loop_read_buf:"(undef)") ;
# EOF
			}
			if (defined ($loop_sock) and $loop_state==1 and vec($wout,fileno($loop_sock),1)==1) {

				if (!defined ($loop_write_buf) and scalar(@loop_queue)) {
					$loop_write_buf = shift (@loop_queue) . "\n";
					$loop_write_buf_count = 0 ;
				}
				#$self->Debug ("Run[$$]: write ipc_sock {%s} %d",$loop_write_buf,$loop_write_buf_count) ;
				my $rc = $loop_sock->syswrite ($loop_write_buf,1,$loop_write_buf_count) ;
				if (!defined ($rc)) {
					if ($! == POSIX::EINTR() and $self->{'catchint'}) {
						next ;
					}
					$self->Error("Run[$$]: %s server failed to write(loop_sock): %s",ref($self),$loop_sock->error() || $!) ;
					undef $loop_sock ;
				}
				else {
					$loop_write_buf_count += $rc ;
					if (length($loop_write_buf)<=$loop_write_buf_count) {
						undef $loop_write_buf ;
						$loop_state = 2 ;
					}
				}
			}
		}
	}
}

sub Send_Trap_To_KOS {
	my ($self,$ref) = @_ ;

	delete $self->{'_need_delete_ipc_socket'} ;
	foreach (@{$ref}) {
		$self->Log('info',"Send_KOS[$$]: `".$_."'") ;
	}
}

sub Circle_Queue {
	my ($self) = @_ ;
	my ($ipc_sock_wait,@ipc_socks) ;
	my ($out_buf,$out_buf_count) ;
	my ($rin,$rout,$win,$wout,$last_time) ;
	my (@queue,$send_flag) ;

	$0 = $self->{'_short_program_name'}.": circle queue" ;
	$self->Debug("Circle_Queue[$$]: Making ipc socket") ;
	$ipc_sock_wait = IO::Socket::UNIX->new (Type=>SOCK_STREAM,
		Local => $self->{'_ipc_socket'}
	) or
		$self->Fatal("Circle_Queue[$$]: Can't create socket `".$self->{'_ipc_socket'}."': $!") ;
	$self->{'_need_delete_ipc_socket'} = 1 ;
	$ipc_sock_wait->listen(1) or
		$self->Fatal("Circle_Queue[$$]: Can't create socket `".$self->{'_ipc_socket'}."': $!") ;
	
	$SIG{'PIPE'} = sub {
		$self->Debug ("SIGPIPE,i dont know WTF") ;
	} ;
	$SIG{'TERM'} = sub {
		$self->DESTROY() ;
		exit 2 ;
	} ;

	undef @queue ;
	$last_time = time() ;
	$send_flag = 0 ;
	while (defined($ipc_sock_wait) or scalar (@ipc_socks)) {
		my $chr ;

		$rin = $win = '' ;
# wait accept
		if (defined ($ipc_sock_wait)) {
			vec($rin,fileno($ipc_sock_wait),1) = 1 ;
		}
		foreach my $ipc_sock (@ipc_socks) {
			if (defined ($ipc_sock->{socket})) {
# reading from Run
				vec($rin,fileno($ipc_sock->{socket}),1) = 1 ;
# writing to Ru
				if ($ipc_sock->{state}==2) {
					vec($win,fileno($ipc_sock->{socket}),1) = 1 ;
				}
			}
		}
		my $nfound = select ($rout=$rin,$wout=$win,undef,1) ;
		if ($nfound<0) {
			if ($! == POSIX::EINTR() and $self->{'catchint'}) {
				next ;
			}
			$self->Error("Circle_Queue[$$]: %s server failed to select(): %s",ref($self),$!) ;
		}

		if (defined ($ipc_sock_wait) and vec($rout,fileno($ipc_sock_wait),1)==1) {
			$self->Debug ("Circle_Queue[$$]: ready for ipc accept") ;
			my $sock = $ipc_sock_wait->accept() ;
			if (!$sock) {
				if ($! == POSIX::EINTR() and $self->{'catchint'}) {
					next ;
				}
				$self->Error("Run[$$]: %s server failed to accept(ipc_sock_wait): %s",ref($self),$ipc_sock_wait->error() || $!) ;
			}
			else {
				my $ref = {} ;
				$ref->{socket} = $sock ;
				$ref->{state} = 1 ;
				$ref->{in_buf} = undef ;
				push (@ipc_socks,$ref) ;
			}
		}
		foreach my $ipc_sock (@ipc_socks) {
# reading
			if (defined ($ipc_sock->{socket}) and vec($rout,fileno($ipc_sock->{socket}),1)==1) {
				my $sock = $ipc_sock->{socket} ;
	
				my $rc = $sock->sysread($chr,$ipc_sock->{state}==2 ? 0 : 1) ;
				if (!defined ($rc)) {
					if ($! == POSIX::EINTR() and $self->{'catchint'}) {
						next ;
					}
					$self->Error("Circle_Queue[$$]: %s server failed to read(ipc_sock): %s",ref($self),$sock->error() || $!) ;
					undef $ipc_sock->{socket} ;
				}
				elsif ($rc==0) {
# EOF
					$self->Debug ("Circle_Queue[$$]: ipc_sock(%d) EOF",$ipc_sock->{in_buf}) ;
					undef $ipc_sock->{socket} ;
					if (defined ($ipc_sock->{in_buf})) {
						$self->Error("Circle_Queue[$$]: %s read(ipc_sock) not a full string `%s', skip it",ref($self),$ipc_sock->{in_buf}) ;
					}
					undef $ipc_sock->{in_buf} ;
				}
				else {
					if ($chr eq chr(10)) {
						push (@queue,$ipc_sock->{in_buf}) ;
						undef ($ipc_sock->{in_buf}) ;
						$ipc_sock->{state} = 2 ;
					}
					else {
						$ipc_sock->{in_buf} .= $chr ;
					}
				}	
				#$self->Debug ("Circle_Queue[$$]: ready for read ipc_sock(%d) {%s}",defined($ipc_sock->{socket})?$ipc_sock->{socket}->fileno():-1,
				#	defined($ipc_sock->{in_buf})?$ipc_sock->{in_buf}:"(undef)") ;
			}
# writing
			if (defined ($ipc_sock->{socket}) and $ipc_sock->{state}==2 and vec($wout,fileno($ipc_sock->{socket}),1)==1) {

				if (!defined ($out_buf)) {
					$out_buf = "+OK\n";
					$out_buf_count = 0 ;
				}
				my $rc = $ipc_sock->{socket}->syswrite ($out_buf,1,$out_buf_count) ;
				if (!defined ($rc)) {
					if ($! == POSIX::EINTR() and $self->{'catchint'}) {
						next ;
					}
					$self->Error("Run[$$]: %s server failed to write ipc_sock(%d): %s",ref($self),$ipc_sock->{socket}->fileno(),$ipc_sock->{socket}->error() || $!) ;
					undef $ipc_sock->{socket} ;
				}
				else {
					$out_buf_count += $rc ;
					if (length($out_buf)<=$out_buf_count) {
						undef $out_buf ;
						$ipc_sock->{state} = 1 ;
					}
				}
				#$self->Debug ("Circle_Queue[$$]: ready for write ipc_sock {%s} %d",defined($out_buf)?$out_buf:"(undef)",$out_buf_count) ;
			}
		}

# checking empty connections
		for (my $i = 0; $i< scalar(@ipc_socks) ; $i++) {
			if (!defined ($ipc_socks[$i]->{socket}) and !defined($ipc_socks[$i]->{in_buf})) {
				splice (@ipc_socks,$i,1) ;
			}
		}

# waiting for send

		if ($last_time+$self->{'_retransmit_sleep_time'}<time()) {
			next if (!scalar(@queue)) ;
			if ((grep {defined ($_->{in_buf})} @ipc_socks) and !$send_flag) {
# small timeout for queue reading
				$last_time += 4 ;		# year! its a magic!
				$send_flag = 1 ;
				next ;
			}

			my (@array) ;
			@array = @queue ;
			$self->ChildFunc('Send_Trap_To_KOS',\@array) ;
			undef @queue ;
			$last_time = time () ;
			$send_flag = 0 ;
		}

	}
	$self->Debug("Circle_Queue[$$]: exit ;(") ;
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

############################################################################################################################
# add locking!!!
############################################################################################################################

my $server = NetProbe::CBR::AVSU::Daemon->new ({
	'pidfile' => sprintf(NETPROBE_PIDFILE,$short_program_name),
	'localpath' => NETPROBE_SOCKETFILE,
	'proto' => 'unix',
#	'user' => 'netprobe',
#	'loop-child' => 1,
#	'loop-timeout' => 20,
	'mode' => 'fork',
	'logfile' => $log_file,
	'listen' => 1,
	'debug' => 1,
	'np_ipc_socket' => NETPROBE_IPC_SOCKETFILE,
	'np_short_program_name' => ${short_program_name},
	'np_lock_file' => NETPROBE_LOCKFILE,
	'np_retransmit_sleep_time' => 5,
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

chdir '/' 			or die "Can't chdir to /: $!" ;
open STDIN,'/dev/null'		or die "Can't read /dev/null: $!" ;
open STDOUT,'>/dev/null'	or die "Can't write to /dev/null: $!" ;
defined (my $pid = fork())	or die "Can't fork: $!" ;
exit if $pid ;
setsid()			or die "Can't start a new session: $!" ;
open STDERR,'>&STDOUT'		or die "Can't dup stdout: $!" ;

$SIG{'TERM'} = sub {
	kill 'TERM',-$$ ;
	exit 2 ;
} ;

$server->Log("start Bind()") ;
$server->ChildFunc("Circle_Queue") ;
$server->Bind() ;

exit 0 ;

__DATA__
Xexe
