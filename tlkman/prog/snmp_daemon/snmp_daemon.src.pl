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

use lib "@INSTALL_LIBDIR@/site_perl/5.6.1" ;

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
		$self->Debug ("DESTROY[$$]: Delete `%s': $!",$self->{'_ipc_socket'}) ;
		unlink ($self->{'_ipc_socket'}) or
			$self->Error ("DESTROY[$$]: Can't delete `%s': $!",$self->{'_ipc_socket'}) ;
		delete $self->{'_need_delete_ipc_socket'} ;
	}
}

sub Run ($) {
	my ($self) = @_ ;
	my ($sock,$loop_sock_wait,$loop_sock) ;
	my ($rin,$win,$loop_state,@loop_queue,$rout,$wout) ;
	my ($sock_buf,$loop_read_buf,$loop_write_buf,$loop_write_buf_count) ;

	$0 = $self->{'_short_program_name'}. ": reading" ;
	$sock = $self->{'socket'} ;

	$self->Debug("Run[$$]: Making ipc socket") ;
	$loop_sock_wait = IO::Socket::UNIX->new (Type=>SOCK_STREAM,
		Local => $self->{'_ipc_socket'}
	) or
		$self->Fatal("Run[$$]: Can't create socket `".$self->{'_ipc_socket'}."': $!") ;
	$self->{'_need_delete_ipc_socket'} = 1 ;
	$loop_sock_wait->listen(1) or
		$self->Fatal("Run[$$]: Can't create socket `".$self->{'_ipc_socket'}."': $!") ;
	
	$loop_state = 1 ;
	@loop_queue = () ;
	$SIG{'PIPE'} = sub {
		$self->Debug ("SIGPIPE,i dont know WTF") ;
	} ;
	$SIG{'TERM'} = sub {
		$self->DESTROY() ;
		exit 2 ;
	} ;

	while (defined($sock) or scalar(@loop_queue) or $loop_state ==2) {
		my $chr ;

		$rin = $win = '' ;
		if (defined ($sock)) {
			vec($rin,fileno($sock),1) = 1 ;
		}
		vec($rin,fileno($loop_sock_wait),1) = 1 ;
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
				#$self->Debug ("Run[$$]: ready for read sock") ;
	
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
			}
			if (vec($rout,fileno($loop_sock_wait),1)==1) {
				$self->Debug ("Run[$$]: ready for loop accept") ;
				if (defined ($loop_sock)) {
					my $dummy ;
					$self->Debug ("already connect with Loop, skip it") ;
					$dummy = $loop_sock_wait->accept() ;
					if (!$dummy) {
						if ($! == POSIX::EINTR() and $self->{'catchint'}) {
							next ;
						}
					}
					undef $dummy ;
				}
				else {
					$loop_sock = $loop_sock_wait->accept() ;
					if (!$loop_sock) {
						if ($! == POSIX::EINTR() and $self->{'catchint'}) {
							next ;
						}
						$self->Error("Run[$$]: %s server failed to accept(loop_sock_wait): %s",ref($self),$loop_sock_wait->error() || $!) ;
					}
				}
			}
			if (defined ($loop_sock) and vec($rout,fileno($loop_sock),1)==1) {
				$self->Debug ("Run[$$]: ready for read loop sock") ;

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
# EOF
			}
			if (defined ($loop_sock) and $loop_state==1 and vec($wout,fileno($loop_sock),1)==1) {
				#$self->Debug ("Run[$$]: ready for write loop sock") ;

				if (!defined ($loop_write_buf)) {
					$loop_write_buf = shift (@loop_queue) ;
					$loop_write_buf_count = 0 ;
				}
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
					if (length($loop_write_buf)==$loop_write_buf_count) {
						undef $loop_write_buf ;
						$loop_state = 2 ;
					}
				}
			}
		}
	}
}

sub Loop ($) {
	my ($self) = @_ ;
	my ($loop_sock) ;
	my ($result,$last_time) ;
	my ($rin,$rout,$sock_buf,$chr) ;

	$0 = $self->{'_short_program_name'}.": loop" ;
	$self->Debug ("Loop[$$]: start") ;

	$self->Debug ("Loop[$$]: making socket/connect") ;
	$loop_sock = IO::Socket::UNIX->new (Type=>SOCK_STREAM) or
		$self->Fatal("Loop[$$]: Can't create socket `".$self->{'_ipc_socket'}."': $!") ;
	$self->{'_need_delete_ipc_socket'} = 1 ;
	$loop_sock->connect(pack_sockaddr_un($self->{'_ipc_socket'})) or
		$self->Fatal("Loop[$$]: Can't connect socket `".$self->{'_ipc_socket'}."': $!") ;
	
	undef $sock_buf ;
	undef $result ;
	$last_time = time() ;
	while (defined ($loop_sock) or defined ($result)) {

		$rin = '' ;
		if (defined ($loop_sock)) {
			vec ($rin,fileno($loop_sock),1) = 1 ;
		}
		my $nfound = select ($rout=$rin,undef,undef,1) ;
		if ($nfound<0) {
			if ($! == POSIX::EINTR() and $self->{'catchint'}) {
				next ;
			}
			$self->Error("Loop[$$]: %s server failed to select(loop_sock): %s",ref($self),$loop_sock->error() || $!) ;
			undef $loop_sock ;
		}

		if (defined ($loop_sock) and vec($rout,fileno($loop_sock),1)==1) {
			my $rc = $loop_sock->sysread($chr,1) ;
			if (!defined ($rc)) {
				if ($! == POSIX::EINTR() and $self->{'catchint'}) {
					next ;
				}
				$self->Error("Loop[$$]: %s server failed to read(loop_sock): %s",ref($self),$loop_sock->error() || $!) ;
				undef $loop_sock ;
			}
			elsif ($rc==0) {
				$self->Debug("Loop[$$]: close(loop_sock)") ;
				undef $loop_sock ;
			}
			else {
				if ($chr eq chr(10)) {
					$result = $sock_buf ;
					undef $sock_buf ;
				}
				else {
					$sock_buf .= $chr ;
				}
			}
		}
		
		if ($last_time+$self->{'_retransmit_sleep_time'}<time()) {
			next if (defined ($sock_buf)) ;
			next if (!defined ($result)) ;

			$self->ChildFunc('Send_Trap_To_KOS',\$result) ;
			undef $result ;
			$last_time = time () ;
		}
	}

	undef $loop_sock ;
	$self->Debug ("Loop[$$]: finish") ;
}

sub Send_Trap_To_KOS {
	my ($self,$ref) = @_ ;

	$self->Log('info',"Send_KOS[$$]: `".${$ref}."'") ;
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
	'user' => 'netprobe',
	'loop-child' => 1,
	'loop-timeout' => 20,
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
$server->Bind() ;

exit 0 ;

__DATA__
Xexe
