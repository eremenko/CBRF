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

INSTALL=install
INSTALL_BINDIR=/opt/netprobe/bin
INSTALL_LIBDIR=/opt/netprobe/lib
INSTALL_LOGSDIR=/opt/netprobe/logs
INSTALL_LOCKDIR=/opt/netprobe/lock
INSTALL_OWNER=$(shell id -run)

SED=/bin/sed
