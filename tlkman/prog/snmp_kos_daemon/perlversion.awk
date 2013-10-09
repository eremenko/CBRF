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

BEGIN {
	P_VER=-1
	P_REV=-1
	P_SUB=-1
}

/PERL_VERSION/ {
	P_VER=$2
}

/PERL_REVISION/ {
	P_REV=$2
}

/PERL_SUBVERSION/ {
	P_SUB=$2
}

END {
	print P_REV " " P_VER " " P_SUB
}
