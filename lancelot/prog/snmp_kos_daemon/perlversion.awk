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
