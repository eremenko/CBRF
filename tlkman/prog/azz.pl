#!/opt/perl/bin/perl
use lib "/opt/netprobe/lib/perl5/site_perl/5.8.8" ;
use lib "/opt/netprobe/lib/perl5/site_perl/5.8.8/mach" ;

use Digest::SHA ;

my $digest = Digest::SHA->new(256) ;

$digest->add("В чащах юга жил бы цитрус, да но фальшивый экземпляр") ;

print $digest->hexdigest,"\n" ;
