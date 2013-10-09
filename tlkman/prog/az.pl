#!/opt/perl/bin/perl
use lib "/opt/netprobe/lib/perl5/site_perl/5.8.8" ;
use lib "/opt/netprobe/lib/perl5/site_perl/5.8.8/mach" ;

use Crypt::CBC ;

         $cipher = Crypt::CBC->new( -key    => 'my secret key2',
                                    -cipher => 'Blowfish'
                                   );

         $cipher->start('decrypting');
         open(F,"./az1");
         while (read(F,$buffer,1024)) {
             print $cipher->crypt($buffer);
         }
         print $cipher->finish;


exit 0 ;
__DATA__

use Crypt::CBC ;
use Crypt::Blowfish ;

              my $key = pack("H16", "0123456789ABCDEF");  # min. 8 bytes
               my $cipher = new Crypt::Blowfish $key;
               my $ciphertext = $cipher->encrypt("plaintexkolinalekolavnek");  # SEE NOTES
               print unpack("H16", $ciphertext), "\n";

протокол:

< OK SECRET_KEY_HEX
> STAT ENCRPYTED_PHRASE_WITH_SECRET_KEY SECRET_KEY_HEX

