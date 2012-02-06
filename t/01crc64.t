use strict;
use Test;
BEGIN { plan tests => 2 }
use File::Fingerprint::Huge;

my $fp = File::Fingerprint::Huge->new("t/testdata");

ok($fp);
ok($fp->fp_crc64 eq '16850729936921025068' ? 1 : 0, 1);
