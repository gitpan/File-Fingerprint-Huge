use strict;
use Test;
BEGIN { plan tests => 2 }
use File::Fingerprint::Huge;

my $fp = File::Fingerprint::Huge->new("t/testdata");

ok($fp);
ok($fp->fp_md5hex eq 'ad60398d3a05beb25e0d80bc787dc947' ? 1 : 0, 1);
