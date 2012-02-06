package File::Fingerprint::Huge;

use Math::Random::MT qw[ rand srand ];
use Digest::CRC qw[ crc64 ];
use strict;
use vars qw ($VERSION);

$VERSION = $1 if('$Id: Huge.pm,v 1.2 2012/02/06 20:12:58 cfaber Exp $' =~ /,v ([\d.]+) /);

=head1 NAME

Net::Whois::Proxy - an easy to use recursive whois client library

=head1 DESCRIPTION

The File::Fingerprint::Huge library is designed to quickly finger print very large files which a very high probability of uniqueness. However absolute uniqueness cannot be guaranteed.

=head1 SYNOPSIS

 use File::Fingerprint::Huge;
 my $fp = File::Fingerprint::Huge->new("/largefile");

 my $crc64 = $fp->fp_crc64;

 print $crc64 . "\n";

 exit;


Also see the whois.pl example script provided with the library distrobution

=head1 METHODS

=cut

=head2 new(file)

Create a new File::Fingerprint::Huge object based on B<file> which is a large file to scan.

=cut

sub new {
 my ($class, $file) = @_;

 return bless { file => $file }, $class;
}

=head2 file(filename)

Change the file to checksum by assigning B<filename> as the new file.

=cut

sub file {
	my ($self, $file) = @_;
	$self->{file} = $file;
	return 1;
}

=head2 fp_crc64()

Return a CRC64 number based on large file scan

=cut

sub fp_crc64 {
	my ($self) = @_;
	my $size = (stat($self->{file}))[7];

	srand($size);

	if(open(my $fh, "<", $self->{file})){
		## assuming CRC-64
		my $chunks = int( $size / 8 ) - 1;

		## Added sort per RichardK's suggestion below.
		my @posns = sort { $a <=> $b } map 8 * int( rand $chunks ), 1 .. 100;

		my $sample = join '', map { seek $fh, $_, 0; read( $fh, my $chunk, 8 ); $chunk } @posns; 
		close $fh;

		return Digest::CRC::crc64( $sample );
	} else {
		return;
	}
}

=head2 fp_md5hex()

Return the file has md5 base64 checksum (32 char)

=cut

sub fp_md5hex {
	my ($self) = @_;
	require Digest::MD5;

	return Digest::MD5::md5_hex( $self->fp_crc64 );
}


1;

__END__

=head1 AUTHOR

Colin Faber <cfaber@gmail.com>

Based on work from http://perlmonks.org/?node_id=951861

=head1 LICENSE

(C) Colin Faber All rights reserved.  This license may be used under the terms of Perl it self.
