#!/usr/bin/perl
use strict;
use warnings;
use Convert::ASN1;
use File::Slurp qw(read_file);
use Data::Dumper;
use Crypt::X509;

my $blob = read_file("BASE.der");
my $asn_def = read_file("working.asn1");
my $asn = Convert::ASN1->new();
$asn->prepare($asn_def) or die "Couldn't prepare ASN: " . $asn->error;
my ($parser,$out);
$parser = $asn->find("Certificate");
my %clone_exts = map { $_, $asn->find($_) } qw(
    SubjectKeyIdentifier 
    BasicConstraints
    KeyUsage
    CertificatePolicies
    SubjectAltName
);

my %oid_2_ext = (
    '2.5.29.14' => "SubjectKeyIdentifier",
    '2.5.29.17' => "SubjectAltName",
    '2.5.29.37' => "KeyUsage",
    '2.5.29.32' => 'CertificatePolicies',
    '2.5.29.19' => "BasicConstraints",
    
);

$out = $asn->find("Certificate")->decode($blob)->{tbsCertificate}{extensions};
foreach my $extn (@$out) {
    my $oid = $extn->{extnID};
    print "found oid $oid...";
    my $extname = $oid_2_ext{$oid};
    if (defined $extname) {
        print "=> $extname";
        print Dumper($clone_exts{$extname}->decode($extn->{extnValue}));
    } else {
        print "Unknown/Unneeded";
    }
    print "\n";
}