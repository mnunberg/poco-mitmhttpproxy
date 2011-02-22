package CertOnTheFly::CA;
use strict;
use warnings;
use Crypt::OpenSSL::CA;
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::X509;
use File::Slurp qw(read_file write_file);
use File::Path qw(make_path);
use Hash::Util qw(lock_keys);
use Data::Dumper;
use Time::HiRes;
use MIME::Base64 qw(decode_base64);
use Convert::ASN1;

my $asn_def = read_file("working.asn1") or die "Couldn't load ASN definitions";
my $ASN = Convert::ASN1->new();
$ASN->prepare($asn_def) or die "GRRR";

my %PARSERS = map { $_, $ASN->find($_) } qw(
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

my @FIELDS = qw(
    PATH
    CA_OBJ
    PRIVKEY_STRING
    PRIVKEY_OBJ
    KEYID
);

sub _gen_new_ca {
    my $self = shift;
    my $rsa = Crypt::OpenSSL::RSA->generate_key(1024);
    my $privkey = Crypt::OpenSSL::CA::PrivateKey->parse(
        $rsa->get_private_key_string
    );
    my $ca = Crypt::OpenSSL::CA::X509->new($privkey->get_public_key);
    my $dn = Crypt::OpenSSL::CA::X509_NAME->new(
        C => 'GB', OU => 'Rocestershire', CN => 'MOO!'
    );
    my $keyid = $privkey->get_public_key->get_openssl_keyid();
    $ca->set_serial("0x1");
    $ca->set_notBefore("20080204101500Z");
    $ca->set_notAfter("20220204101500Z");
    $ca->set_subject_DN($dn);
    $ca->set_issuer_DN($dn);
    $ca->set_extension("subjectKeyIdentifier", $keyid);
    $ca->set_extension("authorityKeyIdentifier", {
        keyid => $keyid,
        issuer => $dn,
        serial => '0x' . time()
    });
    $ca->set_extension("basicConstraints", "CA:TRUE", -critical => 1);

    $self->{CA_OBJ} = $ca;
    $self->{PRIVKEY_OBJ} = $privkey;
    $self->{KEYID} = $keyid;
    $self->{PRIVKEY_STRING} = $rsa->get_private_key_string;
}

sub new {
    my ($cls,%opts) = @_;
    my $self = {};
    bless ($self, $cls);
    lock_keys(%$self, @FIELDS);
    $self->_gen_new_ca();
    return $self;
}


sub clone_cert {
    my ($self,$pem) = @_;
    my $keystr = Crypt::OpenSSL::RSA->generate_key(1024)->get_private_key_string();
    my $privkey = Crypt::OpenSSL::CA::PrivateKey->parse($keystr);
    my $new_cert = Crypt::OpenSSL::CA::X509->new($privkey->get_public_key);
            
    $new_cert->set_subject_DN(Crypt::OpenSSL::CA::X509->parse($pem)->get_subject_DN);
    $new_cert->set_issuer_DN($self->{CA_OBJ}->get_issuer_DN);
    $new_cert->set_notBefore("20080204114600Z");
    $new_cert->set_notAfter("21060108000000Z");
    $new_cert->set_extension("authorityKeyIdentifier", { keyid => $self->{KEYID} },
                             -critical => 1);
    my $serial = Time::HiRes::time;
    $serial =~ s/\.//;
    $serial = "0x$serial";
    $new_cert->set_serial($serial);
    my %extracted;
    {
        my $blob = $pem;
        $blob =~ s/-----(BEGIN|END)\sCERTIFICATE-----//msg;
        $blob = decode_base64($blob);
        my $rootparse = $ASN->find("Certificate");
        my $extensions = $rootparse->decode($blob);
        $extensions = $extensions->{tbsCertificate}->{extensions};
        foreach my $ext (@$extensions) {
            my $oid = $ext->{extnID};
            my $extname = $oid_2_ext{$oid};
            next if !$extname;
            #print $extname . "\n";
            my $der = $ext->{extnValue};
            my $parser = $PARSERS{$extname};
            my $decoded = $parser->decode($der);
            if ($extname eq 'SubjectKeyIdentifier') {
                $new_cert->set_extension(
                    "subjectKeyIdentifier", unpack('H*', $decoded));
            } elsif ($extname eq 'CertificatePolicies') {                
            }
            #print $extname . ' => ' . Dumper($decoded);
        }
        #print Dumper($extensions);
        
        
    }
    #foreach my $extname qw(subjectKeyIdentifier subjectAltName) {
    #    my $v = $extract_data->($extname);
    #    next if (!$v);
    #    $new_cert->set_extension($extname, $v);
    #}
    #my @clone_exts = qw(
    #    subjectKeyIdentifier
    #    basicConstraints
    #    keyUsage
    #    certificatePolicies
    #    subjectAltName
    #);
    #foreach my $needed_ext (@clone_exts) {
    #    my $val = $extract_data->($needed_ext);
    #    next if !$val;
    #    print "$needed_ext => $val\n";
    #    $new_cert->set_extension($needed_ext, $val);
    #}
    #print $orig_cert->dump();
    #Clone some fields...
   # Conforming CAs MUST support key identifiers (Sections 4.2.1.1 and
   #4.2.1.2), basic constraints (Section 4.2.1.9), key usage (Section
   #4.2.1.3), and certificate policies (Section 4.2.1.4) extensions.  If
   #the CA issues certificates with an empty sequence for the subject
   #field, the CA MUST support the subject alternative name extension
   #(Section 4.2.1.6).
    #my $blob = $pem;
    #$blob =~ s/^-----(BEGIN|END) CERTIFICATE-----$//msg;
    #$blob = decode_base64($blob);
    my $new_pem = $new_cert->sign($self->{PRIVKEY_OBJ}, "sha1");
    #print $new_cert->dump;
    return ($new_pem, $keystr);
}

my $TEST_CERT = <<PEM;
-----BEGIN CERTIFICATE-----
MIIGVDCCBTygAwIBAgIQE5DIpL3AtHUVIoRkUc4+AzANBgkqhkiG9w0BAQUFADCB
ujELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL
ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTswOQYDVQQLEzJUZXJtcyBvZiB1c2Ug
YXQgaHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL3JwYSAoYykwNjE0MDIGA1UEAxMr
VmVyaVNpZ24gQ2xhc3MgMyBFeHRlbmRlZCBWYWxpZGF0aW9uIFNTTCBDQTAeFw0x
MDAyMjQwMDAwMDBaFw0xMTAzMDYyMzU5NTlaMIIBGDETMBEGCysGAQQBgjc8AgED
EwJVUzEZMBcGCysGAQQBgjc8AgECEwhEZWxhd2FyZTEbMBkGA1UEDxMSVjEuMCwg
Q2xhdXNlIDUuKGIpMRAwDgYDVQQFEwcyOTI3NDQyMQswCQYDVQQGEwJVUzEOMAwG
A1UEERQFNzUyMDIxDjAMBgNVBAgTBVRleGFzMQ8wDQYDVQQHFAZEYWxsYXMxGTAX
BgNVBAkUEDEyMDEgTWFpbiBTdHJlZXQxJDAiBgNVBAoUG0Jhbmsgb2YgQW1lcmlj
YSBDb3Jwb3JhdGlvbjEYMBYGA1UECxQPV2ViU3BoZXJlIEVjb21tMR4wHAYDVQQD
FBV3d3cuYmFua29mYW1lcmljYS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQD7+FybC5+8D9I3LiXmuQ50wN1OPBaGGDmQE0QhhDe57YSj/3XmNYP2
plZolQeFcVCdtUNWtkAMdXgglHvZtB4MITk0v+3dLXiBeFkiK1CuGSpxUrd/2Rpu
CWW4/sT6RTUftYa5Z1L2olv9wYOmAMjtGsEJxP/R96pqFhrlyOO5nxPshnmP/k/5
4DftwAKs/xgg4c10JnYJ1C8ZdGQN6v9XTC0Kpl3vjRmNgyEqvGrykh42AdEQnosN
VHUwklM7ZBxiXqlm8iAGdNRGFwLH/PeL+FKllPiGpOmNtN3m58qEWG8nBZTL9Zyd
F1AfZpEbRHchEGkULZo3q+rEhfXAHgVnAgMBAAGjggHzMIIB7zAJBgNVHRMEAjAA
MB0GA1UdDgQWBBT/W/tRlK8jFEO06/ol82+pKYOFCTALBgNVHQ8EBAMCBaAwQgYD
VR0fBDswOTA3oDWgM4YxaHR0cDovL0VWU2VjdXJlLWNybC52ZXJpc2lnbi5jb20v
RVZTZWN1cmUyMDA2LmNybDBEBgNVHSAEPTA7MDkGC2CGSAGG+EUBBxcGMCowKAYI
KwYBBQUHAgEWHGh0dHBzOi8vd3d3LnZlcmlzaWduLmNvbS9ycGEwHQYDVR0lBBYw
FAYIKwYBBQUHAwEGCCsGAQUFBwMCMB8GA1UdIwQYMBaAFPyKULqeuSVae1WFT5UA
Y4/pWGtDMHwGCCsGAQUFBwEBBHAwbjAtBggrBgEFBQcwAYYhaHR0cDovL0VWU2Vj
dXJlLW9jc3AudmVyaXNpZ24uY29tMD0GCCsGAQUFBzAChjFodHRwOi8vRVZTZWN1
cmUtYWlhLnZlcmlzaWduLmNvbS9FVlNlY3VyZTIwMDYuY2VyMG4GCCsGAQUFBwEM
BGIwYKFeoFwwWjBYMFYWCWltYWdlL2dpZjAhMB8wBwYFKw4DAhoEFEtruSiWBgy7
0FI4mymsSweLIQUYMCYWJGh0dHA6Ly9sb2dvLnZlcmlzaWduLmNvbS92c2xvZ28x
LmdpZjANBgkqhkiG9w0BAQUFAAOCAQEAQzYqg/4xjyRuyGoXl8JnOhR7EEkRQIVT
9rz6katbdtqC8a0uY6bXru4a7+XfdNMasgYVKQgjTLvLWO1wBxUZirup7iElBrcR
pdt6rMAdDec0I5YuoKy6LrU0B9in5VPKr45km3fz/L86fDIAfHQe+pbZb9kVCmuB
tGyN/+VklcghWYwwA7+DrvXmsQLDgiJYZ8iWGlPOJzTeEWFaV5VcIFnZV1xfCm0Y
MHqeOiVDgHwKO8agh66U9bzNlZvycfl7otagIXlb5VYkGpyjv8dniN1pWLY2TA5o
KML6ddxExOehMwJdnEYX5XZSmDytdfOUKMkcSP0vQIJYmsi+o44beQ==
-----END CERTIFICATE-----
PEM
if (!caller) {
    use Carp qw(confess);
    $SIG{__DIE__} = sub { confess $_[0] };
    
    my $CA = __PACKAGE__->new();
    my ($pem, $privkey) = $CA->clone_cert($TEST_CERT);
    write_file("dummy.pem", \$pem);
    write_file("dummy.key", \$privkey);
}

1;