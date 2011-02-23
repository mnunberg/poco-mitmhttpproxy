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


our $PREFERRED_ALG = "sha1";
our $CA_BASENAME = "CA";

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
    PRIVKEY_OBJ
);

sub load_ca {
    my ($self) = @_;
    my $path = $self->{PATH};
    my ($privkey_obj,$privkey_string,$ca_obj,$pem);
    eval {
        $privkey_string = read_file($path . "/$CA_BASENAME.key");
        $pem = read_file($path."/$CA_BASENAME.pem");
    };
    if ($@) {
        warn "$@";
        return;
    }
    
    $privkey_obj = Crypt::OpenSSL::CA::PrivateKey->parse($privkey_string);
    $ca_obj = Crypt::OpenSSL::CA::X509->parse($pem);
    
    return unless ($privkey_obj && $ca_obj);
    return [$ca_obj,$privkey_obj];
}

sub _gen_new_ca {
    my ($self) = @_;
    my $rsa = Crypt::OpenSSL::RSA->generate_key(1024);
    my $privkey = Crypt::OpenSSL::CA::PrivateKey->parse(
        $rsa->get_private_key_string
    );
    my $ca = Crypt::OpenSSL::CA::X509->new($privkey->get_public_key);
    my $dn = Crypt::OpenSSL::CA::X509_NAME->new(
        C => 'GB', OU => 'Rocestershire', CN => 'localhost'
    );
    my $keyid = $privkey->get_public_key->get_openssl_keyid();
    $ca->set_serial("0x1");
    $ca->set_notBefore("20080204101500Z");
    $ca->set_notAfter("20220204101500Z");
    $ca->set_subject_DN($dn);
    $ca->set_issuer_DN($dn);
    $ca->set_extension("subjectKeyIdentifier", $keyid);
    $ca->set_extension("authorityKeyIdentifier", {keyid => $keyid});
    $ca->set_extension("basicConstraints", "CA:TRUE", -critical => 1);
    
    my $crt_text = $ca->sign($privkey, "sha1");
    return [$ca,$privkey,$crt_text,$rsa->get_private_key_string];
}

sub new {
    my ($cls,%opts) = @_;
    my $self = {};
    bless ($self, $cls);
    lock_keys(%$self, @FIELDS);
    my $path = delete $opts{path};
    $path ||= "CERTCACHE";
    make_path($path);
    $self->{PATH} = $path;
    
    my ($ca_obj,$privkey_obj);
    my $res = $self->load_ca();
    if ($res) {
        ($ca_obj,$privkey_obj) = @$res;
    } else {
        my ($pem,$keytxt);
        ($ca_obj,$privkey_obj,$pem,$keytxt) = @{ $self->_gen_new_ca() };
        write_file($path . "/$CA_BASENAME.pem", $pem);
        write_file($path . "/$CA_BASENAME.key", $keytxt);
    }
    $self->{CA_OBJ} = $ca_obj;
    $self->{PRIVKEY_OBJ} = $privkey_obj;
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
    $new_cert->set_notAfter("20220204114600Z");
    $new_cert->set_extension("authorityKeyIdentifier", { keyid => $self->{CA_OBJ}->get_subject_keyid });
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
            my $der = $ext->{extnValue};
            my $parser = $PARSERS{$extname};
            my $decoded = $parser->decode($der);
            if ($extname eq 'SubjectKeyIdentifier') {
                $new_cert->set_extension(
                    "subjectKeyIdentifier", unpack('H*', $decoded));
            } elsif ($extname eq 'SubjectAltName') {                
                #ASN:
                #
                #GeneralName ::= CHOICE {
                #otherName                       [0]     AnotherName,
                #rfc822Name                      [1]     IA5String,
                #dNSName                         [2]     IA5String,
                #x400Address                     [3]     ANY, --ORAddress,
                #directoryName                   [4]     Name,
                #ediPartyName                    [5]     EDIPartyName,
                #uniformResourceIdentifier       [6]     IA5String,
                #iPAddress                       [7]     OCTET STRING,
                #registeredID                    [8]     OBJECT IDENTIFIER }

                my %asn2openssl = (
                    otherName                   => "otherName",
                    rfc822name                  => "email",
                    dNSName                     => "DNS",
                    x400Address                 => "dirName",
                    #ediPartyName               => "what's this?",
                    directoryName               => "dirName",
                    uniformResourceIdentifier   => "URI",
                    iPAddress                   => "IP",
                    registeredID                => "RID",
                );
                my @altnames;
                my $altname = "";
                foreach my $h (@$decoded) {
                    my ($k,$v) = (%$h);
                    my $new_k = $asn2openssl{$k};
                    if (!$new_k) {
                        warn "Found ASN.1 X509 field $k which doesn't have an OpenSSL mapping";
                        next;
                    }
                    $k = $new_k;
                    push @altnames, "$k:$v";
                }
                $altname = join(",", @altnames);
                $new_cert->set_extension("subjectAltName", $altname);
            }
        }        
    }
    my $new_pem = $new_cert->sign($self->{PRIVKEY_OBJ}, "sha1");
    return ($new_pem, $keystr);
}

if (!caller) {
my $TEST_CERT = <<PEM;
-----BEGIN CERTIFICATE-----
MIIFVTCCBD2gAwIBAgIHBGX+dPs18DANBgkqhkiG9w0BAQUFADCByjELMAkGA1UE
BhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAY
BgNVBAoTEUdvRGFkZHkuY29tLCBJbmMuMTMwMQYDVQQLEypodHRwOi8vY2VydGlm
aWNhdGVzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkxMDAuBgNVBAMTJ0dvIERhZGR5
IFNlY3VyZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTERMA8GA1UEBRMIMDc5Njky
ODcwHhcNMDkxMjExMDUwMjM2WhcNMTQxMjExMDUwMjM2WjBRMRUwEwYDVQQKEwwq
LmdpdGh1Yi5jb20xITAfBgNVBAsTGERvbWFpbiBDb250cm9sIFZhbGlkYXRlZDEV
MBMGA1UEAxMMKi5naXRodWIuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA7dOJw11wcgnzM08acnTZtlqVULtoYZ/3+x8Z4doEMa8VfBp/+XOvHeVD
K1YJAEVpSujEW9/Cd1JRGVvRK9k5ZTagMhkcQXP7MrI9n5jsglsLN2Q5LLcQg3LN
8OokS/rZlC7DhRU5qTr2iNr0J4mmlU+EojdOfCV4OsmDbQIXlXh9R6hVg+4TyBka
szzxX/47AuGF+xFmqwldn0xD8MckXilyKM7UdWhPJHIprjko/N+NT02Dc3QMbxGb
p91i3v/i6xfm/wy/wC0xO9ZZovLdh0pIe20zERRNNJ8yOPbIGZ3xtj3FRu9RC4rG
M+1IYcQdFxu9fLZn6TnPpVKACvTqzQIDAQABo4IBtjCCAbIwDwYDVR0TAQH/BAUw
AwEBADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDgYDVR0PAQH/BAQD
AgWgMDMGA1UdHwQsMCowKKAmoCSGImh0dHA6Ly9jcmwuZ29kYWRkeS5jb20vZ2Rz
MS0xMS5jcmwwUwYDVR0gBEwwSjBIBgtghkgBhv1tAQcXATA5MDcGCCsGAQUFBwIB
FitodHRwOi8vY2VydGlmaWNhdGVzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMIGA
BggrBgEFBQcBAQR0MHIwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmdvZGFkZHku
Y29tLzBKBggrBgEFBQcwAoY+aHR0cDovL2NlcnRpZmljYXRlcy5nb2RhZGR5LmNv
bS9yZXBvc2l0b3J5L2dkX2ludGVybWVkaWF0ZS5jcnQwHwYDVR0jBBgwFoAU/axh
MpNsRdbi7oVfmrrndplozOcwIwYDVR0RBBwwGoIMKi5naXRodWIuY29tggpnaXRo
dWIuY29tMB0GA1UdDgQWBBSH0Y8ZbuSHb1OMd5EHUN+jv1VHIDANBgkqhkiG9w0B
AQUFAAOCAQEAwIe/Bbuk1/r38aqb5wlXjoW6tAmLpzLRkKorDOcDUJLtN6a9XqAk
cgMai7NCI1YV+A4IjEENj53mV2xWLpniqLDHI5y2NbQuL2deu1jQSSNz7xE/nZCk
WGt8OEtm6YI2bUsq5EXy078avRbigBko1bqtFuG0s5+nFrKCjhQVIk+GX7cwiyr4
XJ49FxETvePrxNYr7x7n/Jju59KXTw3juPET+bAwNlRXmScjrMylMNUMr3sFcyLz
DciaVnnextu6+L0w1+5KNVbMKndRwgg/cRldBL4AgmtouTC3mlDGGG3U6eV75cdH
D03DXDfrYYjxmWjTRdO2GdbYnt1ToEgxyA==
-----END CERTIFICATE-----
PEM
    use Carp qw(confess);
    $SIG{__DIE__} = sub { confess $_[0] };
    
    my $CA = __PACKAGE__->new();
    my ($pem, $privkey) = $CA->clone_cert($TEST_CERT);
    write_file($CA->{PATH} . "/dummy.pem", \$pem);
    write_file($CA->{PATH} . "/dummy.key", \$privkey);
}

1;