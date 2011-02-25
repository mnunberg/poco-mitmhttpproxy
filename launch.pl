#!/opt/local/bin/perl
use strict;
use warnings;
BEGIN {
    use Cwd qw(abs_path getcwd);
    use File::Basename qw(dirname);
    my $src = abs_path(dirname(__FILE__));
    unshift @INC, $src, $src . "/lib";
    unshift @INC, "/Users/mordy/src/pl/crypt-openssl-cloner/lib";
    unshift @INC, "/Users/mordy/src/pl/pcch/mypcch/lib";
    unshift @INC, getcwd();
    #$ENV{POCO_HTTP_DEBUG} = 1;
    unlink(glob("$src/cert_cache/*"));
}
use POE;
use POE::Component::Server::MITMHTTPProxy;
POE::Component::Server::MITMHTTPProxy->spawn(
    ProxyBindAddress => '0.0.0.0',
    ProxyBindPort => 54321,
    CertificatePath => "cert_cache",
);
POE::Kernel->run();