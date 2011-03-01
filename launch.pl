#!/usr/bin/env perl
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
    #unlink(glob("$src/cert_cache/*"));
}
use POE;
use POE::Session;
use POE::Component::Server::MITMHTTPProxy;
use POE::Component::Server::MITMHTTPProxy::Constants qw(:callback_retvals);
use HTTP::Response;
use Log::Fu { level => "info" };
use bytes;


my %REQUESTS;
my $SESSION_ALIAS = "user-mitm-session";

sub handle_request {
    my $request = $_[ARG0];
    log_info("(THROWBACK): Got request ".$request->uri);
    #Forward the response back...
    $_[KERNEL]->post($_[SENDER], "request_upstream", $request);
}

sub handle_error {
    my ($request, $errmsg) = @_;
    log_err("Got error for uri ".$request->uri." $errmsg");
}

sub handle_response_chunk {
    my ($request,$response,$extra) = @_;
    my $convert = sub {
        my $d = shift;
        return if !$d;
        if ($d =~ m/^[[:print:]]+$/) {
            log_info("Got text.. converting..");
            return uc($d);
        }
        return $d;
    };
    my $response_aref = [$response];
    if ($extra->{streaming}) {
        my $data = $extra->{data};
        $data = $convert->($data);
        push @$response_aref, (1, $data);
    } else {
        $response->content($convert->($response->content));
    }
    return [CB_HAVE_RESPONSE, $response_aref];
}

sub init_proxy {
    $_[KERNEL]->alias_set($SESSION_ALIAS);
    POE::Component::Server::MITMHTTPProxy->spawn(
        ProxyBindAddress => '0.0.0.0',
        ProxyBindPort => 54321,
        CertificatePath => "cert_cache",
        UserEvents => {
            Request => {
                cb => "handle_request",
                sync => 0,
            },
            UpstreamResponse => {
                cb => \&handle_response_chunk,
                sync => 1
            },
            ProxyError => {
                cb => \&handle_error,
                sync => 1,
            }
        },
        UserSession => $SESSION_ALIAS
    );
}
POE::Session->create (
    inline_states => {
        _start => \&init_proxy
    },
    package_states => [__PACKAGE__ ."" => [
        qw(handle_request handle_error handle_response_chunk)
    ]]
);

POE::Kernel->run();