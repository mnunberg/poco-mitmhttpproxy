#!/usr/bin/perl
use strict;
use warnings;
use POE;

use POE::Component::Server::TCP;
use POE::Component::Client::TCP;

use POE::Component::Client::HTTP;

use POE::Filter::Stream;
use POE::Filter::HTTP::Parser;

use HTTP::Request;
use HTTP::Response;
use HTTP::Headers;

use POE::Filter::SSL;

use LWP::UserAgent::POE;

use Data::Dumper;

use Miner::Logger {level => "debug" };

use Carp qw(confess cluck);
$SIG{__DIE__} = sub { confess @_ };

my $crtfile = "../server.crt";
my $keyfile = "../server.key";

POE::Component::Server::TCP->new(
    Alias => "mitm_proxy",
    Port => 8585,
    ClientFilter => 'POE::Filter::Stream',
    ClientInput => \&handle_input,
    ClientConnected => \&register_client,
    InlineStates => {
        got_response => \&handle_response,
    },
);

POE::Component::Client::HTTP->spawn(
    Alias => "ua",
    FollowRedirects => 0,
);

POE::Kernel->run();

sub handle_input {
    my ($kernel,$heap,$data) = @_[KERNEL,HEAP,ARG0];
    my $requests = $heap->{request_parser}->get([$data]);
    log_debug($data);
    my $r = shift @$requests;
    if(!$r) {
        log_warn ("Got incomplete data: $data");
        return;
    }
    
    if (!$heap->{orig_uri}) {
        $heap->{orig_uri} = $r->uri;
    }
    
    if ($r->method eq 'CONNECT') {
        $heap->{orig_uri} = "https://" . $heap->{orig_uri};
        _handle_CONNECT($heap->{client});
        return;
    }
    log_debug "Requesting page from UA";
    if(!$r->uri || $r->uri !~ m/^http/) {
        my $orig_uri = $heap->{orig_uri};
        my $new_uri = $r->uri;
        $orig_uri =~ s/:443//g;
        if ($orig_uri !~ m/http/) {
            $orig_uri = "https://$orig_uri";
        }
        $orig_uri .= $new_uri;
        $r->uri($orig_uri);
        log_debug "URI changed to " . $r->uri;
    }
    log_debug("REQUEST STRING: ", $r->as_string);
    $kernel->post(
        "ua", "request", "got_response", $r);
}

sub register_client {
    my ($kernel,$heap) = @_[KERNEL,HEAP];
    $heap->{request_parser} = POE::Filter::HTTP::Parser->new(type => 'request');
    log_debug "Registered client";
}

sub handle_response {
    my ($kernel,$heap,$request,$response) = @_[KERNEL,HEAP,ARG0,ARG1];    
    $request = $request->[0];
    $response = $response->[0];
    log_debug("Content length is ", length($response->content));
    $heap->{client}->put($response->as_string());
    $kernel->yield("shutdown");
    log_debug("Disconnecting...");
}

sub _handle_CONNECT {
    my $client = shift;
    $client->put("HTTP/1.1 200 Connection established\r\n\r\n");
    $client->set_filter(POE::Filter::SSL->new(
        crt => $crtfile,
        key => $keyfile,
    ));
}