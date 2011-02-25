package POE::Component::Server::MITMHTTPProxy;
use strict;
use warnings;
use POE;
use POE::Session;
use POE::Wheel::SocketFactory;
use POE::Wheel::ReadWrite;
use POE::Component::SSLify qw(Server_SSLify
                            Client_SSLify
                            SSLify_Options
                            SSLify_GetCTX
                            SSLify_GetSocket
                            SSLify_ContextCreate
                            );
                            
use Net::SSLeay;
use POE::Component::Client::HTTP;
use POE::Component::Client::Keepalive;
use POE::Filter::HTTPD;
use POE::Filter::HTTP::Parser;
use POE::Filter::Stream;
use HTTP::Request;
use HTTP::Response;
use HTTP::Headers;
use File::Basename qw(dirname);
use Miner::Logger { level => "info" };
use URI;
use Crypt::OpenSSL::Cloner;
use File::Slurp qw(write_file read_file);
use Digest::MD5 qw(md5_hex);
use Data::Dumper;
use POE::Component::Server::MITMHTTPProxy::Client;

our $STREAMING = 4096;
our $UA_ALIAS = "mitmproxy-ua";
our $PROXY_ALIAS = "mitmproxy-proxy";
#CA object...
our $CA;
our $CACHEPATH;
my %CERTCACHE;
my %PENDING_CLIENT_IDS;

my $CRLF = "\x0D\x0A";



sub spawn {
    my ($cls,%opts) = @_;
    my $ua_alias = delete $opts{UAAlias} || $UA_ALIAS;
    my $ua_already_exists = delete $opts{NewUA};
    my $proxy_alias = delete $opts{ProxyAlias} || $PROXY_ALIAS;
    my $streaming = delete $opts{Streaming} || $STREAMING;
    my $listen_addr = delete $opts{ProxyBindAddress} || "127.0.0.1";
    my $listen_port = delete $opts{ProxyBindPort} || die "Must have bind port!";
    my $ua_bind_addr = delete $opts{UABindAddress};
    my $sslstuff_path = delete $opts{CertificatePath};
    my $ca_cert = delete $opts{ServerCert};
    my $ca_key = delete $opts{ServerKey};
    
    if (keys %opts) {
        die "Unknown options: " . join(',', keys %opts);
    }
    
    POE::Session->create(
        inline_states => {
            _start => sub {
                my ($kernel,$heap) = @_[KERNEL,HEAP];
                $kernel->alias_set($proxy_alias);
                $heap->{server} = POE::Wheel::SocketFactory->new(
                    BindPort => $listen_port,
                    BindAddress => $listen_addr,
                    Reuse => 1,
                    SuccessEvent => "client_connected",
                    FailureEvent => "server_failure",
                );
            },
        },
        package_states => [ __PACKAGE__ . "" => [
           qw/
           client_connected
           server_failure
           client_error
           client_input
           sent_to_client
           got_response
           ssl_got_cert_response
           swap_ua
           /
        ] ],
        heap => {
            ua_alias => $ua_alias,
            streaming => $streaming,
            cs => "POE::Component::Server::MITMHTTPProxy::Client",
            CERT_CLONER => $sslstuff_path,
        },
    );
    
    if (!$ua_already_exists) {
        my $cm = POE::Component::Client::Keepalive->new(
            max_per_host => 32,
            max_open => 512,
            timeout => 3,
        );
        my %ua_opts = (
            Alias => $ua_alias,
            FollowRedirects => 0,
            ConnectionManager => $cm,
            Timeout => 10,
            Streaming => $streaming,
        );
        if ($ua_bind_addr) {
            $ua_opts{BindAddr} = $ua_bind_addr;
        }
        POE::Component::Client::HTTP->spawn(%ua_opts);
    }
    
    if (!$sslstuff_path) {
        if (!($ca_key && $ca_cert)) {
            die "If not using a cloner with a path, you must provide a cert key and pem location";
        }
        SSLify_Options($ca_key, $ca_cert);
    } else {
        #TODO:
        # We can't have more than a single cache path/CA object for the whole
        # module globally. Why this is an issue (i.e. who needs this), I don't
        # know, but should be changeable if this becomes an issue.
        if (!defined $CA) {
            $CACHEPATH = $sslstuff_path;
            $CA = Crypt::OpenSSL::Cloner->new(path => $CACHEPATH);
        }
    }
}

sub swap_ua {
    my ($kernel,$heap,$alias) = @_[KERNEL,HEAP,ARG0];
    my $existing = $heap->{ua_alias};
    $heap->{ua_alias} = $alias;
}

sub genwheel {
    my ($sock,$input_filter,$output_filter) = @_;
    return POE::Wheel::ReadWrite->new(
        Handle => $sock,
        InputEvent => "client_input",
        ErrorEvent => "client_error",
        FlushedEvent => "sent_to_client",
        InputFilter => $input_filter || POE::Filter::HTTP::Parser->new(type => "server"),
        OutputFilter => $output_filter || POE::Filter::Stream->new(),
    );
}

sub client_connected {
    my ($heap,$newsock) = @_[HEAP,ARG0];
    my $wheel = genwheel($newsock);
    my $client = POE::Component::Server::MITMHTTPProxy::Client->new($wheel);
    log_debug("NEW CLIENT: " . $client->ID . "....");
}

my %n_requests;

sub client_input {
    my ($kernel,$heap,$input,$wid) = @_[KERNEL,HEAP,ARG0,ARG1];
    #Get client ID here...
    my $client = $heap->{cs}->client_by_input_wheel_id($wid);
    log_info(sprintf("Client [%d] %s %s", $client->ID, $input->method, $input->uri));
    $client->orig_request($input);
    $input = $client->request($input);
    if ($input->method eq 'CONNECT') {
        my $pending = $client->wheel->get_input_filter->get_pending();
        if ($input->content || $pending) {
            die "GOT PENDING DATA/CONTENT on a CONNECT request";
        }
        if ($heap->{CERT_CLONER}) {
            log_debug("CertOnTheFly enabled.. going to determine what to send..");
            #Send a request for an SSL cert..
            my $host = $input->uri;
            if (exists $CERTCACHE{$host}) {
                ssl_client_send_200($client);
            } else {
                if (!exists $PENDING_CLIENT_IDS{$host}) {
                    ssl_request_cert($kernel,$heap,$host);
                }
                ssl_add_pending_client($client->ID, $host);
            }
        } else {
            ssl_client_send_200($client);
        }
        
        if ($client->is_CONNECTed) {
            die "CONNECTed client sending CONNECT again!";
        }
    }
    else {
        #if ($input->method eq 'POST') {
        #    #Log the POST request, to give us an idea of what's happening..
        #    log_info('\n'.fold($input->as_string, $client->ID . ' POST:'));
        #}
        $input->header("Connection" => "close");
        $input->protocol("HTTP/1.0");
        $input->headers->remove_header("Keep-Alive");
        log_debug("Sending request", $input->uri, "for", $client->ID, "to POCO::C::HTTP");
        $kernel->post($heap->{ua_alias}, "request", "got_response", $input);
        if (++ $n_requests{$client->ID} > 1) {
            log_info("Client", $client->ID, "has used the same connection", $n_requests{$client->ID}, "times");
        }
    }
    log_debug("REQUEST", "\n".$input->as_string);
}

my %content_cache = ();

sub _debug_response {
    my ($client,$request,$response) = @_;
    my $log_meth = ($response->code =~ m/^[23]/) ? \&log_info : \&log_warn;
    my $cksm = md5_hex($response->content);
    $log_meth->(sprintf("Client [%d] %d %s <%s>, content checksum %s",
                        $client->ID,
                        $response->code,
                        $response->message,
                        URI->new($request->uri)->canonical,
                        $cksm));
    if ($response->code !~ m/^[23]/) {
        log_info("\n" . fold($response->as_string,
                             sprintf("%d [%d]", $client->ID, $response->code)));
        log_info("Request was...\n" . fold($request->as_string, $client->ID));
    }
    
    if($content_cache{$cksm}++ > 1) {
        log_debug("\tContent has been delivered $content_cache{$cksm} times");
    }
}

sub got_response {
    #Feel free to mangle stuff here... etc.
    
    my ($heap,$request,$response) = @_[HEAP,ARG0, ARG1];
    $request = $request->[0];
    my $client = $heap->{cs}->client_by_request($request);
    
    if(!$client) {
        log_warn("Couldn't find client!");
        #Now, we try to cancel the request...
        $_[KERNEL]->post($_[SENDER], "cancel", $request);
        return;
    }
    
    my $data;
    ($response,$data) = @$response;
    
    if ($STREAMING) {
        if (!$client->response_header_sent) {
            write_to_wheel($client->wheel, $response);
            _debug_response($client, $request, $response);
            $client->response_header_sent(1);
        }
        if ($data) {
            $client->wheel->put($data);
            return;
        } else {
            $client->wheel->put($CRLF);
            $client->is_done(1);
            return;
        }
    } else {
        write_to_wheel($client->wheel, $response);
        _debug_response($client, $request, $response);
    }
    
    if ($client->is_CONNECTed) {
        if (!can_persist($response)) {
            log_info("Closing CONNECT for client", $client->ID);
            $client->is_done(1);
        } else {
            log_info("Persisting connection for client ", $client->ID);
        }
    } else {
        $client->is_done(1);
    }
}

sub client_error {
    my ($heap,$wheel_id) = @_[HEAP, ARG3];
    my ($operation,$errnum,$errstr) = @_[ARG0,ARG1,ARG2];
    my $client = $heap->{cs}->client_by_input_wheel_id($wheel_id);
    if (!$client) {
        log_err("Errored wheel $wheel_id with no client");
        return;
    }
    if (!$client->is_done) {
        log_err("Client", $client->ID,
                $client->request ? $client->request->uri : "<UNKNOWN>",
                "errored ($errnum [$operation]: $errstr) before being sent a response");
        #Cancel the request?
        if ($client->request) {
            $_[KERNEL]->post($heap->{ua_alias}, "cancel", $client->request);
        }
    }
    $client->close();
}

sub server_failure {
    log_crit("SERVER ERRORED!");
}

sub sent_to_client {
    my ($heap,$wid) = @_[HEAP,ARG0];
    my $client = $heap->{cs}->client_by_input_wheel_id($wid);
    if (!$client) {
        log_err("Client doesn't exist?");
        return;
    }
    log_debug("I/O flushed for client ", $client->ID . " Wheel $wid");
    my $input = $client->request;
    if (!$input) {
        log_err("Client " . $client->ID." wheel $wid got a flushed event without ".
                "ever having sent anything... removing");
        $client->close();
        return;
    }
    if ($input->method eq 'CONNECT') {
        log_debug("Attempting SSLify");
        my $host = $input->uri;
        my $sslified_sock;
        #Ensure all I/O is flushed?
        if ($heap->{CERT_CLONER}) {
            my ($crtfile,$keyfile) = @{$CERTCACHE{$host}}{qw(cert key)};
            if (!($crtfile && $keyfile)) {
                die "Didn't expect to find a host without a cert/key pair";
            }
            eval {
                local $Net::SSLeay::trace = 2;
                local $Net::SSLeay::ssl_version = 10;
                my $ctx = Net::SSLeay::CTX_new();
                #Net::SSLeay::CTX_set_options()
                Net::SSLeay::CTX_use_RSAPrivateKey_file($ctx, $keyfile, &Net::SSLeay::FILETYPE_PEM);
                Net::SSLeay::CTX_use_certificate_file($ctx, $crtfile, &Net::SSLeay::FILETYPE_PEM );
                log_debug("Created context..");
                $sslified_sock = Server_SSLify($client->wheel->get_input_handle, $ctx);
                log_debug("SSLified socket!");
            };
            if ($@) {
                Carp::confess "ERROR: $@";
            }
        } else {
            my $sslified_sock = Server_SSLify(
            $client->wheel->get_input_handle);
        }
        log_debug("Swapping filters...");
        my $input_filter = $client->wheel->get_input_filter();
        my $output_filter = $client->wheel->get_output_filter();
        log_debug("Swap done!");
        $client->wheel(undef);
        my $new_wheel = genwheel($sslified_sock, $input_filter, $output_filter);
        $client->wheel($new_wheel);
        log_debug("SSLified socket for ", $client->ID, "with wheel", $wid);
        $client->is_CONNECTed(1);
        return;
    }
    if ($client->is_done()) {
        $client->close();
    }
}

######### SSL STUFF ########
##Map requested hosts and their pem file/RSA data
#my %CERTCACHE;
#
##Pending client IDs waiting to be SSLified with a given certificate
#my %PENDING_CLIENT_IDS;


sub ssl_client_send_200 {
    my ($client) = @_;
    log_debug("Sending 200 response", $client->ID, $client->request->uri);
    my $response = HTTP::Response->new(200, "Connection established");
    $response->protocol("HTTP/1.1");
    $response->header("Proxy-agent" => "poco-proxy");
    write_to_wheel($client->wheel, $response);
}

sub ssl_context_for_host {
    my $host = shift;
    return if (!exists $CERTCACHE{$host});
    return SSLify_ContextCreate($CERTCACHE{$host}->{cert},
                                $CERTCACHE{$host}->{key});
}

sub ssl_request_cert {
    my ($kernel,$heap,$host) = @_;
    log_debug("Trying to send dummy request for $host");
    my $uri = URI->new();
    $uri->scheme("https");
    $uri->host($host);
    log_debug("Using URI", $uri->as_string());
    my $request = HTTP::Request->new(HEAD => $uri);
    $request->header('X-For-Host' => $host);
    $kernel->post($heap->{ua_alias}, "request", "ssl_got_cert_response", $request);
}

sub ssl_add_pending_client {
    my ($client_id,$host) = @_;
    log_info("Adding pending client", $client_id, "for host $host");
    push @{ $PENDING_CLIENT_IDS{$host} }, $client_id;
}

sub ssl_got_cert_response {
    my ($heap,$kernel,$request,$response) = @_[HEAP,KERNEL,ARG0,ARG1];
    #Assure we have a correct response.. if successful, we connect all the
    #clients.. if not, we disconnect them... maybe let them know with a polite
    #error message?
    #Or.. just check for a valid header.. and we'll know if things went fine..
    my $pem = $response->[0]->header('X-PCCH-Server-Certificate');
    my $host = $request->[0]->header('X-For-Host');
    
    my $client_action = sub {
        my $cb = shift;
        foreach my $id (@{ delete $PENDING_CLIENT_IDS{$host} }) {
            my $client = $heap->{cs}->client_by_id($id);
            if (!$client) {
                log_warn "Client $id doesn't exist?";
                next;
            }
            $cb->($client);
        }
    };
    
    if (!$pem) {
        log_err("SOMETHING HAPPEN!");
        print Dumper($response->[0]);
        my $new_response = HTTP::Response->new(502, "Couldn't fetch spoofed cert");
        $client_action->(
            sub {
                my $client = shift;
                write_to_wheel($client->wheel, $new_response);
                $client->is_done(1);
            }
        );
        return;
    }
    #log_warn($pem);
    my $domain_name = $host;
    $domain_name =~ s/:\d+$//;
    
    my ($cloned,$key) = $CA->clone_cert($pem, $domain_name);
    my $certfile = $CACHEPATH . "/$host.pem";
    my $keyfile = $CACHEPATH . "/$host.key";
    
    write_file($certfile, $cloned);
    write_file($keyfile, $key);
    $CERTCACHE{$host}->{key} = $keyfile;
    $CERTCACHE{$host}->{cert} = $certfile;
    
    #Now send our our 200 connection established messages.. etc.
    $client_action->(\&ssl_client_send_200);
}
sub fold($$) {
    my ($txt,$prefix) = @_;
    $txt =~ s/(.{75}[\s]*)\s+/$1\n   /gm;
    $txt =~ s/^/$prefix\t/gsm;
    return $txt;
}

################### UTILITY ROUTINES ###################

sub can_persist($) {
    my $response = shift;
    return ($response->protocol eq 'HTTP/1.1' &&
            $response->header('Connection') &&
            $response->header('Connection') !~ /close/i
           );
}

sub write_to_wheel($) {
    my ($wheel,$http) = @_;
    my $data = $http->as_string($CRLF);
    $wheel->put($data);
}

if (!caller) {
    __PACKAGE__->spawn();
    POE::Kernel->run();
}
1;

__END__

=head1 NAME

POE::Component::Server::MITMHTTPPRoxy - MITM SSL-sniffing proxy


=head1 SYNOPSIS

    POE::Component::Server::MITMHTTPProxy->spawn(
        ProxyBindAddress => "127.0.0.1",
        ProxyBindPort => "54321",
        UABindAddress => '69.69.69.69'
    );
    #And let it do its stuff...
    
=head1 DESCRIPTION

B<THIS IS A WORK IN PROGRESS. INTERFACES SUBJECT TO CHANGE>

This module acts as a Man-In-The-Middle SSL (and non-SSL) proxy server. This means
that client applications who use this proxy will have their traffic sniffed;
Replies and/or responses can be customized/altered/mangled/whatever.

A lot of the semantics are derived from POE::Component::Client::HTTP (which is
used by this module as well) which I recently worked on. This module requires
use of my own version of the module, available from my github repository.

It is important to note that this proxy keeps its own copy of poco-http to
retrieve the 'real' pages (and blame most of the HTTP parsing on someone else :P)

=head2 FUNCTIONS

=over

Currently there is only a single function, which initiates the proxy server.
It takes a hashref of options, most of them are not required:

=item spawn

Options:

=over

=item ProxyAlias

The POE Session alias for the proxy server

=item UAAlias

The POE session alias for the internal UA

=item Streaming

Determines whether the proxy will deliver streaming content, or buffer the response
in full before it reaches the destination. This is only relevant for pages
fetched directly with the UA. The value is the chunk size to stream. Set to 0
to disable (default)

=item ProxyBindAddress

Address to which the proxy will bind (defaults to 127.0.0.1)

=item ProxyBindPort

Required. Port on which the proxy will listen

=item NewUA

Boolean flag. Set this to false if you would like to provide your own UA session.
The proxy will still need to know its alias L<UAAlias>

=item UABindAddress

Address from which requests made by the UA will originate

=item CertificatePath

This module does some SSL caching and other funky goodies.
You must set this if you want to have on-the-fly ssl certificate generation.
if you do B<NOT> set this, then you must provide a L<ServeCert> and L<ServerKey> option

=item ServertCert

Server certificate (PEM)

=item ServerKey

Server private key (RSA)


=back

=back

=head1 BUGS

Many. If something doesn't work, ask me - do NOT break your head trying to figure
our why it's not working. This is still very experimental.

=head1 LICENSE & COPYRIGHT

Copyright 2011 M. Nunberg

All rights are reserved. POE::Component::Server::MITMHTTPProxy is free software;
you may redistribute it and/or modify it under the same terms as Perl itself.