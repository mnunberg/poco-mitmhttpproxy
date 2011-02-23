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

use POE::Filter::Stackable;
use POE::Filter::HTTPD;
use POE::Filter::HTTP::Parser;
use POE::Filter::Stream;

use HTTP::Request;
use HTTP::Response;
use HTTP::Headers;
use File::Basename qw(dirname);
use Miner::Logger { level => "info" };

use Net::SSLeay;
use URI;
use CertOnTheFly;
use File::Slurp qw(write_file read_file);

use Digest::MD5 qw(md5_hex);

use Data::Dumper;

use POE::Component::Server::MITMHTTPProxy::Client;

my $CERT_ON_THE_FLY = 1;

my $CRLF = "\x0D\x0A";

sub spawn {
    POE::Session->create(
        inline_states => {
            _start => \&proxy_init
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
           /
        ] ],
    );
    
    my $cm = POE::Component::Client::Keepalive->new(
        max_per_host => 32,
        max_open => 512,
        timeout => 3,
    );
    POE::Component::Client::HTTP->spawn(
        Alias => "__ua",
        FollowRedirects => 0,
        ConnectionManager => $cm,
        Timeout => 10,
    );
    
    SSLify_Options("Proxy/server.key","Proxy/server.crt");
}

sub proxy_init {
    my ($kernel,$heap) = @_[KERNEL,HEAP];
    $kernel->alias_set("__PROXY");
    $heap->{server} = POE::Wheel::SocketFactory->new(
        BindPort => 54321,
        Reuse => 1,
        SuccessEvent => "client_connected",
        FailureEvent => "server_failure",
    );
    $heap->{cs} = "POE::Component::Server::MITMHTTPProxy::Client";
}

sub genwheel {
    my ($sock,$input_filter,$output_filter) = @_;
    return POE::Wheel::ReadWrite->new(
        Handle => $sock,
        InputEvent => "client_input",
        ErrorEvent => "client_error",
        FlushedEvent => "sent_to_client",
        InputFilter => $input_filter || POE::Filter::HTTP::Parser->new(type => "server"),
        OutputFilter => $output_filter || POE::Filter::HTTPD->new(),
    );
}

sub client_connected {
    my ($heap,$newsock) = @_[HEAP,ARG0];
    my $wheel = genwheel($newsock);
    my $client = POE::Component::Server::MITMHTTPProxy::Client->new($wheel);
}

my %CERTCACHE;
my %PENDING_CLIENT_IDS;

sub client_input {
    my ($kernel,$heap,$input,$wid) = @_[KERNEL,HEAP,ARG0,ARG1];
    #Get client ID here...
    my $client = $heap->{cs}->client_by_input_wheel_id($wid);
    log_info(sprintf("Client [%d] %s %s", $client->ID, $input->method, $input->uri));
    $client->orig_request($input);
    $input = $client->request($input);
    if ($input->method eq 'CONNECT') {
        my $pending = $client->client_wheel->get_input_filter->get_pending();
        if ($input->content || $pending) {
            die "GOT PENDING DATA/CONTENT on a CONNECT request";
        }
        if ($CERT_ON_THE_FLY) {
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
        $input->header("Connection" => "close");
        $input->protocol("HTTP/1.0");
        $input->headers->remove_header("Keep-Alive");
        log_debug("Sending request", $input->uri, "for", $client->ID, "to POCO::C::HTTP");
        $kernel->post("__ua", "request", "got_response", $input);
    }
    log_debug("REQUEST", "\n".$input->as_string);
}

my %content_cache = ();

sub fold {
    my ($txt,$prefix) = @_;
    $txt =~ s/(.{75}[\s]*)\s+/$1\n/mg;
    $txt =~ s/^/$prefix/mg;
    return $txt;
}

sub _process_response {
    my ($client,$request,$response) = @_;
    #$response->headers->remove_header("Connection");
    my $input_wheel = $client->client_wheel();
    my $log_meth = ($response->code =~ m/^[23]/) ? \&log_info : \&log_warn;
    my $cksm = md5_hex($response->content);
    $log_meth->(sprintf("Client [%d] %d %s <%s>, content checksum %s",
                        $client->ID,
                        $response->code,
                        $response->message,
                        URI->new($request->uri)->canonical,
                        $cksm));
    if ($response->code !~ m/^[23]/) {
        log_info("\n" . fold($client->ID, $response->as_string));
        log_info("Request was...\n" . fold($client->ID, $request->as_string));
    }
    if($content_cache{$cksm}++ > 1) {
        log_debug("\tContent has been delivered $content_cache{$cksm} times");
    }
    $input_wheel->put($response);
    $client->is_done(1);

}

sub got_response {
    #Feel free to mangle stuff here... etc.
    
    my ($heap,$request,$response) = @_[HEAP,ARG0, ARG1];
    my $client = $heap->{cs}->client_by_request($request->[0]);
    
    if(!$client) {
        log_warn("Couldn't find client!");
        return;
    }
    _process_response($client, $request->[0], $response->[0]);
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
        log_err("Client", $client->ID, $client->request->uri,
                "errored ($errnum [$operation]: $errstr) before being sent a response");
    }
    $client->close();
}

sub server_failure {
    log_err("");
}

sub sent_to_client {
    my ($heap,$wid) = @_[HEAP,ARG0];
    my $client = $heap->{cs}->client_by_input_wheel_id($wid);
    my $input = $client->request;
    if ($input->method eq 'CONNECT') {
        my $host = $input->uri;
        my $sslified_sock;
        if ($CERT_ON_THE_FLY) {
            my ($crtfile,$keyfile) = @{$CERTCACHE{$host}}{qw(cert key)};
            
            if (!($crtfile && $keyfile)) {
                die "Didn't expect to find a host without a cert/key pair";
            }
            
            my $ctx = SSLify_ContextCreate($keyfile, $crtfile);
            $sslified_sock = Server_SSLify($client->client_wheel->get_input_handle, $ctx);
        } else {
            my $sslified_sock = Server_SSLify(
            $client->client_wheel->get_input_handle);
        }
        
        my $input_filter = $client->client_wheel->get_input_filter();
        my $output_filter = $client->client_wheel->get_output_filter();
        $client->client_wheel(undef);
        my $new_wheel = genwheel($sslified_sock, $input_filter, $output_filter);
        $client->client_wheel($new_wheel);
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

#CA object...
my $CA = CertOnTheFly::CA->new();

my $CACHEPATH = "cert_cache";

sub ssl_client_send_200 {
    my ($client) = @_;
    log_debug("Sending 200 response", $client->ID, $client->request->uri);
    my $response = HTTP::Response->new(200, "Connection established");
    $response->protocol("HTTP/1.0");
    $response->header("Proxy-agent" => "poco-proxy");
    $client->client_wheel->put($response);    
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
    $kernel->post("__ua", "request", "ssl_got_cert_response", $request);
}

sub ssl_add_pending_client {
    my ($client_id,$host) = @_;
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
        $client_action->(sub { shift->client_wheel->put($new_response) });
        return;
    }
    #log_warn($pem);
    my ($cloned,$key) = $CA->clone_cert($pem);
    my $certfile = $CACHEPATH . "/$host.pem";
    my $keyfile = $CACHEPATH . "/$host.key";
    
    write_file($certfile, $cloned);
    write_file($keyfile, $key);
    $CERTCACHE{$host}->{key} = $keyfile;
    $CERTCACHE{$host}->{cert} = $certfile;
    
    #Now send our our 200 connection established messages.. etc.
    $client_action->(\&ssl_client_send_200);
}

sub format_output {
    my $in = shift;
    $in =~ s/^/\t/gsm;
    return $in;
}

if (!caller) {
    __PACKAGE__->spawn();
    POE::Kernel->run();
}
1;