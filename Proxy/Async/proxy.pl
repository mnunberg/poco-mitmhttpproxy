#!/usr/bin/perl
use warnings;
use strict;
$SIG{PIPE} = 'IGNORE';    # otherwise, SIGPIPE terminates the proxy.
use POE;
use POE::Component::Server::TCP;
use POE::Component::Client::HTTP;
use POE::Filter::HTTPD;
use POE::Filter::SSL;
use HTTP::Response;
sub DUMP_REQUESTS ()  { 1 }
sub DUMP_RESPONSES () { 1 }
sub LISTEN_PORT ()    { 8088 }
use Data::Dumper;

my $crtfile = "/var/www/vweb/dynamite/bin/Proxy/server.crt";
my $keyfile = "/var/www/vweb/dynamite/bin/Proxy/server.key";

### Spawn a web client to fetch requests through.
POE::Component::Client::HTTP->spawn(Alias => 'ua');
### Spawn a web server.
# The ClientInput function is called to deal with client input.
# ClientInput's callback function will receive entire HTTP requests
# because this server uses POE::Filter::HTTPD to parse its input.
#
# InlineStates let us attach our own events and handlers to a TCP
# server.  Here we attach a handler for the got_response event, which
# will be sent to us by Client::HTTP when it has fetched something.
POE::Component::Server::TCP->new(
  Alias        => "web_server",
  Port         => LISTEN_PORT,
  ClientFilter => 'POE::Filter::HTTPD',
  ClientInput  => \&handle_http_request,
  InlineStates => {got_response => \&handle_http_response,},
);
### Run the proxy until it is done, then exit.
POE::Kernel->run();
exit 0;
### Handle HTTP requests from the client.  Pass them to the HTTP
### client component for further processing.  Optionally dump the
### request as text to STDOUT.
sub handle_http_request {
  my ($kernel, $heap, $request) = @_[KERNEL, HEAP, ARG0];

  # If the request is really a HTTP::Response, then it indicates a
  # problem parsing the client's request.  Send the response back so
  # the client knows what's happened.
  if ($request->isa("HTTP::Response")) {
    $heap->{client}->put($request);
    $kernel->yield("shutdown");
    return;
  }
  print "Got HTTP request...\n";
  print Dumper($request);
  if ($request->method eq 'CONNECT') {
    #SSL...
    print "SSL requested\n";
    $heap->{client}->set_filter(POE::Filter::SSL->new(
        crt => $crtfile, key => $keyfile));
    $heap->{client}->put("HELLO WORLD!!!");
    print "Returning\n";
    return;
  }
  # Client::HTTP doesn't support keep-alives yet.
  $request->header("Connection",       "close");
  $request->header("Proxy-Connection", "close");
  $request->remove_header("Keep-Alive");
  display_thing($request->as_string()) if DUMP_REQUESTS;
  $kernel->post("ua" => "request", "got_response", $request);
}
### Handle HTTP responses from the POE::Component::Client::HTTP we've
### spawned at the beginning of the program.  Send each response back
### to the client that requested it.  Optionally display the response
### as text.
sub handle_http_response {
  my ($kernel, $heap) = @_[KERNEL, HEAP];
  my $http_response = $_[ARG1]->[0];
  my $response_type = $http_response->content_type();
  if ($response_type =~ /^text/i) {
    display_thing($http_response->as_string()) if DUMP_RESPONSES;
  }
  else {
    print Dumper($http_response);
    print "Response wasn't text.\n" if DUMP_RESPONSES;
  }

  # Avoid sending the response if the client has gone away.
  $heap->{client}->put($http_response) if defined $heap->{client};

  # Shut down the client's connection when the response is sent.
  $kernel->yield("shutdown");
}
### Display requests and responses with brackets around them so they
### stand apart.
sub display_thing {
  my $thing = shift;
  $thing =~ s/^/| /mg;
  print ",", '-' x 78, "\n";
  print $thing;
  print "`", '-' x 78, "\n";
}
