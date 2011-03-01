package POE::Component::Server::MITMHTTPProxy::Dispatcher;
use strict;
use warnings;
use POE::Component::Server::MITMHTTPProxy::Constants qw(:callback_retvals);
use Log::Fu { level => "info" };
my $request_counter = 0;

use constant {
    D_THROWBACK         => 0,
    D_REQUEST           => 1,
    D_PROVIDE_RESPONSE  => 2,
    D_UPSTREAM_RESPONSE => 3,
    D_REQUEST_IDS       => 4,
    D_IS_SYNC           => 5,
    D_USER_SESSION      => 6,
    D_ERROR             => 7,
    D_MAX               => 8,
};

my %H2C = (
    Request             => D_REQUEST,
    UpstreamResponse    => D_UPSTREAM_RESPONSE,
    ProxyError          => D_ERROR,
);

sub new {
    my ($cls,$events,$u_session) = @_;
    #Events is a hashref...
    my $self = [];
    bless($self,$cls);
    $self->[$_] = undef foreach (0..D_MAX-1);
    foreach my $evname (keys %$events) {
        my $h = delete $events->{$evname};
        log_info("Initializing event $evname");
        my $fn = $h->{cb};
        my $is_sync = $h->{sync};
        $self->[$H2C{$evname}] = $fn;
        $self->[D_IS_SYNC]->{$H2C{$evname}} = $is_sync;
    }
    if (!defined $self->[D_ERROR]) {
        warn "Must have an error event handler";
        $self->[D_ERROR] = sub {
            warn @_;
        }
    }
    if (!defined $u_session) {
        die "Must have user session alias";
    }
    $self->[D_USER_SESSION] = $u_session;
    return $self;
}

#Dispatches to the user event
sub _dispatch {
    my ($self,$kernel,$cbid,@args) = @_;
    return if !defined $self->[$cbid];
    
    if ($self->[D_IS_SYNC]->{$cbid}) {
        return $self->[$cbid]->(@args);
    } else {
        $kernel->post($self->[D_USER_SESSION],
                      $self->[$cbid],
                      @args);
        return [CB_DEFERRED];
    }
}

#when a request is first received, this decides what to do with it..
sub request {
    my ($self, $kernel, $request) = @_;
    my $throwback = $self->[D_REQUEST];
    return $self->_dispatch($kernel,
                     D_REQUEST,
                     $request);
}

sub upstream_response {
    my ($self,$kernel,$request,$response,$data) = @_;
    return $self->_dispatch($kernel,
                     D_UPSTREAM_RESPONSE,
                     ($request,$response,$data));
}

sub error {
    my ($self,$request,$message) = @_;
    $self->[D_ERROR]->($request,$message);
}
1;
