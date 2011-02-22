package POE::Component::Server::MITMHTTPProxy::Client;
use strict;
use warnings;
BEGIN {
    use File::Basename qw(dirname);
    my $base = dirname(__FILE__);
    require "lib.pm";
    lib->import($base);
    eval {
    require "Miner/Logger.pm";
    };
    if ($@) {
        no strict "refs";
        foreach my $lvl qw(debug err warn crit info) {
            *{"log_".$lvl} = sub {
                print join(" ", @_) . "\n";
            };
        }
    } else {
        Miner::Logger->import({level => "warn"});
    }
}
use URI;
use constant {
    PC_ID                       => 0,
    PC_CLIENT_WHEEL             => 1,
    PC_HTTP_REQUEST             => 2,
    PC_ORIG_REQUEST             => 3,
    PC_HTTPS_CONNECTED          => 4,
    PC_DONE                     => 5,
    _PC_MAX                     => 6,
};

our $id_counter = 1;
our %CLIENT_BY_ID;
our %CLIENT_BY_INPUT_WHEEL_ID;
our %CLIENT_BY_REQUEST;

sub client_by_id {
    my ($cls,$id) = @_;
    return $CLIENT_BY_ID{$id};
}

sub client_by_input_wheel_id {
    my ($cls,$wid) = @_;
    return $CLIENT_BY_INPUT_WHEEL_ID{$wid};
}

sub client_by_request {
    my ($cls,$req) = @_;
    return $CLIENT_BY_REQUEST{$req};
}

sub new {
    my ($cls,$input_wheel) = @_;
    my $self = [];
    foreach my $i (0.._PC_MAX) {
        $self->[$i] = undef;
    }
    $self->[PC_ID] = $id_counter++;
    $CLIENT_BY_ID{$self->[PC_ID]} = $self;
    bless ($self,$cls);
    $self->client_wheel($input_wheel);
}

sub ID {
    shift->[PC_ID];
}
sub client_wheel {
    my ($self,$new_wheel) = @_;
    if (@_ == 2) {
        $self->[PC_CLIENT_WHEEL] = $new_wheel;
        $CLIENT_BY_INPUT_WHEEL_ID{$new_wheel->ID} = $self if defined $new_wheel;
    }
    return $self->[PC_CLIENT_WHEEL];
}

sub request {
    my ($self,$request) = @_;
    if (@_ == 2) {
        if ($self->is_CONNECTed) {
            my $host = $self->orig_request->header('Host');
            my $old_uri = $request->uri;
            my $uri = URI->new();
            $uri->scheme("https");
            $uri->host($host);
            $uri->path_query($old_uri);
            $request->header('Host' => $host);
            $request->uri($uri->canonical);
            log_info(sprintf("Client ID %d: Mangled URL: %s -> %s",
                             $self->ID, $old_uri, $request->uri));
        }
        my ($proto_vers) = ($request->protocol =~ m,HTTP/([\d\.]+),);
        #Strip Connection headers..
        #http://tools.ietf.org/html/rfc2616#section-14.10
        $request->headers->remove_header("Connection") unless $self->is_CONNECTed();
        $self->[PC_HTTP_REQUEST] = $request;
        $CLIENT_BY_REQUEST{$request} = $self;
    }
    return $self->[PC_HTTP_REQUEST];
}

sub orig_request {
    my ($self,$req) = @_;
    if (@_ == 2 && !defined $self->[PC_ORIG_REQUEST]) {
        #log_debug($self->ID, "Setting original request..");
        $self->[PC_ORIG_REQUEST] = $req;
    }
    return $self->[PC_ORIG_REQUEST];
}

sub is_CONNECTed {
    my ($self,$val) = @_;
    if (@_ == 2) {
        $self->[PC_HTTPS_CONNECTED] = $val;
    }
    return $self->[PC_HTTPS_CONNECTED];
}

sub is_done {
    my ($self,$val) = @_;
    if (@_ == 2) {
        $self->[PC_DONE] = $val;
    }
    return $self->[PC_DONE];
}

sub _delete_by_value {
    my ($val,$hlist) = @_;
    foreach my $h (@$hlist) {
        while (1) {
            my %tmp = reverse %$h;
            last if (!exists $tmp{$val});
            delete $h->{$tmp{$val}};
        }
    }
}

sub DESTROY {
    my $self = shift;
    log_debug "DESTROYing $self";
}
sub close {
    my $self = shift;
    _delete_by_value($self,
        [\%CLIENT_BY_REQUEST, \%CLIENT_BY_INPUT_WHEEL_ID,
        \%CLIENT_BY_ID]);
    log_info sprintf("Removing client (id=%d url=%s)",
                     $self->ID, $self->request->uri);
}

1;
