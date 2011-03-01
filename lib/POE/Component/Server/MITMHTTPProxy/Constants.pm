package POE::Component::Server::MITMHTTPProxy::Constants;
use strict;
use warnings;
use base qw(Exporter);
my @CB_CONSTANTS;
our @EXPORT;
our @EXPORT_OK;
our %EXPORT_TAGS;

BEGIN {
    @CB_CONSTANTS = qw/
    CB_FETCH_UPSTREAM
    CB_HAVE_RESPONSE
    CB_FORWARD_UPSTREAM
    CB_DEFERRED
    /;
    no strict "refs";
    foreach my $i (0..$#CB_CONSTANTS) {
        my $fn_name = __PACKAGE__."::$CB_CONSTANTS[$i]";
        *{$fn_name} = sub { return $i+1 };
    }
    push @EXPORT_OK, @CB_CONSTANTS;
    $EXPORT_TAGS{callback_retvals} = [@CB_CONSTANTS];
}