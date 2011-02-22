#!/usr/bin/perl
package POE::Component::Server::MITMHTTPProxy;
use strict;
use warnings;

use constant {
    CERT_PEM            => 1,
    CERT_SPOOFED_PEM    => 2,
    CERT_SPOOFED_KEY    => 3,
    CERT_PENDING_IDS    => 4,
};

sub new {
    my ($cls,$host) = @_;
    
}