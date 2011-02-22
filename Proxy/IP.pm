#!/usr/bin/perl
#
# Very specific module designed to keep us up to date on all
#  TOR related items
#
package Proxy::IP;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(
		bad_ips
		);
our $VERSION = 1.00;
#######

use strict;
use MemcachedInclude;
use SQL::MySQL;

#
# January 11, 2010:
#  Refactored this function outside of CGIInclude so that we can use it for any time we
#  need the prox list
#
sub bad_ips() {

	my $memd = init_memcached();
    my $bad_ip = $memd->get("PROXYIP3");
    if($bad_ip) {
        return $bad_ip;
    }
    eval {
        my $dbh = connect_to_db("read");
        my $query = "select ip from indexes.proxyindex_ndb where temp is null
            and ctime > date_sub(NOW(),interval 1 month) AND ctime is not null";
        my $sth = $dbh->prepare($query);
        $sth->execute();
        while(my $ref = $sth->fetchrow_hashref()) {
            $bad_ip->{$ref->{"ip"}}++;
        }
        $sth->finish();
        my $ok = $memd->set("PROXYIP3",$bad_ip,60*60*24);
    };
    if($@) {
        print STDERR "Warning: cannot recall proxy information: $@\n";
    }
    return $bad_ip;
}

