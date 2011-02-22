#!/usr/bin/perl
#
# Very specific module designed to keep us up to date on all
#  TOR related items
#
package Proxy::Tor;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(
		restart_tor rotate_tor random_tor all_tor_ips tor_to_ip all_tor_ips
		);
our $VERSION = 1.00;
#######

use strict;
use IO::Socket::INET;
use List::Util 'shuffle';
use System::Proc;
use Util::Slurp;


#
# May 26, 2010:
#  We have been unnecssarily killing tor by killing it even if its brand new.  Now we
#  wait up to 10 minutes before killing a new tor
#

sub restart_tor($) {
	my ($port) = @_;

	if(getpwuid($<) ne "root") { 
		return;
	}

	foreach my $pid (shuffle process_grep("bin/tor")) {
		my @stat = stat("/proc/$pid/cmdline");
		my $line = slurp("/proc/$pid/cmdline");
		if($line =~ /SocksPort\0$port\0\-/) {
			if($stat[10] > time() - 60*10) { 
				return 0;
			}
			my $ok = kill(9,$pid);
		}
	}
	my $control_port = $port + 1;
	my $exec = "/usr/local/bin/tor --SocksPort $port --ControlPort $control_port --EnforceDistinctSubnets 0 --DataDirectory /tmp/tor/$port/ --runasdaemon 1 --user _tor 2>&1";
	my $ret = system($exec);

	return 1;
}


sub random_tor() {
	my $port;
	foreach my $pid (shuffle process_grep("bin/tor")) {
		open(my $fp,"</proc/$pid/cmdline");
		my @line = <$fp>;
		close($fp);
		my $line = "@line";

		my @ips;
		if($line =~ /SocksPort\0(.+?)\0\-/) {
			$port = $1;
			@ips = tor_to_ip($port);
		}
		if(!@ips) {
			restart_tor($port);
			$port = "";
			next;
		}
		last;
	}
	return $port;
}


sub all_tor_ips() {
	my @ips;
	foreach my $pid (shuffle process_grep("bin/tor")) {
		open(my $fp,"</proc/$pid/cmdline");
		my @line = <$fp>;
		close($fp);
		my $line = "@line";

		if($line =~ /SocksPort\0(.+?)\0\-/) {
			push(@ips,tor_to_ip($1));
		}
	}
	return uniq(@ips);
}


#
# April 5, 2010:
#   Rotate the TOR identify, so we don't have to worry about hiding
# Return 0 on fail. Return 1 on success
#
# Given the optional argument of "port", this will allow us to rotate the identity on a
#  non-standard port. Should always be an odd number. If not, round up.
#
sub rotate_tor(;$$) {
	my ($port,$shutdown) = @_;
	if(!$port) {
		$port = 9051;
	}
	if($port % 2 == 0) {
		$port++;
	}

	my $old_alarm = alarm();
	alarm(10);
	eval {
		my $sock = IO::Socket::INET->new(PeerAddr => "127.0.0.1",
				PeerPort => $port,
				Proto    => 'tcp',
				Timeout => "2"
				);
		if(!$sock) { return 0 };
		print $sock "AUTHENTICATE\r\n";
		my $line = <$sock>;
		if($line !~ /^250 OK/) {
			die $line;
		}
		if($shutdown) {
			print $sock "SIGNAL SHUTDOWN\r\n";
		}
		else {
			print $sock "SIGNAL NEWNYM\r\n";
		}
		my $line = <$sock>;
		if($line !~ /^250 OK/) {
			die $line;
		}
		close($sock);
	};
	if($@ =~ /[Aa]pache/) {
		die $@;
	}
	alarm($old_alarm);
	if($@) {
		print STDERR "Warning: $@\n";
		return 0;
    }
    return 1;
}


#
# April 16, 2010:
#   Given a local tor port, determine the estimated outbound IP address of the current circuit
#
sub tor_to_ip(;$) {
	my ($port) = @_;

	if(!$port) {
		$port = "9050";
	}
	if($port % 2 == 0) {
		$port++;
	}

	my (@ips);
	eval {
		use IO::Socket::INET;
		my $sock = IO::Socket::INET->new(PeerAddr => "127.0.0.1",
				PeerPort => $port,
				Proto    => 'tcp',
				Timeout => 5
				);
		if(!$sock) { return 0 };
		print $sock "AUTHENTICATE\r\n";
		my $line = <$sock>;
		if($line !~ /^250 OK/) {
			die $line;
		}
		my $name;
		print $sock "getinfo circuit-status\r\n";
		while(my $line = <$sock>) {
			$line = trim($line);
			if($line =~ /^([\d]+)\sBUILT\s(.+)/) {
				my @split = split(/,/,$2);
				$name = $split[-1];
				$name =~ s/\s?PURPOSE=.+//g;
				if($#split != 2) {
					next;
				}

				my $temp_port = $port - 1;
				open(my $fp,"</tmp/tor/$temp_port/cached-consensus");
				while(my $line = <$fp>) {
					if($line =~ /^r\s$name\s.+?\s.+?\s.+?\s.+?\s(.+?)\s/) {
						push(@ips,$1);
						last;
					}
				}
				close($fp);
			}
			if($line =~ /^250 OK/) {
				last;
			}
		}
		close($sock);
	};
	if($@ =~ /[Aa]pache/) {
		die $@;
	}
	return @ips;
}

