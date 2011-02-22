#!/usr/bin/perl
use strict;
use IO::Socket::SSL;
use Data::Dumper;
use lib "/var/www/vweb/dynamite/bin/";


use CommonLiteInclude;
use CommonInclude;
use ProxyInclude;
use MemcachedInclude;
use SQL::MySQL;
use List::Util 'shuffle';
use CGIInclude;

my $memd = $MemcachedInclude::memd;

open(my $fp,"</tmp/proxy.pid");
my @line = <$fp>;
my $proc = $line[0];

if($proc) { 
	print STDERR "Found old PID of $proc\n";
	if(-d "/proc/$proc/") {
		print STDERR " Warning: another proxy process is already running $proc. Exiting\n";
		exit(1);
	}
}
if(!best_server("write")) {
	print STDERR " Warning: no write databases available. Aborting\n";
	exit(1);
}
print STDERR " Running proxy processor: this is thread-safe. \n";

close($fp);
open(my $fp,">/tmp/proxy.pid");
print $fp $$;
close($fp);


while(1) { 
#		kristopher.kubicki2@gmail.com
	my @accounts = qw(
		kristopher.kubicki-8501@gmail.com
		kristopher.kubicki-8505@gmail.com
);
	@accounts = shuffle(@accounts);
	foreach my $account (@accounts) { 
		print STDERR "[$account] \n";
		proxy_driver($account);
	}
	sleep(44);
	commit_proxies();
}

exit(1);

sub  proxy_driver($) { 
	my ($username) = @_;

	my ($ip,$port,$ttl);
	eval { 
		local $SIG{ALRM} = sub { die "Alarm clock\n" };
		alarm(30);
		($ip,$port,$ttl) = &get_temp_proxy($username);
		alarm(0);
	};
	if($ip !~ /^\d+?\.\d+?\.\d+?\.\d+/ || $port !~ /^\d{2,5}$/ || $ttl !~ /^\d{2,6}$/) {
		warn "No IP detected: $ip:$port ($ttl TTL)\n";
		return 0;
	}
	if($ttl < 30) {
		warn "Detected very short TTL of $ttl seconds, aborting\n";
		return 0;
	}

	my $time = time();
	my $cache = test_http_proxy($ip, $port, $time, ProxyInclude::get_my_ip());
	$ttl -= time() - $time;
	if($ttl > 30 && $cache =~ /HTTP\/1.0 200 OK/) {
		eval { 
			$ttl -= 5;
			my $country = CGIInclude::ip_to_country($ip);
			my $query = "INSERT INTO indexes.proxyindex_ndb (ip,port,err,ctime,country,socks,elite,codeen,temp,expiredate) 
				VALUES ('$ip','$port','0',NOW(),'$country','1','1','0',DATE_ADD(NOW(),interval '$ttl' second),DATE(NOW())) 
				ON DUPLICATE KEY UPDATE err='0',temp=DATE_ADD(NOW(),interval '$ttl' second),codeen='0',socks='1',elite='1',expiredate=DATE(NOW())";
			$query =~ s/[\s\n]+?/ /g;

			my $dbh = connect_to_db("write");
			my $sth = $dbh->prepare($query);
			$sth->execute();
			$sth->finish();
			$dbh->disconnect();
			sleep(2);
			ProxyInclude::commit_proxies(1);
		};
		if($@) { 
			print STDERR "[$ip:$port] FAILED1 ($username): $@\n";
		}
		else { 
			print STDERR "[$ip:$port] Added $ttl sec TTL\n";
		}
	}
	else {
		print STDERR "[$ip:$port] FAILED2 ($username): Cannot build circuit\n";
	}
	return 1;
}



sub get_temp_proxy(;$) {
	my ($username) = @_;

	if($username eq "") {
		return;
	}

	my $hardware = "676FEBFBE7363E0FBFF";
	my @ipfields = qw(IP Port Response TTL);
	my %verify = ('GetIP-fields'	=> [qw(IP Port Response TTL)],
			'Auth-fields'	=> [qw(Authenticate UserID)]);


	my $rand;
	while($rand < 700) { 
		$rand = sprintf("%d",rand(1200));
	}
	#my $region = sprintf("%d",rand(4));
	my $region = 0;
	print STDERR "Requesting $rand second TTL in region $region\n";

# some vars here so we can properly do content-length
	my $AuthBody = "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:tns=\"urn:IPRentalAuthMech\" xmlns:types=\"urn:IPRentalAuthMech/encodedTypes\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"><soap:Body soap:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><tns:Authenticate><return href=\"#id1\" /></tns:Authenticate><tns:IPRauthArgs id=\"id1\" xsi:type=\"tns:IPRauthArgs\"><APIkey xsi:type=\"xsd:string\">e3R5phe9e3eguwrumek6vexunuqupretru</APIkey><username xsi:type=\"xsd:string\">$username</username><password xsi:type=\"xsd:string\">iprental1234</password><Hardware xsi:type=\"xsd:string\">$hardware</Hardware></tns:IPRauthArgs></soap:Body></soap:Envelope>\n";
	my $GetIPBody = "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:tns=\"urn:IPRentalFetchMech\" xmlns:types=\"urn:IPRentalFetchMech/encodedTypes\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"><soap:Body soap:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><tns:doIpLease><return href=\"#id1\" /></tns:doIpLease><tns:IPRargs id=\"id1\" xsi:type=\"tns:IPRargs\"><APIkey xsi:type=\"xsd:string\">e3R5phe9e3eguwrumek6vexunuqupretru</APIkey><username xsi:type=\"xsd:string\">$username</username><password xsi:type=\"xsd:string\">iprental1234</password><Hardware xsi:type=\"xsd:string\">$hardware</Hardware><TTL xsi:type=\"xsd:string\">$rand</TTL><Location xsi:type=\"xsd:string\">$region</Location></tns:IPRargs></soap:Body></soap:Envelope>\n";

	my %req = (	AuthHeaders	=>	"POST /authentication/ HTTP/1.1\r\n" .
			"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; MS Web Services Client Protocol 2.0.50727.3053)\r\n" .
			"Content-Type: text/xml; charset=utf-8\r\n" .
			"SOAPAction: \"urn:IPRentalAuthMechAction\"\r\n" .
			"Host: secure.iprental.com\r\n" .
			"Content-Length: " . length($AuthBody) . "\r\n" .
			"Expect: 100-continue\r\n" .
			"Connection: Keep-Alive\r\n" .
			"\r\n",
			AuthBody	=> 	$AuthBody,

			GetIPHeaders	=>	"POST /authentication/pullip/ HTTP/1.1\r\n" .
			"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; MS Web Services Client Protocol 2.0.50727.3053)\r\n" .
			"Content-Type: text/xml; charset=utf-8\r\n" .
			"SOAPAction: \"urn:IPRentalFetchMechAction\"\r\n" .
			"Host: secure.iprental.com\r\n" .
			"Content-Length: " . length($GetIPBody) . "\r\n" .
			"Expect: 100-continue\r\n" .
			"\r\n",
			GetIPBody	=>	$GetIPBody);



	my $try = 0;
step:	foreach my $step (qw(GetIP Auth GetIP)) {
			print STDERR "Authenticating\n" if ($step eq "Auth");
			$try++;
			my $sock = IO::Socket::SSL->new("secure.iprental.com:https")
				|| warn "I encoutered a problem: ".IO::Socket::SSL::errstr();
			print $sock $req{$step . "Headers"};
			my ($rsent, $response);
			while(my $line = <$sock>) {
				if($rsent == 1) {
					chomp; 
					$response .= $line;
				}
			elsif($line =~ /HTTP\/1\.1 100 Continue/i) {
				print $sock $req{$step . 'Body'}; 
				$rsent = 1;
			}
			if($line =~ /Exceeded Daily IP Limit/) {
				print STDERR "Warning, exceeded IP limit on $username\n";
				return undef;
			}
		}

		if($response =~ /<IP[^>]*?>([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})<\/IP>.*?<Port[^>]*?>([\d]{3,5})<\/Port><TTL[^>]*?>([\d]+?)<\/TTL>/) {
			return ($1,$2,$3);
		}

		my %rdata;
		foreach my $x (@{$verify{$step . '-fields'}}) {
			($rdata{$x}) = $response =~ /<$x[^>]*>([^<]+)<\/$x/;
# test if this field is "good", otherwise we need to bail (move on to auth if first GetIP)
			my $string = $rdata{$x};
			if (!$rdata{$x}) {
				return undef if $try > 1;
				next step;
			}
		}
		if ($step eq "GetIP") {
			return @rdata{qw(IP Port TTL)};
		}
	}
	return undef;
}
