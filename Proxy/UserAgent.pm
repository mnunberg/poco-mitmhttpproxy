package Proxy::UserAgent;

use strict;
use warnings;
use lib '/var/www/vweb/dynamite/bin';
use CommonLiteInclude;
use Data::Dumper;
use HTTP::Cookies;
use LWP::UserAgent;
use S3Include;

our @ISA = qw(LWP::UserAgent);

sub new {
	my $class = shift;
	my $self = new LWP::UserAgent;
	bless $self, $class;
	$self->cookie_jar(HTTP::Cookies->new(autosave => 1));
	return $self;
}

sub mine {
	my $self = shift;
	my $class = ref($self) || $self;
	print "Hello, this is $class -> $self\n";
	print Dumper $self;
}

sub progress {
	my $self = shift;
	my ($status, undef) = @_;
	if ($self->{'_requestStartTime'} <= (time - 30)) {
			# uh oh we've taken too long!!!
			print STDERR "REQUEST TIMED OUT BUT WE DON'T KNOW HOW TO BREAK OUT\n";
			return undef;
	}
}

sub dd__setRandomUserAgent {
	my $self = shift;
	my $newua = random_ua();
	$self->agent($newua);
	return $newua;
	}

sub dd__getStoredCache {
	print STDERR "Checking for stored cache...\n";
	my $self = shift;
	my $request = shift;
	my $link = $request->uri;
	my $rid = url_to_reseller($link);
	if ($rid =~ /^r\d{8}$/) {
		$link = uri_decode($link);
		$link = super_clean_url($link);
		my $lid = link_to_lid($link);
		if ($lid =~ /^l(?:\d{12}|\d{8})$/) {
			# we request some different cache types, let's insert the type here too
			# (prefixed by _ if it exists)
			my $ctype = $request->header('X-DCacheType');
			my $cache = get_s3("/alertcache/$rid/$lid/" . ($ctype ? "_$ctype" : '') . $request->header('X-DTime') . ".html")->{'value'};
			print STDERR "Attempted cache retrieval from S3\n";
			if (length($cache) > 5) {
				$request->method("HEAD");
				$self->{'_doCacheReplacement'} = 1;
				$self->{'_substituteCache'} = $cache;
			}
		}
	}
	return $request;
}

sub dd__resetCacheReplacement {
	my $self = shift;
	$self->{'_doCacheReplacement'} = 0;
	$self->{'_substituteCache'} = undef;
}	

sub dd__getCache {
	my $self = shift;
	my $request = shift;
	my $obj_response;
	my ($doFromCache, $cacheS3Path, $ourresponse);

	my $origurl = $request->header('X-DOriginalURL');
	if ($request->header('X-DTime') && $request->uri eq $origurl) {
		# we hvae a dtime header, check if this link is a buy page in our system
		#my $link = $request->uri;
		my $link = $origurl;
		my $rid = url_to_reseller($link);
		if ($rid =~ /^r\d{8}$/) {
			$link = uri_decode($link);
			$link = super_clean_url($link);
			my $lid = link_to_lid($link);
			if ($lid =~ /^l(?:\d{12}|\d{8})$/) {
				# we request some different cache types, let's insert the type here too
				# (prefixed by _ if it exists)
				my $ctype = $request->header('X-DCacheType');
				my $dtime = $request->header('X-DTime');
				my $cacheidx = $request->header('X-DCacheIndex');
				my $cacheref = $request->header('X-DCacheReference');
				my $key = "alertcache/$rid/$lid/" . $dtime . "_c$cacheidx" . ($ctype ? "_$ctype" : '') . ".html";
				$S3Include::bname = "data.dynamitedata.com";
				my $cachehash = get_s3($key);
				my $cache = $cachehash->{'value'};
				#$request->method("HEAD");
				$ourresponse = 1;
				$self->{'_doCacheReplacement'} = 1;
				$self->{'_substituteCache'} = $cache;
			}
		}
		# moved code from dd__getStoredCache to here instead
		#$request = $self->dd__getStoredCache($request);
	}

	$self->{'_requestStartTime'} = time;

	eval {
		# here we do our request
		if ($ourresponse == 1 && $self->{'_doCacheReplacement'}) {
			# make our own
			$obj_response = HTTP::Response->new( '200', 'OK', undef);
			$obj_response->protocol("HTTP/1.0");
		} else {
			$obj_response = $self->request($request);
		}
	};
	if ($@) {
		print STDERR "LWP BAILED: $@\n";
	}

	$self->{'_requestStartTime'} = undef;

	if ($self->{'_doCacheReplacement'}) {
		print STDERR "CACHE OVERRIDE: overriding header 'Content-Encoding'\n";
		$obj_response->header("Content-Encoding" => undef);
		print STDERR "CACHE OVERRIDE: overriding header 'Content-Length'\n";
		$obj_response->header("Content-Length" => length($self->{'_substituteCache'}));
		print STDERR "CACHE OVERRIDE: overriding header 'Content-Type'\n";
		$obj_response->header("Content-Type" => 'text/html');
		$obj_response->content($self->{'_substituteCache'});
		$self->dd__resetCacheReplacement;
	}

	my $pre = '[' . ref($self) . ']';
	print STDERR "$pre grabbed " . $request->uri . "\n";
	print STDERR "$pre return code: " . $obj_response->code . "\n";
	print STDERR "$pre return url: " . $obj_response->base . "\n";
	print STDERR "$pre return content-length: " . length($obj_response->content) . "\n";
	return $obj_response;
}
