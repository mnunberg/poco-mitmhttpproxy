use strict;
package Proxy::HTTPProxy;
our $VERSION = 1.00;
use HTTP::Request;
use Proxy::UserAgent;
use Data::Dumper;

sub new {
	my $class = shift;
	my $self = {};
	bless $self, $class;
	$self->initialize();
	return $self;
}

sub initialize {
	my $self = shift;
	$self->ID(randomString(12));
	$self->{'_requestor'} = Proxy::UserAgent->new;
	$self->{'_requestor'}->dd__setRandomUserAgent;
	$self->{'_requestor'}->proxy([qw/ http https /], "http://174.138.164.177:42420");
	$self->{'_requestor'}->use_eval(0);
	$self->{'_requestor'}->use_alarm(0);
}

sub requestor {
	my $self = shift;
	return $self->{'_requestor'};
}

sub add($) {
	my $self = shift;
	my $sock = shift;
	my $start = time;
	my $valid = undef;
	my $rstring = time . randomString();
	print STDERR "randstring: $rstring\n";
	$self->{'clientID'}->{$rstring}->{'socket'} = $sock;
	$self->{'clientID'}->{$rstring}->{'identifier'} = $rstring;
	$self->{'clientID'}->{$rstring}->{'readBuffer'} = '';
	$self->{'clientID'}->{$rstring}->{'isConnect'} = 0;
	$self->{'clientID'}->{$rstring}->{'serverSocket'} = '';
	$self->{'clientID'}->{$rstring}->{'connectWriteBuffer'} = '';
	$self->{'clientID'}->{$rstring}->{'connectWriteOffset'} = 0;
	$self->{'clientSocket'}->{$sock} = $self->{'clientID'}->{$rstring};
	return $rstring;
}

sub processWriteBuffer {
	my $self = shift;
	my $sock = shift;
	my $ID = $self->getID($sock);
	my $bytes = syswrite($sock, $self->{'clientID'}->{$ID}->{'connectWriteBuffer'},$self->{'clientID'}->{$ID}->{'connectWriteOffset'});
	if ($bytes == length($self->{'clientID'}->{$ID}->{'connectWriteBuffer'}) - $self->{'clientID'}->{$ID}->{'connectWriteOffset'}) {
		$self->{'clientID'}->{$ID}->{'connectWriteBuffer'} = '';
		$self->{'clientID'}->{$ID}->{'connectWriteOffset'} = 0;
	} else {
		$self->{'clientID'}->{$ID}->{'connectWriteOffset'} += $bytes;
	}
}

sub pushConnectWriteBuffer {
	my $self = shift;
	my $sock = shift;
	my $buffer = shift;
	my $ID = $self->getID($sock);
	$self->{'clientID'}->{$ID}->{'connectWriteBuffer'} .= $buffer;
}

sub add_serverSocket {
	my $self = shift;
	my $ID = shift;
	my $socket = shift;
	$self->{'clientID'}->{$ID}->{'serverSocket'} = $socket;
	$self->{'clientSocket'}->{$socket} = $self->{'clientID'}->{$ID};
}

sub cleanup($) {
	my $self = shift;
	my $socket = shift;
	if (defined $socket) {
		my $ID = $self->getID($socket);
		#close($socket);
		$self->{'clientID'}->{$ID}->{'socket'}->close();
		$self->{'clientID'}->{$ID}->{'serverSocket'}->close() if ($self->{'clientID'}->{$ID}->{'isConnect'} == 1);
		#shutdown($socket,2);
		delete $self->{'clientSocket'}->{$socket};
		delete $self->{'clientID'}->{$ID};
	} else {
		print STDERR "Cleaning up all sockets...\n";
		foreach my $fh (keys %{$self->{'clientSocket'}}) {
			print STDERR "Cleaning up " . $self->getID($fh) . "\n";
			$self->cleanup($fh);
		}
	}
}

sub pushClientReadBuffer($$) {
	my $self = shift;
	my $socket = shift;
	my $buff = shift;
	my $ID = $self->getID($socket);
	$self->{'clientID'}->{$ID}->{'readBuffer'} .= $buff;
	print $self->{'clientID'}->{$ID}->{'readBuffer'} . "\n";
}

sub readFromClient($) {
	my $self = shift;
	my $fh = shift;
	print "attempting read from $fh (" . scalar($fh) . ")\n";
	my $buff;
	my $bytes = sysread($fh, $buff, 2048);
	$self->pushClientReadBuffer($fh, $buff);
	return $bytes;
}

sub extractRawClientRequest($) {
	my $self = shift;
	my $socket = shift;
	my $ID = $self->getID($socket);
	# this is a little tricky because we have to extract a request if there is one
	# while leaving any subsequent requests in the buffer
	$self->{'clientID'}->{$ID}->{'readBuffer'} =~ s/^(.*?(?:\r?\n){2})//es;
	my $request = $1;
	return $request;
}


sub extractClientRequest($) {
	my $self = shift;
	my $socket = shift;
	my $request = $self->extractRawClientRequest($socket);

	if ($request !~ /:443 / && $request =~ /^(GET|POST|CONNECT) (\S+) (HTTP\/1.[10])/) {
		my $r = HTTP::Request->parse($request);
#		print Dumper $r;
		print STDERR "Got valid $1 request for $2\n";
		return $r;
	}# elsif ($request =~ /^CONNECT/) {
	#	print STDERR "CONNECT REQUEST: $request\n";
	#	$self->pushConnectWriteBuffer($socket, $request->as_string);
	#	my $r = HTTP::Request->parse($request);
	#	return $r;
	#}
	return undef;
}

sub getAllIDs {
	my $self = shift;
	return keys %{$self->{'clientID'}};
}

sub getID($) {
	my $self = shift;
	my $sock = shift;
	return $self->{'clientSocket'}->{$sock}->{'identifier'};
}

sub getSocket($) {
	my $self = shift;
	my $identifier = shift;
	return $self->{'clientID'}->{$identifier}->{'socket'};
}	

sub ID(;$) {
	my $self = shift;
	my $id = shift;
	if ($id) {
		# set our ID
		$self->{'identifier'} = $id;
	} 
	return $self->{'identifier'};
}

sub randomString(;$) {
	my $len = $_[0] > 0 ? $_[0] : 8;
	my @chars = ('a'..'z','A'..'Z','0'..'9');
	my $string = '';
	for (my $i = 1; $i <= $len; $i++) {
		$string .= $chars[rand @chars];
	}
	return $string;
}


package Proxy::HTTPProxy::Pair;
# pretty sure I never used this
# can probably remove it 
#   -Rob
our $VERSION = 1.00;

sub new($) {
	my $class = shift;
	my $client_socket = shift;
	my $self = {};
	bless $self, $class;
	$self->initialize($client_socket);
	return $self;
}

sub initialize($) {
	my $self = shift;
	# we should have been passed a client socket
	$self->{'clientSocket'} = shift;
	$self->{'serverSocket'} = '';
}

sub client(;$) {
	my $self = shift;
	my $clientSocket = shift;
	if (defined $clientSocket) {
		$self->{'clientSocket'} = $clientSocket;
	}
	return $self->{'clientSocket'};
}

sub server(;$) {
	my $self = shift;
	my $serverSocket = shift;
	if (defined $serverSocket) {
		$self->{'serverSocket'} = $serverSocket;
	}
	return $self->{'serverSocket'};
}
