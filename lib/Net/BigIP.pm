package Net::BigIP;

use Mojo::Base -strict, -signatures;

use Carp;
use Mojo::UserAgent;
use Mojo::JSON qw(decode_json);

our $VERSION = '0.2';

sub new {
    my ($class, %params) = @_;

    croak "missing url parameter" unless $params{url};

    my $url   = $params{url};
    my $agent = Mojo::UserAgent->new();

    $agent->timeout($params{timeout})
        if $params{timeout};
    $agent->tls_options($params{ssl_opts})
        if $params{ssl_opts} && ref $params{ssl_opts} eq 'HASH';

    my $self = {
        url   => $url,
        agent => $agent,
        token => $params{token},
    };
    bless $self, $class;

    return $self;
}

sub create_session {
    my ($self, %params) = @_;

    croak "missing username parameter" unless $params{username};
    croak "missing password parameter" unless $params{password};

    my $result = $self->_post(
        "/mgmt/shared/authn/login",
        username          => $params{username},
        password          => $params{password},
        loginProviderName => 'tmos'
    );

    $self->{token} = $result->{token}->{token};

    $self->{agent}->on(start => sub {
        my ($ua, $tx) = @_;
        $tx->req->headers->header('X-F5-Auth-Token' => $self->{token});
    });
}

sub get_token {
    my ($self) = @_;

    return $self->{token};
}

sub get_certificates {
    my ($self, %params) = @_;

    my @parameters;
    if ($params{partition}) {
        push @parameters, '$filter=partition%20eq%20' . $params{partition};
    }
    if ($params{properties}) {
        push @parameters, '$select=' . $params{properties};
    }

    my $url = "/mgmt/tm/sys/file/ssl-cert";
    if (@parameters) {
        $url .= '/?' . join('&', @parameters);
    }

    my $result = $self->_get($url);

    return $result;
}

sub get_virtual_addresses {
    my ($self, %params) = @_;

    my @parameters;
    if ($params{partition}) {
        push @parameters, '$filter=partition%20eq%20' . $params{partition};
    }
    if ($params{properties}) {
        push @parameters, '$select=' . $params{properties};
    }

    my $url = "/mgmt/tm/ltm/virtual-address";
    if (@parameters) {
        $url .= '/?' . join('&', @parameters);
    }

    my $result = $self->_get($url);

    return $result;
}

sub get_virtual_servers {
    my ($self, %params) = @_;

    my @parameters;
    if ($params{partition}) {
        push @parameters, '$filter=partition%20eq%20' . $params{partition};
    }
    if ($params{properties}) {
        push @parameters, '$select=' . $params{properties};
    }
    if ($params{expandSubcollections}) {
        push @parameters, 'expandSubcollections=' . $params{expandSubcollections};
    }

    my $url = "/mgmt/tm/ltm/virtual";
    if (@parameters) {
        $url .= '/?' . join('&', @parameters);
    }

    my $result = $self->_get($url);

    return $result;
}

sub get_virtual_server_policies {
    my ($self, %params) = @_;

    croak "missing virtual_server parameter" unless $params{virtual_server};

    my @parameters;
    if ($params{partition}) {
        push @parameters, '$filter=partition%20eq%20' . $params{partition};
    }
    if ($params{properties}) {
        push @parameters, '$select=' . $params{properties};
    }
    if ($params{expandSubcollections}) {
        push @parameters, 'expandSubcollections=' . $params{expandSubcollections};
    }

    my $url = "/mgmt/tm/ltm/virtual/$params{virtual_server}/policies";
    if (@parameters) {
        $url .= '/?' . join('&', @parameters);
    }

    my $result = $self->_get($url);

    return $result;
}

sub get_policy_rules {
    my ($self, %params) = @_;

    croak "missing policy parameter" unless $params{policy};

    my @parameters;
    if ($params{partition}) {
        push @parameters, '$filter=partition%20eq%20' . $params{partition};
    }
    if ($params{properties}) {
        push @parameters, '$select=' . $params{properties};
    }
    if ($params{expandSubcollections}) {
        push @parameters, 'expandSubcollections=' . $params{expandSubcollections};
    }

    my $url = "/mgmt/tm/ltm/policy/$params{policy}/rules";
    if (@parameters) {
        $url .= '/?' . join('&', @parameters);
    }

    my $result = $self->_get($url);

    return $result;
}

sub get_pools {
    my ($self, %params) = @_;

    my @parameters;
    if ($params{partition}) {
        push @parameters, '$filter=partition%20eq%20' . $params{partition};
    }
    if ($params{properties}) {
        push @parameters, '$select=' . $params{properties};
    }

    my $url = "/mgmt/tm/ltm/pool";
    if (@parameters) {
        $url .= '/?' . join('&', @parameters);
    }

    my $result = $self->_get($url);

    return $result;
}

sub get_pool_members {
    my ($self, %params) = @_;

    croak "missing pool parameter" unless $params{pool};

    my @parameters;
    if ($params{partition}) {
        push @parameters, '$filter=partition%20eq%20' . $params{partition};
    }
    if ($params{properties}) {
        push @parameters, '$select=' . $params{properties};
    }

    my $url = "/mgmt/tm/ltm/pool/$params{pool}/members";
    if (@parameters) {
        $url .= '/?' . join('&', @parameters);
    }

    my $result = $self->_get($url);

    return $result;
}

sub get_pool_member_stats {
    my ($self, %params) = @_;

    croak "missing pool parameter" unless $params{pool};

    my @parameters;
    if ($params{partition}) {
        push @parameters, '$filter=partition%20eq%20' . $params{partition};
    }
    if ($params{properties}) {
        push @parameters, '$select=' . $params{properties};
    }

    my $url = "/mgmt/tm/ltm/pool/$params{pool}/members/stats";
    if (@parameters) {
        $url .= '/?' . join('&', @parameters);
    }

    my $result = $self->_get($url);

    return $result;
}

sub get_pool_stats {
    my ($self, %params) = @_;

    my @parameters;
    if ($params{partition}) {
        push @parameters, '$filter=partition%20eq%20' . $params{partition};
    }
    if ($params{properties}) {
        push @parameters, '$select=' . $params{properties};
    }

    my $url = "/mgmt/tm/ltm/pool/stats";
    if (@parameters) {
        $url .= '/?' . join('&', @parameters);
    }

    my $result = $self->_get($url);

    return $result;
}

sub get_nodes {
    my ($self, %params) = @_;

    my @parameters;
    if ($params{partition}) {
        push @parameters, '$filter=partition%20eq%20' . $params{partition};
    }
    if ($params{properties}) {
        push @parameters, '$select=' . $params{properties};
    }

    my $url = "/mgmt/tm/ltm/node";
    if (@parameters) {
        $url .= '/?' . join('&', @parameters);
    }

    my $result = $self->_get($url);

    return $result;
}

sub get_node_stats {
    my ($self, %params) = @_;

    my @parameters;
    if ($params{partition}) {
        push @parameters, '$filter=partition%20eq%20' . $params{partition};
    }
    if ($params{properties}) {
        push @parameters, '$select=' . $params{properties};
    }

    my $url = "/mgmt/tm/ltm/node/stats";
    if (@parameters) {
        $url .= '/?' . join('&', @parameters);
    }

    my $result = $self->_get($url);

    return $result;
}

sub _post {
    my ($self, $path, %params) = @_;

    my $tx = $self->{agent}->post($self->{url} . $path => json => \%params);

    my $result = $tx->result();

    my $content = decode_json($result->body());

    if ($result->is_success()) {
        return $content;
    } else {
        if ($content) {
            croak "server error: " . $content->{message};
        } else {
            croak "communication error: " . $result->message()
        }
    }
}

sub _get {
    my ($self, $path, %params) = @_;

    my $tx = $self->{agent}->get( $self->{url} . $path => form => \%params);

    my $result = $tx->result();

    my $content = decode_json($result->body());

    if ($result->is_success()) {
        return $content;
    } else {
        if ($content) {
            croak "server error: " . $content->{message};
        } else {
            croak "communication error: " . $result->message()
        }
    }
}

1;
__END__

=head1 NAME

Net::BigIP - REST interface for BigIP

=head1 DESCRIPTION

This module provides a Perl interface for communication with BigIP load-balancer
using REST interface.

=head1 SYNOPSIS

    use Net::BigIP;

    my $bigip = Net::BigIP->new(
        url => 'https://my.bigip.tld'
    ):
    $bigip->create_session(
        username => 'user',
        password => 's3cr3t',
    );
    my $certs = $bigip->get_certs();

=head1 CLASS METHODS

=head2 Net::BigIP->new(url => $url, [ssl_opts => $opts, timeout => $timeout, token => $token])

Creates a new L<Net::BigIP> instance.

=head1 INSTANCE METHODS

=head2 $bigip->create_session(username => $username, password => $password)

Creates a new session token for the given user.

=head2 $bigip->get_token()

Return the current session token.

=head2 $bigip->get_certificates([ partition => $partition, properties => $properties ])

Return the list of certificates.

Available parameters:

=over

=item partition => $partition

Filter objects list to given partition.

=item properties => $properties

Filter objects properties to the given ones, as a comma-separated list.

=back

=head2 $bigip->get_virtual_addresses([ partition => $partition, properties => $properties ])

Return the list of virtual addresses.

Available parameters:

=over

=item partition => $partition

Filter objects list to given partition.

=item properties => $properties

Filter objects properties to the given ones, as a comma-separated list.

=back

=head2 $bigip->get_virtual_servers([ partition => $partition, properties => $properties ])

Return the list of virtual servers.

Available parameters:

=over

=item partition => $partition

Filter objects list to given partition.

=item properties => $properties

Filter objects properties to the given ones, as a comma-separated list.

=back

=head2 $bigip->get_pools([ partition => $partition, properties => $properties ])

Return the list of pools.

Available parameters:

=over

=item partition => $partition

Filter objects list to given partition.

=item properties => $properties

Filter objects properties to the given ones, as a comma-separated list.

=back

=head2 $bigip->get_nodes(%parameters)

Return the list of nodes.

Available parameters:

=over

=item partition => $partition

Filter objects list to given partition.

=item properties => $properties

Filter objects properties to the given ones, as a comma-separated list.

=back

=head2 $bigip->get_node_stats(%parameters)

Return statistics for the nodes.

Available parameters:

=over

=item partition => $partition

Filter objects list to given partition.

=item properties => $properties

Filter objects properties to the given ones, as a comma-separated list.

=back

=head2 $bigip->get_policy_rules(%parameters)

Return the list of rules for the given policy.

Available parameters:

=over

=item policy => $policy

The policy (mandatory).

=item partition => $partition

Filter objects list to given partition.

=item properties => $properties

Filter objects properties to the given ones, as a comma-separated list.

=item expand_subcollection => $boolean

Wether to expand subcollections or not.

=back

=head2 $bigip->get_virtual_server_policies(%parameters)

Return the list of policies for the given virtual server.

Available parameters:

=over

=item virtual_server => $virtual_server

The virtual server (mandatory).

=item partition => $partition

Filter objects list to given partition.

=item properties => $properties

Filter objects properties to the given ones, as a comma-separated list.

=item expand_subcollection => $boolean

Wether to expand subcollections or not.

=back

=head2 $bigip->get_pool_members(%parameters)

Return the list of members for the given pool.

Available parameters:

=over

=item pool => $pool

The pool (mandatory).

=item partition => $partition

Filter objects list to given partition.

=item properties => $properties

Filter objects properties to the given ones, as a comma-separated list.

=back

=head2 $bigip->get_pool_member_stats(%parameters)

Return statistics for the given pool members:.

Available parameters:

=over

=item pool => $pool

The pool (mandatory).

=item partition => $partition

Filter objects list to given partition.

=item properties => $properties

Filter objects properties to the given ones, as a comma-separated list.

=back

=head2 $bigip->get_pool_stats(%parameters)

Return statistics for the pools.

Available parameters:

=over

=item partition => $partition

Filter objects list to given partition.

=item properties => $properties

Filter objects properties to the given ones, as a comma-separated list.

=back

=head1 LICENSE

You can use and distribute this module under the same terms as Perl itself.
See the C<LICENSE> file included in this distribution for complete
details.
