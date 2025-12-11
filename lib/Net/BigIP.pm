package Net::BigIP;

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

=head1 LICENSE

You can use and distribute this module under the same terms as Perl itself.
See the C<LICENSE> file included in this distribution for complete
details.

=cut

use Mojo::Base -strict, -signatures;

use Carp;
use Mojo::UserAgent;
use Mojo::JSON qw(decode_json);
use Moo;
use Types::Standard qw(Str Int HashRef);

our $VERSION = '0.3';

=head1 CLASS METHODS

=head2 Net::BigIP->new(url => $url, [ssl_opts => $opts, timeout => $timeout, token => $token])

Creates a new L<Net::BigIP> instance.

=cut

has url => (
    is       => 'ro',
    isa      => Str,
    required => 1,
);

has token => (
    is  => 'rwp',
    isa => Str,
);

has timeout => (
    is  => 'ro',
    isa => Int
);

has ssl_opts => (
    is  => 'ro',
    isa => HashRef
);

has ua => (
    is => 'lazy',
);

sub _build_ua($self) {
    return Mojo::UserAgent->new(
        tls_options     => $self->ssl_opts(),
        connect_timeout => $self->timeout(),
        request_timeout => $self->timeout(),
    );
}

=head1 INSTANCE METHODS

=head2 $bigip->create_session(username => $username, password => $password)

Creates a new session token for the given user.

=cut

sub create_session($self, %args) {

    croak "missing username parameter" unless $args{username};
    croak "missing password parameter" unless $args{password};

    my $result = $self->_post(
        "/mgmt/shared/authn/login",
        username          => $args{username},
        password          => $args{password},
        loginProviderName => 'tmos'
    );

    $self->_set_token($result->{token}->{token});

    $self->ua()->on(start => sub {
        my ($ua, $tx) = @_;
        $tx->req->headers->header('X-F5-Auth-Token' => $self->token());
    });
}

=head2 $bigip->get_certificates([ partition => $partition, properties => $properties ])

Return the list of certificates.

Available parameters:

=over

=item partition => $partition

Filter objects list to given partition.

=item properties => $properties

Filter objects properties to the given ones, as a comma-separated list.

=back

=cut

sub get_certificates($self, %args) {

    my @parameters;
    if ($args{partition}) {
        push @parameters, '$filter=partition%20eq%20' . $args{partition};
    }
    if ($args{properties}) {
        push @parameters, '$select=' . $args{properties};
    }

    my $url = "/mgmt/tm/sys/file/ssl-cert";
    if (@parameters) {
        $url .= '/?' . join('&', @parameters);
    }

    my $result = $self->_get($url);

    return $result;
}

=head2 $bigip->get_virtual_addresses([ partition => $partition, properties => $properties ])

Return the list of virtual addresses.

Available parameters:

=over

=item partition => $partition

Filter objects list to given partition.

=item properties => $properties

Filter objects properties to the given ones, as a comma-separated list.

=back

=cut

sub get_virtual_addresses($self, %args) {

    my @parameters;
    if ($args{partition}) {
        push @parameters, '$filter=partition%20eq%20' . $args{partition};
    }
    if ($args{properties}) {
        push @parameters, '$select=' . $args{properties};
    }

    my $url = "/mgmt/tm/ltm/virtual-address";
    if (@parameters) {
        $url .= '/?' . join('&', @parameters);
    }

    my $result = $self->_get($url);

    return $result;
}

=head2 $bigip->get_virtual_servers([ partition => $partition, properties => $properties ])

Return the list of virtual servers.

Available parameters:

=over

=item partition => $partition

Filter objects list to given partition.

=item properties => $properties

Filter objects properties to the given ones, as a comma-separated list.

=back

=cut

sub get_virtual_servers($self, %args) {

    my @parameters;
    if ($args{partition}) {
        push @parameters, '$filter=partition%20eq%20' . $args{partition};
    }
    if ($args{properties}) {
        push @parameters, '$select=' . $args{properties};
    }
    if ($args{expandSubcollections}) {
        push @parameters, 'expandSubcollections=' . $args{expandSubcollections};
    }

    my $url = "/mgmt/tm/ltm/virtual";
    if (@parameters) {
        $url .= '/?' . join('&', @parameters);
    }

    my $result = $self->_get($url);

    return $result;
}

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

=cut

sub get_virtual_server_policies($self, %args) {

    croak "missing virtual_server parameter" unless $args{virtual_server};

    my @parameters;
    if ($args{partition}) {
        push @parameters, '$filter=partition%20eq%20' . $args{partition};
    }
    if ($args{properties}) {
        push @parameters, '$select=' . $args{properties};
    }
    if ($args{expandSubcollections}) {
        push @parameters, 'expandSubcollections=' . $args{expandSubcollections};
    }

    my $url = "/mgmt/tm/ltm/virtual/$args{virtual_server}/policies";
    if (@parameters) {
        $url .= '/?' . join('&', @parameters);
    }

    my $result = $self->_get($url);

    return $result;
}

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

=cut

sub get_policy_rules($self, %args) {

    croak "missing policy parameter" unless $args{policy};

    my @parameters;
    if ($args{partition}) {
        push @parameters, '$filter=partition%20eq%20' . $args{partition};
    }
    if ($args{properties}) {
        push @parameters, '$select=' . $args{properties};
    }
    if ($args{expandSubcollections}) {
        push @parameters, 'expandSubcollections=' . $args{expandSubcollections};
    }

    my $url = "/mgmt/tm/ltm/policy/$args{policy}/rules";
    if (@parameters) {
        $url .= '/?' . join('&', @parameters);
    }

    my $result = $self->_get($url);

    return $result;
}

=head2 $bigip->get_pools([ partition => $partition, properties => $properties ])

Return the list of pools.

Available parameters:

=over

=item partition => $partition

Filter objects list to given partition.

=item properties => $properties

Filter objects properties to the given ones, as a comma-separated list.

=back

=cut

sub get_pools($self, %args) {

    my @parameters;
    if ($args{partition}) {
        push @parameters, '$filter=partition%20eq%20' . $args{partition};
    }
    if ($args{properties}) {
        push @parameters, '$select=' . $args{properties};
    }

    my $url = "/mgmt/tm/ltm/pool";
    if (@parameters) {
        $url .= '/?' . join('&', @parameters);
    }

    my $result = $self->_get($url);

    return $result;
}

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

=cut

sub get_pool_members($self, %args) {

    croak "missing pool parameter" unless $args{pool};

    my @parameters;
    if ($args{partition}) {
        push @parameters, '$filter=partition%20eq%20' . $args{partition};
    }
    if ($args{properties}) {
        push @parameters, '$select=' . $args{properties};
    }

    my $url = "/mgmt/tm/ltm/pool/$args{pool}/members";
    if (@parameters) {
        $url .= '/?' . join('&', @parameters);
    }

    my $result = $self->_get($url);

    return $result;
}

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

=cut

sub get_pool_member_stats($self, %args) {

    croak "missing pool parameter" unless $args{pool};

    my @parameters;
    if ($args{partition}) {
        push @parameters, '$filter=partition%20eq%20' . $args{partition};
    }
    if ($args{properties}) {
        push @parameters, '$select=' . $args{properties};
    }

    my $url = "/mgmt/tm/ltm/pool/$args{pool}/members/stats";
    if (@parameters) {
        $url .= '/?' . join('&', @parameters);
    }

    my $result = $self->_get($url);

    return $result;
}

=head2 $bigip->get_pool_stats(%parameters)

Return statistics for the pools.

Available parameters:

=over

=item partition => $partition

Filter objects list to given partition.

=item properties => $properties

Filter objects properties to the given ones, as a comma-separated list.

=back

=cut

sub get_pool_stats($self, %args) {

    my @parameters;
    if ($args{partition}) {
        push @parameters, '$filter=partition%20eq%20' . $args{partition};
    }
    if ($args{properties}) {
        push @parameters, '$select=' . $args{properties};
    }

    my $url = "/mgmt/tm/ltm/pool/stats";
    if (@parameters) {
        $url .= '/?' . join('&', @parameters);
    }

    my $result = $self->_get($url);

    return $result;
}

=head2 $bigip->get_nodes(%parameters)

Return the list of nodes.

Available parameters:

=over

=item partition => $partition

Filter objects list to given partition.

=item properties => $properties

Filter objects properties to the given ones, as a comma-separated list.

=back

=cut

sub get_nodes($self, %args) {

    my @parameters;
    if ($args{partition}) {
        push @parameters, '$filter=partition%20eq%20' . $args{partition};
    }
    if ($args{properties}) {
        push @parameters, '$select=' . $args{properties};
    }

    my $url = "/mgmt/tm/ltm/node";
    if (@parameters) {
        $url .= '/?' . join('&', @parameters);
    }

    my $result = $self->_get($url);

    return $result;
}

=head2 $bigip->get_node_stats(%parameters)

Return statistics for the nodes.

Available parameters:

=over

=item partition => $partition

Filter objects list to given partition.

=item properties => $properties

Filter objects properties to the given ones, as a comma-separated list.

=back

=cut

sub get_node_stats($self, %args) {

    my @parameters;
    if ($args{partition}) {
        push @parameters, '$filter=partition%20eq%20' . $args{partition};
    }
    if ($args{properties}) {
        push @parameters, '$select=' . $args{properties};
    }

    my $url = "/mgmt/tm/ltm/node/stats";
    if (@parameters) {
        $url .= '/?' . join('&', @parameters);
    }

    my $result = $self->_get($url);

    return $result;
}

sub _post($self, $path, %args) {

    my $tx = $self->ua()->post($self->{url} . $path => json => \%args);

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

sub _get($self, $path, %args) {

    my $tx = $self->ua()->get($self->{url} . $path => form => \%args);

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
