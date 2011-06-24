package App::locket;
BEGIN {
  $App::locket::VERSION = '0.0013';
}
# ABSTRACT: Copy secrets from a YAML/JSON cipherstore into the clipboard (pbcopy, xsel, xclip)

use strict;
use warnings;

use Any::Moose;

use File::HomeDir;
use Path::Class;
use Term::ReadKey;
use JSON; my $JSON = JSON->new->pretty;
use YAML::XS();
use File::Temp;
use Term::EditorEdit;
use Try::Tiny;
my $usage;
BEGIN {
$usage = <<_END_;

    Usage: locket [options] setup|edit|<query>

        --copy              Copy value to clipboard using pbcopy, xsel, or xclip

        --delay <delay>     Keep value in clipboard for <delay> seconds
                            If value is still in the clipboard at the end of
                            <delay> then it will be automatically wiped from
                            the clipboard

        --cfg <file>        Use <file> for configuration

        setup               Setup a new or edit an existing user configuration
                            file (~/.locket/cfg)

        edit                Edit the cipherstore
                            The configuration must have an "edit" value, e.g.:

                                /usr/bin/vim -n ~/.locket.gpg

        <query>             Search the cipherstore for <query> and emit the
                            resulting secret
                            
                            The configuration must have a "read" value to
                            tell it how to read the cipherstore. Only piped
                            commands are supported today, and they should
                            be something like:

                                </usr/local/bin/gpg -q --no-tty -d ~/.locket.gpg'

                            If the found key in the cipherstore is of the format
                            "<username>@<site>" then the username will be emitted
                            first before the secret (which is assumed to be a password/passphrase)

        Example YAML cipherstore:

            %YAML 1.1
            ---
            # A GMail identity
            alice\@gmail: p455w0rd
            # Some frequently used credit card information
            cc4123: |
                4123412341234123
                01/23
                123

_END_
}
use Getopt::Usaginator $usage;

END {
    ReadMode 0;
}

BEGIN {
    # Safe path
    $ENV{ PATH } = '/bin:/usr/bin:/usr/local/bin';
}

my %default_options = (
    delay => 45,
);

has home => qw/ is ro lazy_build 1 /;
sub _build_home {
    my $self = shift;
    my $home = File::HomeDir->my_data;
    if ( defined $home ) {
        $home = dir $home, '.locket';
    }
    return $home;
}

has cfg_file => qw/ is ro lazy_build 1 /;
sub _build_cfg_file {
    my $self = shift;
    if ( defined ( my $file = $self->argument_options->{ cfg } ) ) {
        return file $file;
    }
    my $home = $self->home;
    return unless $home;
    return $home->file( 'cfg' );
}

has cfg => qw/ reader cfg writer _cfg isa HashRef lazy_build 1 /;
sub _build_cfg {
    my $self = shift;
    return $self->load_cfg;
}

sub read_cfg {
    my $self = shift;
    return unless my $cfg_file = $self->cfg_file;
    return unless -f $cfg_file && -r $cfg_file;
    return scalar $cfg_file->slurp;
}

sub load_cfg {
    my $self = shift;
    return {} unless defined ( my $cfg_content = $self->read_cfg );
    my $cfg = YAML::XS::Load( $cfg_content );
    return $cfg;
}

sub reload_cfg {
    my $self = shift;
    $self->_cfg( $self->load_cfg );
}

has argument_options => qw/ is ro lazy_build 1 /;
sub _build_argument_options {
    return {};
}

has options => qw/ is ro lazy_build 1 /;
sub _build_options {
    my $self = shift;

    my $cfg = $self->cfg;
    my @options;
    defined $cfg->{ $_ } && length $cfg->{ $_ } and push @options, $_ => $cfg->{ $_ } for qw/ delay /;

    my %argument_options = %{ $self->argument_options };

    return { %default_options, @options, %argument_options };
}

sub dispatch {
    my $self = shift;
    my @arguments = @_;

    my $options = $self->argument_options;
    my ( $help );
    Getopt::Usaginator->parse( \@arguments,
        'copy' => \$options->{ copy },
        'delay=s' => \$options->{ delay },
        'help|h' => \$help,
        'cfg|config=s' => \$options->{ cfg },
    );
    $options = $self->options;

    if ( ! @arguments ) {
        my $cfg_file = $self->cfg_file;
        my $cfg_file_size = -f $cfg_file && -s _;
        defined && length or $_ = '-1' for $cfg_file_size;
        my ( $read, $edit ) = map { defined $_ ? $_ : '-' } @{ $self->cfg }{qw/ read edit /};

        $self->stdout( <<_END_ );
App::locket @{[ $App::locket::VERSION || '0.0' ]}

    $cfg_file ($cfg_file_size)

      Read cipherstore: $read
      Edit cipherstore: $edit

_END_
    }
    else {

        usage 0 if $help || $arguments[ 0 ] eq 'help';

        $options->{ delay } ||= 0;
        if ( $options->{ delay } !~ m/^\d+$/ ) {
            die "*** Invalid delay value ($options->{ delay })";
        }

        my $_0 = shift @arguments;
        if ( $_0 eq 'setup' || $_0 eq 'cfg' || $_0 eq 'config' ) {

            my $cfg_file = $self->cfg_file;
            my $cfg_content;
            $cfg_content = $self->read_cfg if -s $cfg_file;
            if ( ! defined $cfg_content || $cfg_content !~ m/\S/ ) {
                $cfg_content = <<_END_;
%YAML 1.1
---
#read: '</usr/bin/gpg -d <file>'
#read: '</usr/bin/openssl des3 -d -in <file>'
#edit: '/usr/bin/vim -n <file>'
_END_
            }
            my $file = File::Temp->new( template => '.locket.cfg.XXXXXXX', dir => '.', unlink => 0 ); # TODO A better dir?
            my $edit = Term::EditorEdit->edit( file => $file, document => $cfg_content );
            $cfg_file->parent->mkpath;
            if ( -s $file->filename ) {
                rename $file->filename, $cfg_file or die "*** Unable to overwrite $cfg_file: $!";
            }
        }
        elsif ( $_0 eq 'edit' ) {
            my $edit = $self->cfg->{ edit };
            if ( defined $edit && length $edit ) {
                system( $edit );
            }
            else {
                $self->stderr( "% Missing (edit) in cfg" );
            }
        }
        else {
            my $read = $self->cfg->{ read };
            my $store;
            if ( $read =~ m/^\s*[|<]/ ) {
                ( my $pipe = $read ) =~ s/^\s*[|<]//;
                open my $cipher, '-|', $pipe;
                my $plaintext_store = join '', <$cipher>;
                try {
                    if ( $plaintext_store =~ m/^\s*\{/ )
                            { $store = $JSON->decode( $plaintext_store ) }
                    else    { $store = YAML::XS::Load( "$plaintext_store\n" ) }
                };
                if ( ! $store ) {
                    die "*** Unable to read store";
                }
            }
            else {
                die "*** Invalid read ($read)";
            }

            my $target = $_0;
            $target =~ s/^\///;
            my @found = ( $store->{ $target } );

            if ( !length $target ) {
                @found = sort keys %$store;
            }
            elsif ( defined $store->{ $target } ) {
                @found = ( $target );
            }
            else {
                @found = sort grep { m/\Q$target\E/ } keys %$store;
            }

            if ( 1 == @found ) {
                my $found = $found[0];
                my $secret = $store->{ $found };
                if ( $found =~ m/^([^@]+)@/ ) {
                    $self->emit_username_password( $1, $secret );
                }
                else {
                    $self->emit_secret( $secret );
                }
            }
            elsif ( 0 == @found ) {
                $self->stdout( "# No matches for \"$target\"" );
            }
            else {
                $self->stdout( "# Found for \"$target\":" ) if length $target;
                $self->stdout( "    $_" ) for @found;
            }
        }
    }
}

sub copy {
    my $self = shift;
    my $name = shift;
    my $value = shift;

    my $SIG_INT = $SIG{ INT } || sub { exit 0 };
    local $SIG{ INT } = sub {
        $self->_copy( '' );
        ReadMode 0;
        $SIG_INT->();
    };

    my $delay = $self->options->{ delay };
    if ( $delay ) {
        $self->stdout( sprintf "# Copied ($name) into clipboard with %d:%02d delay", int( $delay / 60 ), $delay % 60 );
    }
    else {
        $self->stdout( "# Copied ($name) into clipboard for NO delay" );
    }
    $self->stdout( "# Press ENTER to continue (clipboard will be wiped)" );
    $self->_copy( $value );
    ReadMode 2; # Disable keypress echo
    while ( 1 ) {
        my $continue = ReadKey $delay;
        chomp $continue;
        last unless length $continue;
    }
    ReadMode 0;
    my $paste = $self->_paste;
    if ( ! defined $paste || $paste eq $value ) {
        # To be safe, we wipe out the clipboard in the case where
        # we were unable to get a read on the clipboard (pbpaste, xsel, or
        # xclip failed)
        $self->_copy( '' ); # Wipe out clipboard
    }
}

sub _find_cmd {
    my $self = shift;
    my $name = shift;

    for (qw{ /bin /usr/bin /usr/local/bin }) {
        my $cmd = file split( '/', $_ ), $name;
        return $cmd if -f $cmd && -x $cmd;
    }

    return undef;
}

sub _copy {
    my $self = shift;
    my $value = shift;

    if ( lc $^O eq 'darwin' ) {
        return $self->_try_pbcopy( $value );
    }
    else {
        return 1 if $self->_try_xsel_copy( $value );
        return $self->_try_xclip_copy( $value );
    }
}

sub _pipe_into {
    my $self = shift;
    my $cmd = shift;
    my $value = shift;

    open my $pipe, '|-', $cmd or die $!;
    $pipe->print( $value );
    close $pipe;
}

sub _try_pbcopy {
    my $self = shift;
    my $value = shift;

    return unless my $pbcopy = $self->_find_cmd( 'pbcopy' );
    $self->_pipe_into( $pbcopy => $value );
    return 1;
}

sub _try_xsel_copy {
    my $self = shift;
    my $value = shift;

    return unless my $xsel = $self->_find_cmd( 'xsel' );
    $self->_pipe_into( $xsel => $value );
    return 1;
}

sub _try_xclip_copy {
    my $self = shift;
    my $value = shift;

    return unless my $xclip = $self->_find_cmd( 'xclip' );
    $self->_pipe_into( "$xclip -i" => $value );
    return 1;
}

sub _paste {
    my $self = shift;

    if ( lc $^O eq 'darwin' ) {
        return $self->_try_pbpaste;
    }
    else {
        my $value;
        $value = $self->_try_xsel_paste( $value );
        return $value if defined $value;
        return $self->_try_xclip_paste( $value );
    }
}

sub _pipe_outfrom {
    my $self = shift;
    my $cmd = shift;
    my $value = shift;

    open my $pipe, '-|', $cmd or die $!;
    return join '', <$pipe>;
}

sub _try_pbpaste {
    my $self = shift;
    my $value = shift;

    return unless my $pbpaste = $self->_find_cmd( 'pbpaste' );
    return $self->_pipe_outfrom( $pbpaste );
}

sub _try_xsel_paste {
    my $self = shift;

    return unless my $xsel = $self->_find_cmd( 'xsel' );
    return $self->_pipe_outfrom( $xsel );
}

sub _try_xclip_paste {
    my $self = shift;
    my $value = shift;

    return unless my $xclip = $self->_find_cmd( 'xclip' );
    return $self->_pipe_outfrom( $xclip );
}

sub emit_username_password {
    my $self = shift;
    my ( $username, $password ) = @_;

    if ( $self->options->{ copy } ) {
        $self->copy( username => $username );
        $self->copy( password => $password );
    }
    else {
        $self->stdout( <<_END_ );
$username
$password
_END_
    }
}

sub emit_secret {
    my $self = shift;
    my ( $secret ) = @_;

    if ( $self->options->{ copy } ) {
        $self->copy( secret => $secret );
    }
    else {
        $self->stdout( $secret, "\n" );
    }
}

sub stdout {
    my $self = shift;
    my $emit = join '', @_;
    chomp $emit;
    print STDOUT $emit, "\n";
}

sub stderr {
    my $self = shift;
    my $emit = join '', @_;
    chomp $emit;
    print STDERR $emit, "\n";
}

1;



=pod

=head1 NAME

App::locket - Copy secrets from a YAML/JSON cipherstore into the clipboard (pbcopy, xsel, xclip)

=head1 VERSION

version 0.0013

=head1 SYNOPSIS

    # Setup the configuration file for the cipherstore:
    # (How to read the cipherstore, how to edit the cipherstore, etc.)
    $ locket setup

    # Add or change data in the cipherstore:
    $ locket edit

    # List all the entries in the cipherstore:
    $ locket /

    # Show a secret from the cipherstore:
    $ locket /alice@gmail

    # Copy an entry from the cipherstore into the clipboard:
    # (The clipboard will be purged after 10 seconds)
    $ locket --copy --delay 10 /alice@gmail

=head1 DESCRIPTION

App::locket is a tool for querying a simple YAML/JSON-based cipherstore 

It has a simple commandline-based querying method and supports copying into the clipboard 

Currently, encryption and decryption is performed via external tools (e.g. GnuPG, OpenSSL, etc.)

App::locket is best used with:

* gnupg.vim L<http://www.vim.org/scripts/script.php?script_id=661>

* openssl.vim L<http://www.vim.org/scripts/script.php?script_id=2012>

* EasyPG L<http://www.emacswiki.org/emacs/AutoEncryption>

=head1 SECURITY

=head2 Encryption/decryption algorithm

App::locket defers actual encryption/decryption to external tools. The choice of the actual
cipher/encryption method is left up to you

If you're using GnuPG, then you could use C<gpg-agent> for passphrase prompting and limited retention

=head2 In-memory encryption

App::locket does not perform any in-memory encryption; once the cipherstore is loaded it is exposed in memory

In addition, if the process is swapped out while running then the plaintextstore could be written to disk

Encrypting swap is one way of mitigating this problem (secure virtual memory)

=head2 Clipboard access

App::locket uses third-party tools for read/write access to the clipboard. It tries to detect if
pbcopy, xsel, or xclip are available. It does this by looking in /bin, /usr/bin, and /usr/local/bin (in that order)

It will NOT search $PATH

=head2 Purging the clipboard

By default, App::locket will purge the clipboard of a secret it put there after a set delay. It will try to verify that it is
wiping what it put there in the first place (so it doesn't accidentally erase something else you copied)

If for some reason App::locket cannot read from the clipboard, it will purge it just in case

If you prematurely cancel a secret copying operation via CTRL-C, App::locket will catch the signal and purge the clipboard first

=head1 INSTALL

    $ cpanm -i App::locket

=head1 INSTALL cpanm

L<http://search.cpan.org/perldoc?App::cpanminus#INSTALLATION> 

=head1 USAGE

    locket [options] setup|edit|<query>

        --copy              Copy value to clipboard using pbcopy, xsel, or xclip

        --delay <delay>     Keep value in clipboard for <delay> seconds
                            If value is still in the clipboard at the end of
                            <delay> then it will be automatically wiped from
                            the clipboard

        setup               Setup a new or edit an existing user configuration
                            file (~/.locket/cfg)

        edit                Edit the cipherstore
                            The configuration must have an "edit" value, e.g.:

                                /usr/bin/vim -n ~/.locket.gpg


        <query>             Search the cipherstore for <query> and emit the
                            resulting secret
                            
                            The configuration must have a "read" value to
                            tell it how to read the cipherstore. Only piped
                            commands are supported today, and they should
                            be something like:

                                </usr/local/bin/gpg -q --no-tty -d ~/.locket.gpg'

                            If the found key in the cipherstore is of the format
                            "<username>@<site>" then the username will be emitted
                            first before the secret (which is assumed to be a password/passphrase)

=head1 Example YAML cipherstore

    %YAML 1.1
    ---
    # A GMail identity
    alice@gmail: p455w0rd
    # Some frequently used credit card information
    cc4123: |
        4123412341234123
        01/23
        123

=head1 Example configuration file

    %YAML 1.1
    ---
    read: '</usr/local/bin/gpg --no-tty --decrypt --quiet ~/.locket.gpg'
    edit: '/usr/bin/vim -n ~/.locket.gpg'

=head1 AUTHOR

Robert Krimen <robertkrimen@gmail.com>

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2011 by Robert Krimen.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut


__END__

