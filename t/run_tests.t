#!/usr/bin/env perl

use strict;
use warnings;
use autodie;
use feature qw(say);

use FindBin;
use Test::More;
BEGIN {
    my $pkg;

    eval {
        $pkg = 'Test::Differences::Color';
        require Test::Differences::Color;
    } or do {
        $pkg = 'Test::Differences';
        require Test::Differences;
    };

    $pkg->import;
}

my $INDENT         = qr/\s+/;
my $SYSCALL_NAME   = qr/[a-zA-Z_:]+/;
my $SYSCALL_ARGS   = qr/\((?<args>.*)\)/;
my $SYSCALL_RESULT = qr/([-]?\d+)|([*])/;
my $LOCATION       = qr/.*/;

sub capture_trace_output {
    my ( @command ) = @_;

    note('running command: ' . join(' ', @command));

    my ( $read, $write );
    pipe $read, $write;

    my $pid = fork();

    if($pid) {
        close $write;

        my @lines = <$read>;
        chomp @lines;
        close $read;
        waitpid $pid, 0;

        return \@lines;
    } else {
        close $read;
        close STDOUT;
        open STDERR, '>&', $write;

        exec @command;
    }
}

sub parse_args {
    my ( $args ) = @_;

    return [ split /\s*,\s*/, $args ];
}

sub parse_location {
    my ( $location ) = @_;

    if($location eq '(BEGIN)') { # special case for now
        return {
            filename => 'BEGIN',
            line     => 0,
        };
    }

    if($location =~ /^at (?<filename>.*) line (?<line>\d+)[.]?$/) {
        return {
            filename => $+{'filename'},
            line     => $+{'line'},
        };
    } else {
        die "Unable to parse location '$location'";
    }
}

sub parse_events {
    my ( $lines ) = @_;

    my @events;

    foreach my $line (@$lines) {
        if($line =~ /^(?<name>$SYSCALL_NAME) $SYSCALL_ARGS \s+=\s+ (?<result>$SYSCALL_RESULT) \s+ (?<location>$LOCATION)$/x) {
            my ( $name, $args, $result, $location ) = @+{qw/name args result location/};

            push @events, [{
                name       => $name,
                args       => parse_args($args),
                result     => $result,
                location   => parse_location($location),
            }];
        } elsif($line =~ /^$INDENT (?<name>$SYSCALL_NAME) $SYSCALL_ARGS \s+called\s+ (?<location>$LOCATION)$/x) {
            my ( $name, $args, $location ) = @+{qw/name args location/};

            push @{ $events[-1] }, {
                name     => $name,
                args     => parse_args($args),
                location => parse_location($location),
            };
        } elsif($line !~ /^\s*$/) {
            die "Line '$line' did not match a known regex\n";
        }
    }

    return \@events;
}

sub strip_unimportant_events {
    my ( $events ) = @_;

    return [ grep {
        $_->[0]{'name'} ne 'open' || ($_->[0]{'args'}[0] !~ m{/usr/share/} && $_->[0]{'args'}[0] !~ /[.]pm"$/)
    } @$events ];
}

sub read_events_from_data {
    my ( $filename ) = @_;

    my %metadata;
    my $in_data;
    my @lines;
    open my $fh, '<', $filename;

    while(<$fh>) {
        chomp;

        if($_ eq '__DATA__') {
            $in_data = 1;
        } elsif($in_data) {
            if(/^\s*#\s*(?<key>\w+)\s*:\s*(?<value>.*)\s*$/) {
                $metadata{ $+{'key'} } = $+{'value'};
            } else {
                push @lines, $_;
            }
        }
    }

    close $fh;
    return ( \%metadata, parse_events(\@lines) );
}

sub fill_in_wildcards {
    my ( $expected, $got ) = @_;

    for(my $i = 0; $i < @$expected; $i++) {
        my $got      = $got->[$i];
        my $expected = $expected->[$i];

        if($expected->[0]{'result'} eq '*') {
            delete $expected->[0]{'result'};
            delete $got->[0]{'result'};
        }

        for my $frame_no (0 .. $#$expected) {
            my $expected_frame = $expected->[$frame_no];
            my $got_frame      = $got->[$frame_no];

            for my $arg_no (0 .. $#{ $expected_frame->{'args'} }) {
                if($expected_frame->{'args'}[$arg_no] eq '*') {
                    $got_frame->{'args'}[$arg_no] = '*';
                }
            }
        }
    }
}

chdir "$FindBin::Bin/../t_source";
my @test_files = glob("*.pl");

plan tests => scalar(@test_files);

$ENV{'PERL5LIB'} = '../blib/arch:../blib/lib';

foreach my $filename (@test_files) {
    my ( $metadata, $expected_events ) = read_events_from_data($filename);
    my @args         = split(/\s*,\s*/, $metadata->{'args'} || 'open');
    my $output_lines = capture_trace_output($^X, '-d:Trace::Syscall=' . join(',', @args), $filename);
    my $got_events   = parse_events($output_lines);
    $got_events      = strip_unimportant_events($got_events);

    fill_in_wildcards($expected_events, $got_events);

    SKIP: {
        skip "$filename: $metadata->{'skip'}", 1 if $metadata->{'skip'};
        eq_or_diff($got_events, $expected_events, "event streams for $filename should match");
    }
}
