#!/usr/bin/env perl

use strict;
use warnings;
use feature qw(say);

sub baz {
    open my $fh, '>', '/dev/null';

    say {$fh} 'hello';

    close $fh;
}

sub bar {
    baz();
}

sub foo {
    bar();
}

say 'before';
foo();
say 'after';
foo();
say 'end';
