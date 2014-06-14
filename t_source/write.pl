#!/usr/bin/env perl

use strict;
use warnings;
use feature qw(say);

sub foo {
    say 1;
}

foo();

__DATA__
# args: write

write(1, *, *) = * at write.pl line 7.
    main::foo() called at write.pl line 11
