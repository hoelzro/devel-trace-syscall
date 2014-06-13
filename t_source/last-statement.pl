#!/usr/bin/env perl

use strict;
use warnings;
use feature qw(say);

print -T '/dev/null';

__DATA__
# skip: known issue; not fixed yet
open("/dev/null", 0x0, 0666) = * at last-statement.pl line 7.
