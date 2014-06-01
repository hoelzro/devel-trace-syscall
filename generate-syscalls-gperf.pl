use strict;
use warnings;

use File::Temp;

my $GPERF_PREAMBLE = <<'END_GPERF';
%define hash-function-name   syscall_hash
%define lookup-function-name syscall_lookup
%readonly-tables
%struct-type

%{
#include <asm/unistd.h>
%}

struct syscall {
    const char *name;
    int syscall_no;
};
%%
END_GPERF

my $tmpfile  = File::Temp->new(SUFFIX => '.c');
my $filename = $tmpfile->filename;
print {$tmpfile} "#include <asm/unistd.h>\n";
close $tmpfile;

my @defines = qx(gcc -E -dM $filename);
chomp @defines;

my @syscalls = map { /\b__NR_(\w+)\b/ ? $1 : () } @defines;

print $GPERF_PREAMBLE;
for my $syscall (@syscalls) {
    print "$syscall, __NR_$syscall\n";
}
