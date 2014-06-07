use strict;
use warnings;

use File::Temp;

my $GPERF_TEMPLATE = <<'END_GPERF';
%define hash-function-name   syscall_hash
%define lookup-function-name syscall_lookup
%define initializer-suffix   ,0
%readonly-tables
%struct-type

%{
#include <asm/unistd.h>

#define MAX_SYSCALL_NO {{MAX_SYSCALL_NO}}

static const char *syscall_names[] = {
{{SYSCALL_NAMES}}
};
%}

struct syscall {
    const char *name;
    int syscall_no;
};
%%
{{KEYWORDS}}
END_GPERF

my $tmpfile  = File::Temp->new(SUFFIX => '.c');
my $filename = $tmpfile->filename;
print {$tmpfile} "#include <asm/unistd.h>\n";
close $tmpfile;

my @defines = qx(gcc -E -dM $filename);
chomp @defines;

my %syscall_to_number = map { /\b__NR_(\w+)\b \s+ (\d+)/x ? ($1, $2) : () } @defines;
my %number_to_syscall = reverse %syscall_to_number;
my @syscalls          = keys %syscall_to_number;
my $max_syscall_no    = (sort { $a <=> $b } keys %number_to_syscall)[-1];

my %template_vars = (
    MAX_SYSCALL_NO => $max_syscall_no,
    SYSCALL_NAMES  => join(",\n", map { exists $number_to_syscall{$_} ? qq{    "$number_to_syscall{$_}"} : '    NULL' } 0 .. $max_syscall_no),
    KEYWORDS       => join("\n", map { "$_, __NR_$_" } @syscalls),
);

$GPERF_TEMPLATE =~ s/\{\{(\w+)\}\}/$template_vars{$1}/ge;

print $GPERF_TEMPLATE;
