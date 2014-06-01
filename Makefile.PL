use 5.008005;
use ExtUtils::MakeMaker;

# XXX check for gperf

sub MY::postamble {
    return <<"END_MAKE";
syscalls.gperf:
	$^X generate-syscalls-gperf.pl > \$@

syscall-hash.h: syscalls.gperf
	gperf --output-file=\$@ \$^
END_MAKE
}

WriteMakefile(
    NAME           => 'Devel::Trace::Syscall',
    VERSION_FROM   => 'lib/Devel/Trace/Syscall.pm',
    PREREQ_PM      => { 'Test::More' => 0 },
    ABSTRACT_FROM  => 'lib/Devel/Trace/Syscall.pm',
    AUTHOR         => 'Rob Hoelz',
    LIBS           => [''],
    DEFINE         => '',
    INC            => '-I.',
    OBJECT         => '$(O_FILES)',
    depend         => {
        'Syscall.o' => 'syscall-hash.h',
    },
);
