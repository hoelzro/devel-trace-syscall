use 5.008005;
use ExtUtils::MakeMaker;

sub MY::postamble {
    return <<"END_MAKE";
syscall-lookup.h:
	$^X generate-syscalls-gperf.pl > \$@
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
    CCFLAGS        => '-Wall -Wextra -Werror',
    depend         => {
        'Syscall.o' => 'syscall-lookup.h',
    },
    clean => {
        FILES => 'syscall-lookup.h',
    },
);
