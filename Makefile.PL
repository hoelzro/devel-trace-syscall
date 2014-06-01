 use 5.008005;
use ExtUtils::MakeMaker;
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
);
