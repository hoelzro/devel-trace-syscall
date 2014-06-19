use 5.008005;
use ExtUtils::MakeMaker;
use Config;

sub MY::postamble {
    return <<"END_MAKE";
syscall-lookup.h:
	$^X generate-syscalls-gperf.pl > \$@
END_MAKE
}

sub check_feature {
    my ( $filename ) = @_;

    my $cc = $Config{'cc'};

    # we assume gcc-like arguments; I think that's ok, considering
    # the platform-specific nature of this module
    system $cc, '-o', 'test', $filename;
    return 0 if $? != 0;
    system './test';
    my $status = $?;
    unlink 'test';

    return $status == 0 ? 1 : 0;
}

sub generate_config_header {
    my $has_process_vm_readv = check_feature('test_process_vm_readv.c');
    my $has_ptrace_exit_kill = check_feature('test_ptrace_exitkill.c');

    open my $fh, '>', 'config.h' or die "Unable to write config.h: $!";
    print {$fh} <<"END_CONFIG_H";
#ifndef CONFIG_H
#define CONFIG_H

#define HAS_PROCESS_VM_READV  $has_process_vm_readv
#define HAS_PTRACE_O_EXITKILL $has_ptrace_exit_kill

#endif
END_CONFIG_H
    close $fh;
}

generate_config_header();

WriteMakefile(
    NAME           => 'Devel::Trace::Syscall',
    VERSION_FROM   => 'lib/Devel/Trace/Syscall.pm',
    PREREQ_PM      => { 'Test::More' => 0 },
    ABSTRACT_FROM  => 'lib/Devel/Trace/Syscall.pm',
    AUTHOR         => 'Rob Hoelz',
    LIBS           => [''],
    DEFINE         => '',
    INC            => '-I.',
    OBJECT         => '$(BASEEXT)$(OBJ_EXT) syscall-info-x86-64.o',
    CCFLAGS        => '-Wall -Wextra -Werror',
    depend         => {
        'Syscall.o' => 'syscall-lookup.h',
    },
    clean => {
        FILES => 'syscall-lookup.h config.h',
    },
);
