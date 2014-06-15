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

// a lookup table that describes the arguments to a particular system call
const char *SYSCALL_ARGS[MAX_SYSCALL_NO + 1];

void
init_syscall_args(void)
{
    memset(SYSCALL_ARGS, 0, sizeof(SYSCALL_ARGS));

    SYSCALL_ARGS[__NR_accept4]                    = "ippi";
    SYSCALL_ARGS[__NR_accept]                     = "ipp";
    SYSCALL_ARGS[__NR_access]                     = "pi";
    SYSCALL_ARGS[__NR_acct]                       = "p";
    SYSCALL_ARGS[__NR_add_key]                    = "pppiu";
    SYSCALL_ARGS[__NR_adjtimex]                   = "p";
    SYSCALL_ARGS[__NR_alarm]                      = "u";
    SYSCALL_ARGS[__NR_bind]                       = "ipi";
    SYSCALL_ARGS[__NR_brk]                        = "u";
    SYSCALL_ARGS[__NR_brk]                        = "u";
    SYSCALL_ARGS[__NR_capget]                     = "pp";
    SYSCALL_ARGS[__NR_capset]                     = "pp";
    SYSCALL_ARGS[__NR_chdir]                      = "p";
    SYSCALL_ARGS[__NR_chmod]                      = "pu";
    SYSCALL_ARGS[__NR_chown]                      = "puu";
    SYSCALL_ARGS[__NR_chroot]                     = "p";
    SYSCALL_ARGS[__NR_clock_adjtime]              = "up";
    SYSCALL_ARGS[__NR_clock_getres]               = "up";
    SYSCALL_ARGS[__NR_clock_gettime]              = "up";
    SYSCALL_ARGS[__NR_clock_nanosleep]            = "uipp";
    SYSCALL_ARGS[__NR_clock_settime]              = "up";
    SYSCALL_ARGS[__NR_clone]                      = "xpppp";
    SYSCALL_ARGS[__NR_close]                      = "u";
    SYSCALL_ARGS[__NR_connect]                    = "ipi";
    SYSCALL_ARGS[__NR_creat]                      = "pu";
    SYSCALL_ARGS[__NR_delete_module]              = "pu";
    SYSCALL_ARGS[__NR_dup2]                       = "uu";
    SYSCALL_ARGS[__NR_dup3]                       = "uui";
    SYSCALL_ARGS[__NR_dup]                        = "u";
    SYSCALL_ARGS[__NR_epoll_create1]              = "i";
    SYSCALL_ARGS[__NR_epoll_create]               = "i";
    SYSCALL_ARGS[__NR_epoll_ctl]                  = "iiip";
    SYSCALL_ARGS[__NR_epoll_pwait]                = "ipiipi";
    SYSCALL_ARGS[__NR_epoll_wait]                 = "ipii";
    SYSCALL_ARGS[__NR_eventfd2]                   = "ui";
    SYSCALL_ARGS[__NR_eventfd]                    = "u";
    SYSCALL_ARGS[__NR_execve]                     = "ppp";
    SYSCALL_ARGS[__NR_exit]                       = "i";
    SYSCALL_ARGS[__NR_exit_group]                 = "i";
    SYSCALL_ARGS[__NR_faccessat]                  = "ipi";
    SYSCALL_ARGS[__NR_fadvise64]                  = "iiii";
    SYSCALL_ARGS[__NR_fallocate]                  = "iiii";
    SYSCALL_ARGS[__NR_fanotify_init]              = "uu";
    SYSCALL_ARGS[__NR_fanotify_mark]              = "iuuip";
    SYSCALL_ARGS[__NR_fchdir]                     = "u";
    SYSCALL_ARGS[__NR_fchmod]                     = "uu";
    SYSCALL_ARGS[__NR_fchmodat]                   = "ipu";
    SYSCALL_ARGS[__NR_fchown]                     = "uuu";
    SYSCALL_ARGS[__NR_fchownat]                   = "ipuui";
    SYSCALL_ARGS[__NR_fcntl]                      = "uuu";
    SYSCALL_ARGS[__NR_fdatasync]                  = "u";
    SYSCALL_ARGS[__NR_fgetxattr]                  = "ippi";
    SYSCALL_ARGS[__NR_finit_module]               = "ipi";
    SYSCALL_ARGS[__NR_flistxattr]                 = "ipi";
    SYSCALL_ARGS[__NR_flock]                      = "uu";
    SYSCALL_ARGS[__NR_fork]                       = "";
    SYSCALL_ARGS[__NR_fremovexattr]               = "ip";
    SYSCALL_ARGS[__NR_fsetxattr]                  = "ippii";
    SYSCALL_ARGS[__NR_fstat]                      = "up";
    SYSCALL_ARGS[__NR_fstatfs]                    = "up";
    SYSCALL_ARGS[__NR_fsync]                      = "u";
    SYSCALL_ARGS[__NR_ftruncate]                  = "uu";
    SYSCALL_ARGS[__NR_futex]                      = "piuppu";
    SYSCALL_ARGS[__NR_futimesat]                  = "ipp";
    SYSCALL_ARGS[__NR_get_mempolicy]              = "ppuuu";
    SYSCALL_ARGS[__NR_get_robust_list]            = "ipp";
    SYSCALL_ARGS[__NR_get_thread_area]            = "p";
    SYSCALL_ARGS[__NR_get_thread_area]            = "p";
    SYSCALL_ARGS[__NR_getcpu]                     = "ppp";
    SYSCALL_ARGS[__NR_getcwd]                     = "pu";
    SYSCALL_ARGS[__NR_getdents64]                 = "upu";
    SYSCALL_ARGS[__NR_getdents]                   = "upu";
    SYSCALL_ARGS[__NR_getegid]                    = "";
    SYSCALL_ARGS[__NR_geteuid]                    = "";
    SYSCALL_ARGS[__NR_getgid]                     = "";
    SYSCALL_ARGS[__NR_getgroups]                  = "ip";
    SYSCALL_ARGS[__NR_getitimer]                  = "ip";
    SYSCALL_ARGS[__NR_getpeername]                = "ipp";
    SYSCALL_ARGS[__NR_getpgid]                    = "u";
    SYSCALL_ARGS[__NR_getpgrp]                    = "";
    SYSCALL_ARGS[__NR_getpid]                     = "";
    SYSCALL_ARGS[__NR_getppid]                    = "";
    SYSCALL_ARGS[__NR_getpriority]                = "ii";
    SYSCALL_ARGS[__NR_getresgid]                  = "ppp";
    SYSCALL_ARGS[__NR_getresuid]                  = "ppp";
    SYSCALL_ARGS[__NR_getrlimit]                  = "up";
    SYSCALL_ARGS[__NR_getrusage]                  = "ip";
    SYSCALL_ARGS[__NR_getsid]                     = "u";
    SYSCALL_ARGS[__NR_getsockname]                = "ipp";
    SYSCALL_ARGS[__NR_getsockopt]                 = "iiipp";
    SYSCALL_ARGS[__NR_gettid]                     = "";
    SYSCALL_ARGS[__NR_gettimeofday]               = "pp";
    SYSCALL_ARGS[__NR_getuid]                     = "";
    SYSCALL_ARGS[__NR_getxattr]                   = "pppi";
    SYSCALL_ARGS[__NR_init_module]                = "pup";
    SYSCALL_ARGS[__NR_inotify_add_watch]          = "ipu";
    SYSCALL_ARGS[__NR_inotify_init1]              = "i";
    SYSCALL_ARGS[__NR_inotify_init]               = "";
    SYSCALL_ARGS[__NR_inotify_rm_watch]           = "ii";
    SYSCALL_ARGS[__NR_io_cancel]                  = "upp";
    SYSCALL_ARGS[__NR_io_destroy]                 = "u";
    SYSCALL_ARGS[__NR_io_getevents]               = "uiipp";
    SYSCALL_ARGS[__NR_io_setup]                   = "up";
    SYSCALL_ARGS[__NR_io_submit]                  = "uip";
    SYSCALL_ARGS[__NR_ioctl]                      = "uuu";
    SYSCALL_ARGS[__NR_iopl]                       = "u";
    SYSCALL_ARGS[__NR_ioprio_get]                 = "ii";
    SYSCALL_ARGS[__NR_ioprio_set]                 = "iii";
    SYSCALL_ARGS[__NR_kcmp]                       = "uuiuu";
    SYSCALL_ARGS[__NR_kexec_load]                 = "uupu";
    SYSCALL_ARGS[__NR_keyctl]                     = "iuuuu";
    SYSCALL_ARGS[__NR_kill]                       = "ui";
    SYSCALL_ARGS[__NR_lchown]                     = "puu";
    SYSCALL_ARGS[__NR_lgetxattr]                  = "pppi";
    SYSCALL_ARGS[__NR_link]                       = "pp";
    SYSCALL_ARGS[__NR_linkat]                     = "ipipi";
    SYSCALL_ARGS[__NR_listen]                     = "ii";
    SYSCALL_ARGS[__NR_listxattr]                  = "ppi";
    SYSCALL_ARGS[__NR_llistxattr]                 = "ppi";
    SYSCALL_ARGS[__NR_lookup_dcookie]             = "upi";
    SYSCALL_ARGS[__NR_lremovexattr]               = "pp";
    SYSCALL_ARGS[__NR_lseek]                      = "uiu";
    SYSCALL_ARGS[__NR_lsetxattr]                  = "pppii";
    SYSCALL_ARGS[__NR_madvise]                    = "uii";
    SYSCALL_ARGS[__NR_mbind]                      = "uuupuu";
    SYSCALL_ARGS[__NR_migrate_pages]              = "uupp";
    SYSCALL_ARGS[__NR_mincore]                    = "uip";
    SYSCALL_ARGS[__NR_mkdir]                      = "pu";
    SYSCALL_ARGS[__NR_mkdirat]                    = "ipu";
    SYSCALL_ARGS[__NR_mknod]                      = "puu";
    SYSCALL_ARGS[__NR_mknodat]                    = "ipuu";
    SYSCALL_ARGS[__NR_mlock]                      = "ui";
    SYSCALL_ARGS[__NR_mlockall]                   = "i";
#ifdef __NR_mmap2
    SYSCALL_ARGS[__NR_mmap2]                      = "pixxui";
#endif
    SYSCALL_ARGS[__NR_mmap]                       = "pixxui";
    SYSCALL_ARGS[__NR_mount]                      = "pppup";
    SYSCALL_ARGS[__NR_move_pages]                 = "uupppi";
    SYSCALL_ARGS[__NR_mprotect]                   = "uiu";
    SYSCALL_ARGS[__NR_mq_getsetattr]              = "ipp";
    SYSCALL_ARGS[__NR_mq_notify]                  = "ip";
    SYSCALL_ARGS[__NR_mq_open]                    = "piup";
    SYSCALL_ARGS[__NR_mq_timedreceive]            = "ipipp";
    SYSCALL_ARGS[__NR_mq_timedsend]               = "ipiup";
    SYSCALL_ARGS[__NR_mq_unlink]                  = "p";
    SYSCALL_ARGS[__NR_mremap]                     = "uuuuu";
    SYSCALL_ARGS[__NR_msgctl]                     = "iip";
    SYSCALL_ARGS[__NR_msgget]                     = "ii";
    SYSCALL_ARGS[__NR_msgrcv]                     = "ipiii";
    SYSCALL_ARGS[__NR_msgsnd]                     = "ipii";
    SYSCALL_ARGS[__NR_msync]                      = "uii";
    SYSCALL_ARGS[__NR_munlock]                    = "ui";
    SYSCALL_ARGS[__NR_munlockall]                 = "";
    SYSCALL_ARGS[__NR_munmap]                     = "ui";
    SYSCALL_ARGS[__NR_name_to_handle_at]          = "ipppi";
    SYSCALL_ARGS[__NR_nanosleep]                  = "pp";
    SYSCALL_ARGS[__NR_newfstatat]                 = "ippi";
    SYSCALL_ARGS[__NR_open]                       = "zxo";
    SYSCALL_ARGS[__NR_openat]                     = "ipiu";
    SYSCALL_ARGS[__NR_pause]                      = "";
    SYSCALL_ARGS[__NR_perf_event_open]            = "puiiu";
    SYSCALL_ARGS[__NR_personality]                = "u";
    SYSCALL_ARGS[__NR_pipe2]                      = "pi";
    SYSCALL_ARGS[__NR_pipe]                       = "p";
    SYSCALL_ARGS[__NR_pivot_root]                 = "pp";
    SYSCALL_ARGS[__NR_poll]                       = "pui";
    SYSCALL_ARGS[__NR_ppoll]                      = "puppi";
    SYSCALL_ARGS[__NR_prctl]                      = "iuuuu";
    SYSCALL_ARGS[__NR_pread64]                    = "upii";
    SYSCALL_ARGS[__NR_preadv]                     = "upuuu";
    SYSCALL_ARGS[__NR_prlimit64]                  = "uupp";
    SYSCALL_ARGS[__NR_process_vm_readv]           = "upupuu";
    SYSCALL_ARGS[__NR_process_vm_writev]          = "upupuu";
    SYSCALL_ARGS[__NR_pselect6]                   = "ippppp";
    SYSCALL_ARGS[__NR_ptrace]                     = "iiuu";
    SYSCALL_ARGS[__NR_pwrite64]                   = "upii";
    SYSCALL_ARGS[__NR_pwritev]                    = "upuuu";
    SYSCALL_ARGS[__NR_quotactl]                   = "upup";
    SYSCALL_ARGS[__NR_read]                       = "upi";
    SYSCALL_ARGS[__NR_readahead]                  = "iii";
    SYSCALL_ARGS[__NR_readlink]                   = "ppi";
    SYSCALL_ARGS[__NR_readlinkat]                 = "ippi";
    SYSCALL_ARGS[__NR_readv]                      = "upu";
    SYSCALL_ARGS[__NR_reboot]                     = "iiup";
    SYSCALL_ARGS[__NR_recvfrom]                   = "ipiupp";
    SYSCALL_ARGS[__NR_recvmmsg]                   = "ipuup";
    SYSCALL_ARGS[__NR_recvmsg]                    = "ipu";
    SYSCALL_ARGS[__NR_remap_file_pages]           = "uuuuu";
    SYSCALL_ARGS[__NR_removexattr]                = "pp";
    SYSCALL_ARGS[__NR_rename]                     = "pp";
    SYSCALL_ARGS[__NR_renameat]                   = "ipip";
    SYSCALL_ARGS[__NR_request_key]                = "pppu";
    SYSCALL_ARGS[__NR_restart_syscall]            = "";
    SYSCALL_ARGS[__NR_rmdir]                      = "p";
    SYSCALL_ARGS[__NR_rt_sigaction]               = "ipppi";
    SYSCALL_ARGS[__NR_rt_sigaction]               = "ipppi";
    SYSCALL_ARGS[__NR_rt_sigpending]              = "pi";
    SYSCALL_ARGS[__NR_rt_sigprocmask]             = "ippi";
    SYSCALL_ARGS[__NR_rt_sigqueueinfo]            = "uip";
    SYSCALL_ARGS[__NR_rt_sigreturn]               = "";
    SYSCALL_ARGS[__NR_rt_sigsuspend]              = "pi";
    SYSCALL_ARGS[__NR_rt_sigtimedwait]            = "pppi";
    SYSCALL_ARGS[__NR_rt_tgsigqueueinfo]          = "uuip";
    SYSCALL_ARGS[__NR_sched_get_priority_max]     = "i";
    SYSCALL_ARGS[__NR_sched_get_priority_min]     = "i";
    SYSCALL_ARGS[__NR_sched_getaffinity]          = "uup";
    SYSCALL_ARGS[__NR_sched_getattr]              = "upuu";
    SYSCALL_ARGS[__NR_sched_getparam]             = "up";
    SYSCALL_ARGS[__NR_sched_getscheduler]         = "u";
    SYSCALL_ARGS[__NR_sched_rr_get_interval]      = "up";
    SYSCALL_ARGS[__NR_sched_setaffinity]          = "uup";
    SYSCALL_ARGS[__NR_sched_setattr]              = "upu";
    SYSCALL_ARGS[__NR_sched_setparam]             = "up";
    SYSCALL_ARGS[__NR_sched_setscheduler]         = "uip";
    SYSCALL_ARGS[__NR_sched_yield]                = "";
    SYSCALL_ARGS[__NR_select]                     = "ipppp";
    SYSCALL_ARGS[__NR_semctl]                     = "iiiu";
    SYSCALL_ARGS[__NR_semget]                     = "iii";
    SYSCALL_ARGS[__NR_semop]                      = "ipu";
    SYSCALL_ARGS[__NR_semtimedop]                 = "ipup";
    SYSCALL_ARGS[__NR_sendfile]                   = "iipi";
    SYSCALL_ARGS[__NR_sendmmsg]                   = "ipuu";
    SYSCALL_ARGS[__NR_sendmsg]                    = "ipu";
    SYSCALL_ARGS[__NR_sendto]                     = "ipiupi";
    SYSCALL_ARGS[__NR_set_mempolicy]              = "ipu";
    SYSCALL_ARGS[__NR_set_robust_list]            = "pi";
    SYSCALL_ARGS[__NR_set_thread_area]            = "p";
    SYSCALL_ARGS[__NR_set_tid_address]            = "p";
    SYSCALL_ARGS[__NR_setdomainname]              = "pi";
    SYSCALL_ARGS[__NR_setfsgid]                   = "u";
    SYSCALL_ARGS[__NR_setfsuid]                   = "u";
    SYSCALL_ARGS[__NR_setgid]                     = "u";
    SYSCALL_ARGS[__NR_setgroups]                  = "ip";
    SYSCALL_ARGS[__NR_sethostname]                = "pi";
    SYSCALL_ARGS[__NR_setitimer]                  = "ipp";
    SYSCALL_ARGS[__NR_setns]                      = "ii";
    SYSCALL_ARGS[__NR_setpgid]                    = "uu";
    SYSCALL_ARGS[__NR_setpriority]                = "iii";
    SYSCALL_ARGS[__NR_setregid]                   = "uu";
    SYSCALL_ARGS[__NR_setresgid]                  = "uuu";
    SYSCALL_ARGS[__NR_setresuid]                  = "uuu";
    SYSCALL_ARGS[__NR_setreuid]                   = "uu";
    SYSCALL_ARGS[__NR_setrlimit]                  = "up";
    SYSCALL_ARGS[__NR_setsid]                     = "";
    SYSCALL_ARGS[__NR_setsockopt]                 = "iiipi";
    SYSCALL_ARGS[__NR_settimeofday]               = "pp";
    SYSCALL_ARGS[__NR_setuid]                     = "u";
    SYSCALL_ARGS[__NR_setxattr]                   = "pppii";
    SYSCALL_ARGS[__NR_shmat]                      = "ipi";
    SYSCALL_ARGS[__NR_shmctl]                     = "iip";
    SYSCALL_ARGS[__NR_shmdt]                      = "p";
    SYSCALL_ARGS[__NR_shmget]                     = "iii";
    SYSCALL_ARGS[__NR_shutdown]                   = "ii";
    SYSCALL_ARGS[__NR_sigaltstack]                = "pp";
    SYSCALL_ARGS[__NR_signalfd4]                  = "ipii";
    SYSCALL_ARGS[__NR_signalfd]                   = "ipi";
    SYSCALL_ARGS[__NR_socket]                     = "iii";
    SYSCALL_ARGS[__NR_socketpair]                 = "iiip";
    SYSCALL_ARGS[__NR_splice]                     = "ipipiu";
    SYSCALL_ARGS[__NR_stat]                       = "pp";
    SYSCALL_ARGS[__NR_statfs]                     = "pp";
    SYSCALL_ARGS[__NR_swapoff]                    = "p";
    SYSCALL_ARGS[__NR_swapon]                     = "pi";
    SYSCALL_ARGS[__NR_symlink]                    = "pp";
    SYSCALL_ARGS[__NR_symlinkat]                  = "pip";
    SYSCALL_ARGS[__NR_sync]                       = "";
    SYSCALL_ARGS[__NR_sync_file_range]            = "iiiu";
    SYSCALL_ARGS[__NR_syncfs]                     = "i";
    SYSCALL_ARGS[__NR__sysctl]                    = "p";
    SYSCALL_ARGS[__NR_sysfs]                      = "iuu";
    SYSCALL_ARGS[__NR_sysinfo]                    = "p";
    SYSCALL_ARGS[__NR_syslog]                     = "ipi";
    SYSCALL_ARGS[__NR_tee]                        = "iiiu";
    SYSCALL_ARGS[__NR_tgkill]                     = "uui";
    SYSCALL_ARGS[__NR_time]                       = "p";
    SYSCALL_ARGS[__NR_timer_create]               = "upp";
    SYSCALL_ARGS[__NR_timer_delete]               = "u";
    SYSCALL_ARGS[__NR_timer_getoverrun]           = "u";
    SYSCALL_ARGS[__NR_timer_gettime]              = "up";
    SYSCALL_ARGS[__NR_timer_settime]              = "uipp";
    SYSCALL_ARGS[__NR_timerfd_create]             = "ii";
    SYSCALL_ARGS[__NR_timerfd_gettime]            = "ip";
    SYSCALL_ARGS[__NR_timerfd_settime]            = "iipp";
    SYSCALL_ARGS[__NR_times]                      = "p";
    SYSCALL_ARGS[__NR_tkill]                      = "ui";
    SYSCALL_ARGS[__NR_truncate]                   = "pi";
    SYSCALL_ARGS[__NR_umask]                      = "i";
    SYSCALL_ARGS[__NR_umount2]                    = "pi";
    SYSCALL_ARGS[__NR_uname]                      = "p";
    SYSCALL_ARGS[__NR_unlink]                     = "p";
    SYSCALL_ARGS[__NR_unlinkat]                   = "ipi";
    SYSCALL_ARGS[__NR_unshare]                    = "u";
    SYSCALL_ARGS[__NR_uselib]                     = "p";
    SYSCALL_ARGS[__NR_ustat]                      = "up";
    SYSCALL_ARGS[__NR_utime]                      = "pp";
    SYSCALL_ARGS[__NR_utimensat]                  = "ippi";
    SYSCALL_ARGS[__NR_utimes]                     = "pp";
    SYSCALL_ARGS[__NR_vfork]                      = "";
    SYSCALL_ARGS[__NR_vhangup]                    = "";
    SYSCALL_ARGS[__NR_vmsplice]                   = "ipuu";
    SYSCALL_ARGS[__NR_wait4]                      = "upip";
    SYSCALL_ARGS[__NR_waitid]                     = "iupip";
    SYSCALL_ARGS[__NR_write]                      = "upi";
    SYSCALL_ARGS[__NR_writev]                     = "upu";
}

%}

struct syscall_name_num {
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
