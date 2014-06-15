use strict;
use warnings;

use File::Temp;

my %FORMATS = (
     accept4                => "ippi",
     accept                 => "ipp",
     access                 => "pi",
     acct                   => "p",
     add_key                => "pppiu",
     adjtimex               => "p",
     alarm                  => "u",
     bind                   => "ipi",
     brk                    => "u",
     brk                    => "u",
     capget                 => "pp",
     capset                 => "pp",
     chdir                  => "p",
     chmod                  => "pu",
     chown                  => "puu",
     chroot                 => "p",
     clock_adjtime          => "up",
     clock_getres           => "up",
     clock_gettime          => "up",
     clock_nanosleep        => "uipp",
     clock_settime          => "up",
     clone                  => "xpppp",
     close                  => "u",
     connect                => "ipi",
     creat                  => "pu",
     delete_module          => "pu",
     dup2                   => "uu",
     dup3                   => "uui",
     dup                    => "u",
     epoll_create1          => "i",
     epoll_create           => "i",
     epoll_ctl              => "iiip",
     epoll_pwait            => "ipiipi",
     epoll_wait             => "ipii",
     eventfd2               => "ui",
     eventfd                => "u",
     execve                 => "ppp",
     exit                   => "i",
     exit_group             => "i",
     faccessat              => "ipi",
     fadvise64              => "iiii",
     fallocate              => "iiii",
     fanotify_init          => "uu",
     fanotify_mark          => "iuuip",
     fchdir                 => "u",
     fchmod                 => "uu",
     fchmodat               => "ipu",
     fchown                 => "uuu",
     fchownat               => "ipuui",
     fcntl                  => "uuu",
     fdatasync              => "u",
     fgetxattr              => "ippi",
     finit_module           => "ipi",
     flistxattr             => "ipi",
     flock                  => "uu",
     fork                   => "",
     fremovexattr           => "ip",
     fsetxattr              => "ippii",
     fstat                  => "up",
     fstatfs                => "up",
     fsync                  => "u",
     ftruncate              => "uu",
     futex                  => "piuppu",
     futimesat              => "ipp",
     get_mempolicy          => "ppuuu",
     get_robust_list        => "ipp",
     get_thread_area        => "p",
     get_thread_area        => "p",
     getcpu                 => "ppp",
     getcwd                 => "pu",
     getdents64             => "upu",
     getdents               => "upu",
     getegid                => "",
     geteuid                => "",
     getgid                 => "",
     getgroups              => "ip",
     getitimer              => "ip",
     getpeername            => "ipp",
     getpgid                => "u",
     getpgrp                => "",
     getpid                 => "",
     getppid                => "",
     getpriority            => "ii",
     getresgid              => "ppp",
     getresuid              => "ppp",
     getrlimit              => "up",
     getrusage              => "ip",
     getsid                 => "u",
     getsockname            => "ipp",
     getsockopt             => "iiipp",
     gettid                 => "",
     gettimeofday           => "pp",
     getuid                 => "",
     getxattr               => "pppi",
     init_module            => "pup",
     inotify_add_watch      => "ipu",
     inotify_init1          => "i",
     inotify_init           => "",
     inotify_rm_watch       => "ii",
     io_cancel              => "upp",
     io_destroy             => "u",
     io_getevents           => "uiipp",
     io_setup               => "up",
     io_submit              => "uip",
     ioctl                  => "uuu",
     iopl                   => "u",
     ioprio_get             => "ii",
     ioprio_set             => "iii",
     kcmp                   => "uuiuu",
     kexec_load             => "uupu",
     keyctl                 => "iuuuu",
     kill                   => "ui",
     lchown                 => "puu",
     lgetxattr              => "pppi",
     link                   => "pp",
     linkat                 => "ipipi",
     listen                 => "ii",
     listxattr              => "ppi",
     llistxattr             => "ppi",
     lookup_dcookie         => "upi",
     lremovexattr           => "pp",
     lseek                  => "uiu",
     lsetxattr              => "pppii",
     madvise                => "uii",
     mbind                  => "uuupuu",
     migrate_pages          => "uupp",
     mincore                => "uip",
     mkdir                  => "pu",
     mkdirat                => "ipu",
     mknod                  => "puu",
     mknodat                => "ipuu",
     mlock                  => "ui",
     mlockall               => "i",
     mmap2                  => "pixxui",
     mmap                   => "pixxui",
     mount                  => "pppup",
     move_pages             => "uupppi",
     mprotect               => "uiu",
     mq_getsetattr          => "ipp",
     mq_notify              => "ip",
     mq_open                => "piup",
     mq_timedreceive        => "ipipp",
     mq_timedsend           => "ipiup",
     mq_unlink              => "p",
     mremap                 => "uuuuu",
     msgctl                 => "iip",
     msgget                 => "ii",
     msgrcv                 => "ipiii",
     msgsnd                 => "ipii",
     msync                  => "uii",
     munlock                => "ui",
     munlockall             => "",
     munmap                 => "ui",
     name_to_handle_at      => "ipppi",
     nanosleep              => "pp",
     newfstatat             => "ippi",
     open                   => "zxo",
     openat                 => "ipiu",
     pause                  => "",
     perf_event_open        => "puiiu",
     personality            => "u",
     pipe2                  => "pi",
     pipe                   => "p",
     pivot_root             => "pp",
     poll                   => "pui",
     ppoll                  => "puppi",
     prctl                  => "iuuuu",
     pread64                => "upii",
     preadv                 => "upuuu",
     prlimit64              => "uupp",
     process_vm_readv       => "upupuu",
     process_vm_writev      => "upupuu",
     pselect6               => "ippppp",
     ptrace                 => "iiuu",
     pwrite64               => "upii",
     pwritev                => "upuuu",
     quotactl               => "upup",
     read                   => "upi",
     readahead              => "iii",
     readlink               => "ppi",
     readlinkat             => "ippi",
     readv                  => "upu",
     reboot                 => "iiup",
     recvfrom               => "ipiupp",
     recvmmsg               => "ipuup",
     recvmsg                => "ipu",
     remap_file_pages       => "uuuuu",
     removexattr            => "pp",
     rename                 => "pp",
     renameat               => "ipip",
     request_key            => "pppu",
     restart_syscall        => "",
     rmdir                  => "p",
     rt_sigaction           => "ipppi",
     rt_sigaction           => "ipppi",
     rt_sigpending          => "pi",
     rt_sigprocmask         => "ippi",
     rt_sigqueueinfo        => "uip",
     rt_sigreturn           => "",
     rt_sigsuspend          => "pi",
     rt_sigtimedwait        => "pppi",
     rt_tgsigqueueinfo      => "uuip",
     sched_get_priority_max => "i",
     sched_get_priority_min => "i",
     sched_getaffinity      => "uup",
     sched_getattr          => "upuu",
     sched_getparam         => "up",
     sched_getscheduler     => "u",
     sched_rr_get_interval  => "up",
     sched_setaffinity      => "uup",
     sched_setattr          => "upu",
     sched_setparam         => "up",
     sched_setscheduler     => "uip",
     sched_yield            => "",
     select                 => "ipppp",
     semctl                 => "iiiu",
     semget                 => "iii",
     semop                  => "ipu",
     semtimedop             => "ipup",
     sendfile               => "iipi",
     sendmmsg               => "ipuu",
     sendmsg                => "ipu",
     sendto                 => "ipiupi",
     set_mempolicy          => "ipu",
     set_robust_list        => "pi",
     set_thread_area        => "p",
     set_tid_address        => "p",
     setdomainname          => "pi",
     setfsgid               => "u",
     setfsuid               => "u",
     setgid                 => "u",
     setgroups              => "ip",
     sethostname            => "pi",
     setitimer              => "ipp",
     setns                  => "ii",
     setpgid                => "uu",
     setpriority            => "iii",
     setregid               => "uu",
     setresgid              => "uuu",
     setresuid              => "uuu",
     setreuid               => "uu",
     setrlimit              => "up",
     setsid                 => "",
     setsockopt             => "iiipi",
     settimeofday           => "pp",
     setuid                 => "u",
     setxattr               => "pppii",
     shmat                  => "ipi",
     shmctl                 => "iip",
     shmdt                  => "p",
     shmget                 => "iii",
     shutdown               => "ii",
     sigaltstack            => "pp",
     signalfd4              => "ipii",
     signalfd               => "ipi",
     socket                 => "iii",
     socketpair             => "iiip",
     splice                 => "ipipiu",
     stat                   => "pp",
     statfs                 => "pp",
     swapoff                => "p",
     swapon                 => "pi",
     symlink                => "pp",
     symlinkat              => "pip",
     sync                   => "",
     sync_file_range        => "iiiu",
     syncfs                 => "i",
     _sysctl                => "p",
     sysfs                  => "iuu",
     sysinfo                => "p",
     syslog                 => "ipi",
     tee                    => "iiiu",
     tgkill                 => "uui",
     time                   => "p",
     timer_create           => "upp",
     timer_delete           => "u",
     timer_getoverrun       => "u",
     timer_gettime          => "up",
     timer_settime          => "uipp",
     timerfd_create         => "ii",
     timerfd_gettime        => "ip",
     timerfd_settime        => "iipp",
     times                  => "p",
     tkill                  => "ui",
     truncate               => "pi",
     umask                  => "i",
     umount2                => "pi",
     uname                  => "p",
     unlink                 => "p",
     unlinkat               => "ipi",
     unshare                => "u",
     uselib                 => "p",
     ustat                  => "up",
     utime                  => "pp",
     utimensat              => "ippi",
     utimes                 => "pp",
     vfork                  => "",
     vhangup                => "",
     vmsplice               => "ipuu",
     wait4                  => "upip",
     waitid                 => "iupip",
     write                  => "upi",
     writev                 => "upu",
);

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

{{SYSCALL_FORMATTING}}
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
    MAX_SYSCALL_NO     => $max_syscall_no,
    SYSCALL_NAMES      => join(",\n", map { exists $number_to_syscall{$_} ? qq{    "$number_to_syscall{$_}"} : '    NULL' } 0 .. $max_syscall_no),
    SYSCALL_FORMATTING => join("\n", map {
        exists $FORMATS{$_}
            ?  qq{    SYSCALL_ARGS[__NR_$_] = "$FORMATS{$_}";}
            :  qq{    SYSCALL_ARGS[__NR_$_] = NULL;}
    } @syscalls),
    KEYWORDS           => join("\n", map { "$_, __NR_$_" } @syscalls),
);

$GPERF_TEMPLATE =~ s/\{\{(\w+)\}\}/$template_vars{$1}/ge;

print $GPERF_TEMPLATE;
