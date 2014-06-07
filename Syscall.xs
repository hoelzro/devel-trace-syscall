#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <asm/unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "syscall-hash.h"
#include "syscall-info.h"

#define WORD_SIZE (sizeof(void *))
#define WORD_ALIGNED(p)\
    ((void *) (((unsigned long long)p) & (0xFFFFFFFFFFFFFFFF & ~(WORD_SIZE - 1))))

#ifdef __NR_mmap2
# define SYSCALL_IS_MMAP(value) ((value) == __NR_mmap || (value) == __NR_mmap2)
#else
# define SYSCALL_IS_MMAP(value) ((value) == __NR_mmap)
#endif

static int syscall_occurred __attribute__((aligned (WORD_SIZE))) = 0;
static int is_flushing __attribute__((aligned (WORD_SIZE))) = 0;
static int channel[2];
static int watching_syscall[MAX_SYSCALL_NO + 1];

static const char *SYSCALL_ARGS[MAX_SYSCALL_NO + 1];

#if HAS_PROCESS_VM_READV
static int
pmemcpy(void *dst, size_t size, pid_t child, void *addr)
{
    struct iovec local;
    struct iovec remote;

    local.iov_base = dst;
    local.iov_len  = size;

    remote.iov_base = addr;
    remote.iov_len  = size;

    return (int) process_vm_readv(child,
        &local, 1,
        &remote, 1,
        0);
}
#else
static int
pmemcpy(void *dst, size_t size, pid_t child, void *addr)
{
    union {
        long l;
        char c[WORD_SIZE];
    } u;
    size_t offset       = addr - WORD_ALIGNED(addr);
    size_t bytes_copied = 0;
    addr -= offset;

    while(bytes_copied < size) {
        errno = 0;
        u.l   = ptrace(PTRACE_PEEKDATA, child, addr, 0);
        if(u.l == -1 && errno) {
            return -1;
        }
        if(size < WORD_SIZE) {
            memcpy(dst, u.c + offset, size - offset);
        } else {
            memcpy(dst, u.c + offset, WORD_SIZE - offset);
        }
        offset = 0;

        dst          += WORD_SIZE;
        addr         += WORD_SIZE;
        bytes_copied += WORD_SIZE;
    }

    return 0;
}
#endif

static void
send_args(pid_t child, int fd, struct syscall_info *info)
{
    const char *arg = SYSCALL_ARGS[info->syscall_no];
    int arg_idx = 0;

    if(! arg) {
        return;
    }

    while(*arg) {
        switch(*arg) {
            case 'z': // zero (NUL) terminated string
                {
                    char *child_p = (char *) info->args[arg_idx++];
                    char buffer[64];

                    while(1) {
                        char *end_p;
                        pmemcpy(buffer, 64, child, child_p);

                        end_p = memchr(buffer, 0, 64);

                        if(end_p) {
                            write(fd, buffer, (end_p - buffer) + 1);
                            break;
                        } else {
                            write(fd, buffer, 64);
                            child_p += 64;
                        }
                    }
                }
                break;
            case 'i': // signed int
            case 'u': // unsigned int
            case 'p': // pointer
            case 'o': // unsigned int (formatted in octal)
            case 'x': // unsigned int (formatted in hex)
                write(fd, &info->args[arg_idx++], sizeof(info->args[0]));
                break;
        }
        arg++;
    }
}

static int
handle_syscall_enter(pid_t child)
{
    struct user userdata;
    struct syscall_info info;

#if __sparc__
    ptrace(PTRACE_GETREGS, child, &userdata, 0);
#else
    ptrace(PTRACE_GETREGS, child, 0, &userdata);
#endif
    syscall_info_from_user(&userdata, &info);

    if(watching_syscall[info.syscall_no]) {
        if(info.syscall_no == __NR_write) {
            long child_is_flushing = ptrace(PTRACE_PEEKDATA, child, (void *) &is_flushing, 0);

            if(child_is_flushing) {
                return 0;
            }
        } else if(info.syscall_no == __NR_read && info.args[0] == channel[0]) {
            return 0;
        } else if(SYSCALL_IS_MMAP(info.syscall_no)) {
            if( ((int) info.args[4]) == -1) {
                return 0;
            }
        }

        ptrace(PTRACE_POKEDATA, child, (void *) &syscall_occurred, 1);
        write(channel[1], &info.syscall_no, sizeof(uint16_t)); // XXX error checking, chance of EPIPE?

        send_args(child, channel[1], &info);
        return 1;
    }
    return 0;
}

static void
handle_syscall_exit(pid_t child, int handled_previous_enter)
{
    if(handled_previous_enter) {
        struct user userdata;
        struct syscall_info info;

#if __sparc__
        ptrace(PTRACE_GETREGS, child, &userdata, 0);
#else
        ptrace(PTRACE_GETREGS, child, 0, &userdata);
#endif
        syscall_info_from_user(&userdata, &info);

        write(channel[1], &info.return_value, sizeof(int)); // XXX error checking, chance of EPIPE?
    }
}

static void
run_parent(pid_t child)
{
    int status;
    int enter = 1;
    int handled_previous_enter;

    waitpid(child, &status, 0);

    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD);
    ptrace(PTRACE_SYSCALL, child, 0, 0);

    while(waitpid(child, &status, 0) >= 0) {
        if(WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80)) {
            if(enter) {
                handled_previous_enter = handle_syscall_enter(child);
            } else {
                handle_syscall_exit(child, handled_previous_enter);
            }
            enter = !enter;
        }
        ptrace(PTRACE_SYSCALL, child, 0, 0);
    }
}

static void
read_and_print_args(FILE *fp, uint16_t syscall_no)
{
    const char *arg = SYSCALL_ARGS[syscall_no];
    int first = 1;

    if(! arg) {
        fprintf(stderr, "...");
        return;
    }

    while(*arg) {
        size_t bytes_read;

        if(first) {
            first = 0;
        } else {
            fprintf(stderr, ", ");
        }

        if(*arg == 'z') {
            char *end_p;
            char buffer[64];
            int i;

            fprintf(stderr, "\"");
            while(1) {
                bytes_read = 0;
                for(i = 0; i < 64; i++) {
                    buffer[i] = fgetc(fp);

                    if(buffer[i] == EOF) {
                        break;
                    } else if(buffer[i] == '\0') {
                        bytes_read++;
                        break;
                    }
                    bytes_read++;
                }

                if(bytes_read != 64 && buffer[i] != '\0') {
                    goto short_read;
                }

                end_p = memchr(buffer, 0, 64);

                if(end_p) {
                    fwrite(buffer, 1, end_p - buffer, stderr);
                    break;
                } else {
                    fwrite(buffer, 1, 64, stderr);
                }
            }
            fprintf(stderr, "\"");
        } else {
            const char *format_string = "";

            unsigned long long arg_value;
            bytes_read = fread(&arg_value, 1, WORD_SIZE, fp);
            if(bytes_read < WORD_SIZE) {
                goto short_read;
            }

            switch(*arg) {
                case 'i': format_string = "%d";   break;
                case 'u': format_string = "%u";   break;
                case 'p': format_string = "%p";   break;
                case 'o': format_string = "0%o";  break;
                case 'x': format_string = "0x%x"; break;
            }
            fprintf(stderr, format_string, arg_value);
        }

        arg++;
    }
    return;

short_read:
    fprintf(stderr, "short read on IPC pipe\n");
    return;
}

static int
read_return_value(FILE *fp)
{
    int return_value;

    fread(&return_value, 1, sizeof(int), fp);

    return (int) return_value;
}

static void
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

MODULE = Devel::Trace::Syscall PACKAGE = Devel::Trace::Syscall

void
import(...)
    INIT:
        int i;
        pid_t child;
    CODE:
    {
        init_syscall_args();

        memset(watching_syscall, 0, sizeof(watching_syscall));
        for(i = 1; i < items; i++) {
            const char *syscall_name            = SvPVutf8_nolen(ST(i));
            const struct syscall_name_num *info = syscall_lookup(syscall_name, strlen(syscall_name));

            if(info) {
                if(info->syscall_no == __NR_brk) {
                    warn("*** Monitoring brk will likely result in a lot of events out of the control of your program due to memory allocation; disabling ***");
                    continue;
                } else if(SYSCALL_IS_MMAP(info->syscall_no)) {
                    warn("*** Monitoring mmap will *not* list mmap calls that are made purely for memory allocation, considering this is out of the control of your program ***");
                } else if(info->syscall_no == __NR_exit || info->syscall_no == __NR_exit_group) {
                    warn("*** Because of the way this module works, events for exit and exit_group will never appear. ***");
                    continue;
                }
                watching_syscall[info->syscall_no] = 1;
            } else {
                croak("unknown syscall '%s'", syscall_name);
            }
        }
        if(items <= 1) {
            croak("you must provide at least one system call to monitor");
        }

        pipe(channel);
        child = fork();

        if(child == -1) {
            croak("failed to fork!"); // XXX reason
        }

        if(child) {
            close(channel[0]);
            fcntl(channel[1], F_SETFL, O_NONBLOCK);
            run_parent(child);
            my_exit(0);
        } else {
            close(channel[1]);
            fcntl(channel[0], F_SETFL, O_NONBLOCK);
            ptrace(PTRACE_TRACEME, 0, 0, 0);
            raise(SIGTRAP);
            XSRETURN_UNDEF;
        }
    }

void
flush_events(SV *trace)
    CODE:
        static FILE *fp = NULL;

        if(fp == NULL && channel[0] != 0) {
            fp = fdopen(channel[0], "r");
        }
        if(UNLIKELY(syscall_occurred)) {
            char *trace_chars = SvPVutf8_nolen(trace);
            uint16_t syscall_no;

            syscall_occurred = 0;
            is_flushing      = 1;

            while(fread(&syscall_no, sizeof(uint16_t), 1, fp) > 0) {
                fprintf(stderr, "%s(", syscall_names[syscall_no]);
                read_and_print_args(fp, syscall_no);
                fprintf(stderr, ") = %d%s", read_return_value(fp), trace_chars);
            }
            is_flushing = 0;
        }

BOOT:
        CV *flush_events = get_cv("Devel::Trace::Syscall::flush_events", 0);
        CvNODEBUG_on(flush_events);
