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

#define WORD_SIZE (sizeof(void *))
#define WORD_ALIGNED(p)\
    ((void *) (((unsigned long long)p) & 0xFFFFFFFFFFFFFFF8))

#ifdef __NR_mmap2
# define SYSCALL_IS_MMAP(value) ((value) == __NR_mmap || (value) == __NR_mmap2)
#else
# define SYSCALL_IS_MMAP(value) ((value) == __NR_mmap)
#endif

// XXX error handling
// XXX check that ptrace functions all work as intended during configure

static int my_custom_signal = 0;
static int is_flushing = 0;
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
send_args(pid_t child, int fd, int syscall_no, struct user *userdata)
{
    int status;
    const char *arg = SYSCALL_ARGS[syscall_no];
    unsigned long long args[] = {
        userdata->regs.rdi,
        userdata->regs.rsi,
        userdata->regs.rdx,
        userdata->regs.rcx,
        userdata->regs.r8,
        userdata->regs.r9,
    };
    int arg_idx = 0;

    if(! arg) {
        return;
    }

    while(*arg) {
        switch(*arg) {
            case 'z': // zero (NUL) terminated string
                {
                    char *child_p = (char *) args[arg_idx++];
                    char buffer[64];

                    while(1) {
                        char *end_p;
                        status = pmemcpy(buffer, 64, child, child_p);

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
                write(fd, &args[arg_idx++], sizeof(args[0]));
                break;
        }
        arg++;
    }
}

static void
handle_syscall_enter(pid_t child)
{
    struct user userdata;
    uint16_t syscall_no;

#if __sparc__
    ptrace(PTRACE_GETREGS, child, &userdata, 0);
#else
    ptrace(PTRACE_GETREGS, child, 0, &userdata);
#endif

    // XXX arch-specific
    syscall_no = userdata.regs.orig_rax;

    if(watching_syscall[syscall_no]) {
        if(syscall_no == __NR_write) {
            long child_is_flushing = ptrace(PTRACE_PEEKDATA, child, (void *) &is_flushing, 0);

            if(child_is_flushing) {
                return;
            }
        } else if(syscall_no == __NR_read && userdata.regs.rdi == channel[0]) {
            return;
        } else if(SYSCALL_IS_MMAP(syscall_no)) {
            if( ((int) userdata.regs.r8) == -1) {
                return;
            }
        }

        // XXX fun with alignment
        ptrace(PTRACE_POKEDATA, child, (void *) &my_custom_signal, 1);
        write(channel[1], &syscall_no, sizeof(uint16_t)); // XXX error checking, chance of EPIPE?

        send_args(child, channel[1], syscall_no, &userdata);
    }
}

static void
handle_syscall_exit(pid_t child)
{
    // no-op (for now)
}

static void
run_parent(pid_t child)
{
    int status;
    int enter;

    waitpid(child, &status, 0);

    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD);
    ptrace(PTRACE_SYSCALL, child, 0, 0);

    while(waitpid(child, &status, 0) >= 0) {
        if(WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80)) {
            if(enter) {
                handle_syscall_enter(child);
            } else {
                handle_syscall_exit(child);
            }
            enter = !enter;
        }
        ptrace(PTRACE_SYSCALL, child, 0, 0);
    }
}

static int
read_event(int fd, uint16_t *result)
{
    uint16_t syscall_no;

    // XXX proper error handling
    if(read(fd, result, sizeof(uint16_t)) > 0) {
        return 1;
    } else {
        return 0;
    }
}

static void
read_args(int fd, uint16_t syscall_no)
{
    const char *arg = SYSCALL_ARGS[syscall_no];

    if(! arg) {
        return;
    }

    while(*arg) {
        printf("got an argument!\n");
        int bytes_read;

        switch(*arg) {
            case 'z':
                {
                    char *end_p;
                    char buffer[64];

                    while(1) {
                        bytes_read = read(fd, buffer, 64);

                        if(bytes_read != 64) {
                            goto short_read;
                        }

                        end_p = memchr(buffer, 0, 64);

                        if(end_p) {
                            fwrite(buffer, 1, end_p - buffer, stdout);
                            break;
                        } else {
                            fwrite(buffer, 1, 64, stdout);
                        }
                    }
                }
                break;
            case 'i':
                {
                    unsigned long long arg;
                    bytes_read = read(fd, &arg, sizeof(unsigned long long));
                    if(bytes_read < sizeof(unsigned long long)) {
                        goto short_read;
                    }
                    printf("%d\n", arg);
                }
                break;
            case 'u':
                {
                    unsigned long long arg;
                    bytes_read = read(fd, &arg, sizeof(unsigned long long));
                    if(bytes_read < sizeof(unsigned long long)) {
                        goto short_read;
                    }
                    printf("%u\n", arg);
                }
                break;
            case 'p':
                {
                    unsigned long long arg;
                    bytes_read = read(fd, &arg, sizeof(unsigned long long));
                    if(bytes_read < sizeof(unsigned long long)) {
                        goto short_read;
                    }
                    printf("%p\n", arg);
                }
                break;
        }
        arg++;
    }
    return;

short_read:
    fprintf(stderr, "short read on IPC pipe\n");
    return;
}

static void
init_syscall_args(void)
{
    memset(SYSCALL_ARGS, 0, sizeof(SYSCALL_ARGS));

    SYSCALL_ARGS[__NR_open]       = "zii";
    SYSCALL_ARGS[__NR_close]      = "i";
    SYSCALL_ARGS[__NR_read]       = "upi";
    SYSCALL_ARGS[__NR_write]      = "upi";
    SYSCALL_ARGS[__NR_exit]       = "i";
    SYSCALL_ARGS[__NR_exit_group] = "i";
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
            const char *syscall_name   = SvPVutf8_nolen(ST(i));
            const struct syscall *info = syscall_lookup(syscall_name, strlen(syscall_name));

            if(info) {
                if(info->syscall_no == __NR_brk) {
                    Perl_warn("*** Monitoring brk will likely result in a lot of events out of the control of your program due to memory allocation; disabling ***");
                    continue;
                } else if(SYSCALL_IS_MMAP(info->syscall_no)) {
                    Perl_warn("*** Monitoring mmap will *not* list mmap calls that are made purely for memory allocation, considering this is out of the control of your program ***");
                }
                watching_syscall[info->syscall_no] = 1;
            } else {
                Perl_croak("unknown syscall '%s'", syscall_name);
            }
        }
        if(items <= 1) {
            Perl_croak("you must provide at least one system call to monitor");
        }

        pipe(channel);
        child = fork();

        if(child == -1) {
            Perl_croak("failed to fork!"); // XXX reason
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
        if(UNLIKELY(my_custom_signal)) {
            char *trace_chars = SvPVutf8_nolen(trace);
            uint16_t syscall_no;

            my_custom_signal = 0;
            is_flushing      = 1;

            while(read_event(channel[0], &syscall_no)) {
                read_args(channel[0], syscall_no);
                printf("system call %s%s", syscall_names[syscall_no], trace_chars);
            }
            is_flushing = 0;
        }
