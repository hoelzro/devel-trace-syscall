#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <asm/unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

// XXX error handling
// XXX check that ptrace functions all work as intended during configure
// XXX assert that PL_sig_pending and PL_psig_pend are word-aligned?
// XXX what if multiple syscalls occur in an interval?

static void (*old_handler)(int);
static int my_custom_signal = 0;

static void
handle_syscall_enter(pid_t child)
{
    struct user userdata;

#if __sparc__
    ptrace(PTRACE_GETREGS, child, &userdata, 0);
#else
    ptrace(PTRACE_GETREGS, child, 0, &userdata);
#endif

    // XXX arch-specific
    if(userdata.regs.orig_rax == __NR_open) { // XXX FIXME
        // XXX fun with alignment
        ptrace(PTRACE_POKEDATA, child, (void *) &my_custom_signal, 1);
        ptrace(PTRACE_POKEDATA, child, (void *) &PL_sig_pending, 1);
        ptrace(PTRACE_POKEDATA, child, (void *) &PL_psig_pend[SIG_SIZE-1], 1);
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

static void
my_sig_handler(int signum)
{
    if(signum == SIG_SIZE-1 && my_custom_signal) {
        my_custom_signal = 0;
        // XXX print stack trace
        return;
    }
    old_handler(signum);
}

MODULE = Devel::Trace::Syscall PACKAGE = Devel::Trace::Syscall

void
import(...)
    PREINIT:
        int i;
        pid_t child;
    PPCODE:
    {
        child = fork();

        if(child == -1) {
            Perl_croak("failed to fork!"); // XXX reason
        }

        if(child) {
            run_parent(child);
            my_exit(0);
        } else {
            old_handler    = PL_sighandlerp;
            PL_sighandlerp = my_sig_handler;

            ptrace(PTRACE_TRACEME, 0, 0, 0);
            raise(SIGTRAP);
            XSRETURN_UNDEF;
        }
    }
