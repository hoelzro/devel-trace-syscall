## no critic (RequireUseStrict)
package Devel::Trace::Syscall;

## use critic (RequireUseStrict)
use strict;
use warnings;

use Carp ();
use XSLoader;

XSLoader::load(__PACKAGE__, $Devel::Trace::Syscall::VERSION || '0');

my $previous_trace = " (BEGIN)\n";
sub DB::DB {
    flush_events($previous_trace);
    $previous_trace = Carp::longmess('');
}

1;

__END__

# ABSTRACT: Print a stack trace whenever a system call is made

=head1 SYNOPSIS

    # from the command line
    perl -d:Trace::Syscall=open my-script.pl # print a stack trace whenever open() is used

    perl -d:Trace::Syscall=open,openat my-script.pl # same thing, but for openat too

    # from Perl (this should occur as early as possible)

    use Devel::Trace::Syscall qw(open openat);

=head1 DESCRIPTION

Have you ever been looking at the C<strace> output for a Perl process, looking at all of the
calls to C<open> or whatever and wondering "where the heck in my program are those happening"?
You L<ack|http://beyondgrep.com/> the source code for calls to L<open> in vain, only to find
that it's a stray invocation of C<-T> that you missed.

Does this sound familiar to you?  If so, you may find this module useful.  Once loaded, it
uses C<ptrace> to trace the process, printing a stack trace whenever one of the system calls
you specify is called.  How cool is that!

=head1 HOW IT WORKS

L<http://hoelz.ro/blog/...>

=head1 CAVEATS

=over 4

=item *

I have no idea how this module behaves when there are multiple interpreters
present in a single process, or in conjunction with threads.  It may work, it
may blow your computer up, it may summon an army of squirrels to raid your kitchen.
I highly doubt it will do either of the latter two, but I also doubt it will work either.
Use at your own risk!

=item *

This is intended as a debugging tool only; I don't know how this may affect a production
system, so I don't recommend using it in one.

=item *

Linux-only for now.  Patches to add support for other operating systems are welcome!

=item *

Using C<no Devel::Trace::Syscall> won't turn this off.  It's a one-way ticket.

=item *

System calls happening at global destruction time might be interesting.

=item *

x86_64 only for now.  Patches to add support for other architectures are welcome!

=item *

There's no support for tracing grandchildren after a child C<fork()>s.  This is because
we have no guarantee that the grandchild will even be a Perl process, let alone one run
with C<-d:Trace::Syscall>.

=back

=head1 FUTURE IDEAS

There are things I'd like to add in the future if interest fuels its development:

=over 4

=item *

Support for other operating systems

=item *

Report system call arguments

=item *

Have a hook that users can use for finer-grain control

=back

=head1 SEE ALSO

L<ptrace(2)>

=cut
