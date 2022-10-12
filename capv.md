Colocation tutorial
===================

PROTIP: "man 7 capv" is shorter.  Many/most things, like colookup(1), have man pages,
so look at `man 1 colookup` on the nearest Morello box.

The whole topic below is conceptually split into three "layers", each building upon
the previous one.  This is to make it easy to substitute the higher layers with something
else.  One example is `comsg`, which uses the same `coexecve`/`cocall` mechanisms,
but then makes design decisions very different from the `cocalls` branch.

Also note that this tutorial is about _using_ colocation, not about how it's implemented
underneath.


Setup
=====

You'll need CheriBSD built the usual way, preferably using `cheribuild`; the only difference is that the CheriBSD
branch should be `cocalls` instead of `main` or `dev`; do `cd ~/cheri/cheribsd && git switch cocalls` and then rebuild
(`./cheribuild.py cheribsd-riscv64-purecap disk-image-riscv64-purecap run-riscv64-purecap  --skip-update  --no-clean`).
You probably want to use riscv64-purecap, as the Morello version of the switcher is not working yet.


coexecve
========

This is the first of three layers.  It's about the ability to run multiple processes
in the same address space.  The reason for doing it is that memory capabilities can't
work between address spaces.  Thus, to use capabilities as a mechanism for processes
to communicate and share data, we need to put those processes in the same address space.
Because of CHERI we can allow this without compromising security - the protection
and isolation can be enforced by capabilities alone, without the need for MMU switching.
The only (expected) new way for colocated processes to be able to interfere with one
another, compared to a non-capability system, is by exhausing the virtual address space.
Traditional resource limits still work.

The only convenient moment to decide "where to put" a process is when executing a binary;
this typically means the execve(2) system call.  There are two ways to colocate:
one is by invoking coexecve(2) system call, which is similar to execve(2), but takes
an additional argument to indicate the PID of an existing process to colocate with.
The other is just ordinary execve(2) sysccall with `kern.opportunistic_coexecve` sysctl
set to 1 - this makes the kernel try to colocate processes whenever possible; by default
it tries to colocate them with their parent processes.

From the user point of view, when you login to CheriBSD as root, you can do:
```
root@cheribsd-riscv64-purecap:~ # ps aux -o vmaddr
USER  PID %CPU %MEM       VSZ   RSS TT  STAT STARTED       TIME COMMAND                    VMADDR
root   11 92.0  0.0         0    16  -  RNL  23:20   1032:27.42 [idle]           ffffffc000a160e0
root  838  3.0  0.5   1123268 10956 u0  S    16:45      0:00.29 -sh (sh)         ffffffd0014ed380
root  837  1.0  0.5   1123268 10956 u0  Ss   16:45      0:00.50 login [pam] (log ffffffd0014ed380
root    0  0.0  0.0         0   224  -  DLs  23:20      0:28.87 [kernel]         ffffffc000a160e0
root    1  0.0  0.1     16864  1376  -  SLs  23:20      0:00.20 /sbin/init       ffffffd0014ed1c0
root    2  0.0  0.0         0    16  -  WL   23:20      2:23.85 [clock]          ffffffc000a160e0
root    3  0.0  0.0         0    32  -  DL   23:20      0:00.00 [crypto]         ffffffc000a160e0
root    4  0.0  0.0         0    48  -  DL   23:20      0:00.00 [cam]            ffffffc000a160e0
root    5  0.0  0.0         0    16  -  DL   23:20      5:33.82 [rand_harvestq]  ffffffc000a160e0
root    6  0.0  0.0         0    48  -  DL   23:20      1:49.22 [pagedaemon]     ffffffc000a160e0
root    7  0.0  0.0         0    16  -  DL   23:20      0:00.00 [vmdaemon]       ffffffc000a160e0
root    8  0.0  0.0         0    48  -  DL   23:20      0:32.29 [bufdaemon]      ffffffc000a160e0
root    9  0.0  0.0         0    16  -  DL   23:20      0:09.88 [syncer]         ffffffc000a160e0
root   10  0.0  0.0         0    16  -  DL   23:20      0:00.00 [audit]          ffffffc000a160e0
root   12  0.0  0.0         0   112  -  WL   23:20      0:00.77 [intr]           ffffffc000a160e0
root   13  0.0  0.0         0    48  -  DL   23:20      0:00.05 [geom]           ffffffc000a160e0
root   14  0.0  0.0         0    16  -  DL   23:20      0:07.53 [vnlru]          ffffffc000a160e0
root  396  0.0  0.1   6398196  1452  -  Is   23:21      0:00.11 dhclient: system ffffffd0014ee700
root  399  0.0  0.1  74118452  1236  -  Is   23:21      0:00.19 dhclient: vtnet0 ffffffd0014ee8c0
_dhcp 467  0.0  0.1   8532880  1512  -  ICs  23:21      0:00.17 dhclient: vtnet0 ffffffd0014eec40
root  468  0.0  0.0 133631696   336  -  Is   23:21      0:01.88 /sbin/devd       ffffffd0014eee00
root  682  0.0  0.1  23311896  1740  -  Ss   23:21      0:06.86 /usr/sbin/syslog ffffffd0014ee380
root  781  0.0  0.1  19102964  2296  -  Is   23:21      0:00.07 sshd: /usr/sbin/ ffffffd0014efc40
root  840  0.0  0.5   1123268 10956 u0  R+   16:45      0:00.14 ps aux -o vmaddr ffffffd0014ed380
```
The rightmost column, VMADDR, identifies the address space.  Here you can see PIDs 838, 837,
and 840 sharing the same one - they are colocated.  You can view the address space layout like this:
```
root@cheribsd-riscv64-purecap:~ # procstat -v 837
  PID              START                END PRT    RES PRES REF SHD FLAG  TP PATH
  837           0x100000           0x105000 r--R-    5   16   4   2 CN--- vn /usr/bin/login
  837           0x105000           0x109000 r-xR-    4   16   4   2 CN--- vn /usr/bin/login
  837           0x109000           0x10a000 r--R-    1    0   1   0 CN--- vn /usr/bin/login
  837           0x10a000           0x10b000 rw-RW    1    0   1   0 CN--- vn /usr/bin/login
  837           0x10b000           0x10c000 rw-RW    1    1   1   0 CN--- sw
  838           0x10c000           0x11b000 r--R-   15   56  48   6 CN--- vn /bin/sh
  838           0x11b000           0x13c000 r-xR-   33   56  48   6 CN--- vn /bin/sh
  838           0x13c000           0x13e000 r--R-    2    0   1   0 CN--- vn /bin/sh
  838           0x13e000           0x141000 rw-RW    3    0   1   0 CN--- vn /bin/sh
  838           0x141000           0x143000 rw-RW    2    2   1   0 C---- sw
100000           0x143000           0x17d000 -----    0    0   0   0 ----- --
  842           0x17d000           0x18b000 r--R-   14   32   4   2 CN--- vn /usr/bin/procstat
  842           0x18b000           0x193000 r-xR-    8   32   4   2 CN--- vn /usr/bin/procstat
  842           0x193000           0x196000 r--R-    3    0   1   0 C---- vn /usr/bin/procstat
  842           0x196000           0x199000 rw-RW    3    0   1   0 C---- vn /usr/bin/procstat
 
[lots of shared library mappings snipped]
```
Observe the PID column - it indicates which process owns a mapping.  The kernel won't allow
processes to interfere with mappings owned (ie created) by others.

To manually force a binary to be colocated with another process use the coexec(1) command.

XXX most things stay as they were, but some how non-trivial consequences, eg after fork,
the child is no longer colocated with the parent, but after execve(2) it probably will.

There are several ways of sharing capabilities between processes: they can be sent
via the buffers provided to cocall(2), or via capv(7), or using the obsolete colookup(2)
system call, all of which are described below.  They can also be transferred over unix(4)
domain sockets (see `SCM_CAPS`) , similar to how file descriptors are.
Kernel will prevent the transfer if the sending and receiving processes are in different
address spaces.

cocall
======

This builds upon coexecve, as described above, to provide a fast RPC-like mechanism between colocated
processes.  It uses CHERI magic in the form of `ccall` CPU instruction to switch protection
domains without the need to enter the kernel.  From the user point of view it's all about
two functions: cocall(2) for the caller (client) side, and coaccept(2) for the callee (service)
side.

The cocall(2) side is simple: it takes a target capability, which identifies the service
to call, and two buffers; the content of the output buffer gets copied to the service side,
then cocall(2) sleeps waiting for the service to finish, then the input buffer
gets overwritten with data from the service, and the length of that data becomes cocall(2)'s
return value.

The coaccept(2) is the "service side", and it's to be called in a loop.  It also takes two buffers.
Every call to coaccept(2) copies its output buffer to caller's input buffer; then it sleeps
until invoked by another cocall(2).  It then returns with input buffer overwritten from caller's
output buffer.  Note how each invocation of coaccept(2) copies the output to the _previous_
caller, and later, after sleep, returns with input data from the _next_ caller.

Both cocall(2) and coaccept(2) calls have their cocall\_slow(2) and coaccept\_slow(2) counterparts.
Their semantics is (supposed to be) exactly the same; the difference is that the slow ones are
implemented as ordinary system calls, they don't use the switcher.  If something works with
cocall\_slow(2), but doesn't with plain cocall(2), it usually means a switcher bug.

Note that switcher bugs often manifest in ways that make one question their own sanity.  This is normal.
Most utilities provide the '-k' option to use kernel-based fallbacks instead.

Before using coaccept(2) or cocall(2) for the first time in a thread, call cosetup(2).  If
you are both the calling and the callee, call it twice.  The (to be) callee thread obtains
the target capability using coregister(2), then passes it to prospective callers either via
the capability vector, or over unix domain socket using `SCM_CAPS`.
See usr.bin/coregister/coregister.c for a code example.  There is also the colookup(2)
syscall, which provides a simpler way, but please don't use it.

On every return coaccept(2) fills in the `cookie`, which uniquely identifies the cocall(2)-ing
thread.  This value is supposed to be cached.  Threads with unrecognized cookie values can be identified
using cogetpid(2).  Being a system call, cogetpid(2) is an order of magnitude slower than
the cocall itself, thus the need for caching.
Or use cocachedpid(3) instead, which handles it for you.

The buffers used with coaccept(2) and cocall(2) must be capability-aligned, and so must their sizes.
If the services might end up in the capability vector, please follow the conventions in <sys/capv.h>;
apart from that the buffer contents are entirely application-defined, from raw binary ioctl structs
to JSON.  You might want to use nv(9).

This interface is strictly synchronous - which kind of follows from being optimised for low latency.
It also avoids the common problem of impedance mismatch between the kind of asynchronicity provided
by APIs and the one optimal for the application.
If you need async, have the service side queue up the transaction in whatever way you see fit,
wake up the worker thread, then return.

Thread-wise, this interface is N:1.  When the target is busy - ie not currently waiting in
coaccept(2) - another cocall(2) to that target will spin until it's free.  If that happens,
it usually means you should have multiple threads waiting on coaccept(2), and send their target
capabilities to the callers to cocall them directly.  Targets are cheap.  Different applications
might benefit from different strategies of spreading the workload, but there probably should
be a higher-level wrapper API implementing the few typical ones XXX.

Everything in UNIX revolves around file descriptors, and so there is a mechanism to "translate"
file descriptors into sealed capabilities and vice versa; grep the source for capfromfd(2)
and captofd(2) system calls.  This can be used to pass a file descriptor to a cocalled service.


capv
====

The capability vector is an array of capabilities inherited by child processes from the parent
process when colocated with it.  Typically it contains sealed target capabilities - the ones
to pass to cocall(2).  By default the vector is inherited unchanged by the child process,
as long as it's colocated with that parent.  This means that if you run sh(1) with a given vector,
every command you run, and every command run by a shell script you run, will inherit that
vector, and will be able to access the services.  One can execute a program with a different
capability vector by using the coexecvec(2) syscall.  Should it fail for no reason at all,
you probably need to use vfork(2) instead of fork(2).

To fetch the vector in a child process use elf_aux_info(3).  The capvset(3) function might
be of use too.

Initially the vector is empty; login as root, and do:
```
root@cheribsd-riscv64-purecap:~ # capv
capv: no capability vector
```
Now run the `clocks` service - which is a code example which implements clock\_gettime(2)
as a service call instead of the usual syscall - with shell as a child process:
```
root@cheribsd-riscv64-purecap:~ # clocks sh
root@cheribsd-riscv64-purecap:~ #
```
Seemingly nothing changed, but it's a different sh(1) instance, as shown by the process
tree on the right:
```
root@cheribsd-riscv64-purecap:~ # ps axld
UID PID PPID C PRI NI       VSZ   RSS MWCHAN   STAT TT     TIME COMMAND
  0   0    0 0 -16  0         0   224 swapin   DLs   -  0:00.14 [kernel]
  0   1    0 0  23  0     16864  1376 wait     ILs   -  0:00.17 - /sbin/init
  0 396    1 0  29  0   6398196  1452 select   Is    -  0:00.04 |-- dhclient: system.syslog (dhclient)
  0 399    1 0  68  0  52956192  1236 select   Is    -  0:00.07 |-- dhclient: vtnet0 [priv] (dhclient)
 65 467    1 0  23  0   8532880   948 select   ICs   -  0:00.02 |-- dhclient: vtnet0 (dhclient)
  0 468    1 0  20  0 133631696   336 select   Ss    -  0:00.01 |-- /sbin/devd
  0 682    1 0  20  0  23311896  1740 select   Ss    -  0:00.12 |-- /usr/sbin/syslogd -s
  0 781    1 0  68  0  19102964  2296 select   Is    -  0:00.07 |-- sshd: /usr/sbin/sshd [listener] 0 of 10-100 startups (sshd)
  0 794    1 0  28  0   3273292 17048 wait     Is   u0  0:00.42 `-- login [pam] (login)
  0 795  794 0  20  0   3273292 17048 wait     I    u0  0:00.26   `-- -sh (sh)
  0 799  795 0  29  0   3273292 17048 copark   IC   u0  0:00.07     `-- clocks sh
  0 800  799 0  20  0   3273292 17048 wait     S    u0  0:00.18       `-- sh
  0 801  800 0  34  0   3273292 17048 -        R+   u0  0:00.09         `-- ps axld
```
 
You can see the login shell, PID 795, the `clocks` service, PID 799, and the shell it started, PID 800.  You
can also see that WCHAN for `clocks` is "copark", which means it's waiting on coaccept(2).
Now:
```
root@cheribsd-riscv64-purecap:~ # capv -c
8:      0x13000 [rwRW,0x13000-0x14000] (sealed):	"clocks(1), pid 799, responding to clock_gettime()"
```

This shows the capability vector, which for now contains only one capability: the clocks service,
at offset 8; the rest of the vector is NULLs.
Services tend to use predefined, even offsets; clocks is 8.  The string to the right is what the service
responded with - it returns a literal string in an "answerback" packet; you can snoop on the
communication between `capv` and `clocks`:
```
root@cheribsd-riscv64-purecap:~ # cotrace -v capv
cotrace: cocall from pid 810[8] -> pid 809, received 16, len 16, op 12: "\020\0\0\0\0\0\0\0\f\0\0\0\0\0\0\0"
cotrace: returning to pid 810[8] <- pid 809, len 48, op -8: "0\0\0\0\0\0\0\0\370\377\377\377\0\0\0\0\0\0\0\0\0\0\0\0~\001\0\0\0\0\0\0\207\252\2178\0\0\0\0\0\0\0\0\0\0\0\0"
cotrace: cocall from pid 810[8] -> pid 809, received 16, len 16, op 12: "\020\0\0\0\0\0\0\0\f\0\0\0\0\0\0\0"
cotrace: returning to pid 810[8] <- pid 809, len 48, op -8: "0\0\0\0\0\0\0\0\370\377\377\377\0\0\0\0\0\0\0\0\0\0\0\0~\001\0\0\0\0\0\0\017\335\3318\0\0\0\0\0\0\0\0\0\0\0\0"
cotrace: cocall from pid 810[8] -> pid 809, received 16, len 16, op 12: "\020\0\0\0\0\0\0\0\f\0\0\0\0\0\0\0"
cotrace: returning to pid 810[8] <- pid 809, len 48, op -8: "0\0\0\0\0\0\0\0\370\377\377\377\0\0\0\0\0\0\0\0\0\0\0\0~\001\0\0\0\0\0\0s+\3778\0\0\0\0\0\0\0\0\0\0\0\0"
cotrace: cocall from pid 810[8] -> pid 809, received 16, len 16, op 0: "\020\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
cotrace: returning to pid 810[8] <- pid 809, len 1040, op 0: "\020\004\0\0\0\0\0\0\0\0\0\0clocks(1), pid 799, responding to clock_gettime()\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
cotrace: returning answerback to pid[810] 8 <- pid 809
8:      "clocks(1), pid 799, responding to clock_gettime() -- via cotrace(1..."
```

Each line is either a cocall or a return from a cocall.  Those '\0' are zeroes; it's the binary dump of output
buffers passed to cocall(3) and coaccept(2).
The first couple of cocalls you see is jemalloc(3) calling clock\_gettimeofday(2) for... whatever reason.
The buffers returned are 'struct timespec' contents.
The last cocall returns the answerback, which contains an embedded string that capv(1) then displays.

Note that `cotrace` is itself a special kind of service.
Also observe how in this example the answerback was actually different - it's because cotrace(1), being an interposer,
added its own piece of text there.  The convention here is that services can be chained, similar to how
the traditional nice(1) command is used.  Thus, the example above could instead be run as:
```
# clocks cotrace capv
```

The capability vector is inherited by default, as long as the child process is colocated with the parent,
which it usually is because of opportunistic colocation.
But sometimes this parent-descendants model is not enough.  That's when coregister(1) and colookup(1)
utilities can be used.  The former "pushes" a capability over unix domain
socket (a "file system" socket); the latter receives it.  Thus:
```
# clocks -v coregister -i8 -f socket-path &
# colookup -f socket-path -i8 capv
```

Observe how capv(1) calls into service 8, clocks(1), even though it's not its descendant.  This can be used
to run a service as a different user.

Benchmarks
==========

If you wanted to perform a quick comparison between normal and slow cocalls: start a shell with two
services, ping them, exit that shell, start it again but this time with one of them
in slow mode (`-k`), and ping again; observe the reported speed difference:
```
root@cheribsd-riscv64-purecap:~ # clocks binds sh
root@cheribsd-riscv64-purecap:~ # capv
8:      "clocks(1), pid 819, responding to clock_gettime()"
10:     "binds(1), pid 820, allowed port -1 (capsicum disabled)"
root@cheribsd-riscv64-purecap:~ # coping -ac 1000
coping: capv[8]: 51.552ms for 1000 iterations, 51.552us each
coping: capv[10]: 52.214ms for 1000 iterations, 52.214us each
root@cheribsd-riscv64-purecap:~ # ^D
root@cheribsd-riscv64-purecap:~ # clocks binds -k sh
root@cheribsd-riscv64-purecap:~ # capv
8:      "clocks(1), pid 824, responding to clock_gettime()"
10:     "binds(1), pid 825, allowed port -1 (slow) (capsicum disabled)"
root@cheribsd-riscv64-purecap:~ # coping -ac 1000
coping: capv[8]: 50.656ms for 1000 iterations, 50.655us each
coping: capv[10]: 270.122ms for 1000 iterations, 270.122us each
```
There's also cocall support in syscall\_timing(1).


Repo organisation
=================

There are three branches: `coexecve`, `cocall`, and `cocalls`.  Branching goes like this: `dev` -> `coexecve` -> `cocall` -> `cocalls`.

Use `git diff coexecve..cocall` or `git diff cocall..cocalls` for the diff between branches.

