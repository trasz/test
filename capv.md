Colocation tutorial
===================

PROTIP: Take a look at "man 7 capv" on the nearest Morello box.  Many/most things
described here have man pages, so one can do eg `man colookup`.

The whole topic below is conceptually split into three "layers", each building upon
the previous one.  This is to make it easy to substitute the higher layers with something
else.  One example is `comsg`, which uses the same `coexecve`/`cocall` mechanisms,
but then makes design decisions very different from what's happening in the `cocalls` branch.

Also note that this tutorial is about _using_ colocation, not about how it's implemented
under the hood.


Setup
=====

You'll need CheriBSD built the usual way, preferably using `cheribuild`; the only difference is that the CheriBSD
branch should be `cocalls` instead of `main` or `dev`; do `cd ~/cheri/cheribsd && git switch cocalls` and then rebuild
(`./cheribuild.py cheribsd-riscv64-purecap disk-image-riscv64-purecap run-riscv64-purecap  --skip-update  --no-clean`).
You probably want to use riscv64-purecap, as the Morello version of the switcher is not working yet.


coexecve
========

This is the first of three layers.  It's about the ability to have multiple processes
running in the same address space.  The reason for doing it is that memory capabilities
can't work between address spaces.  Thus, to use capabilities as a mechanism for processes
to communicate and share data, we need to put those processes in the same space.
Because of CHERI we can allow this without compromising security - the protection
and isolation can be enforced by capabilities alone, without the need for MMU switching.
The only (expected) new way for colocated processes to be able to interfere with one
another, compared to a traditional, non-capability Unix system, is by exhausting the virtual
address space.  Traditional resource limits still work.

The convenient moment to decide "where to put" a process is when executing the binary;
this typically means the execve(2) system call.  There are two ways to colocate.
The first one is by invoking coexecve(2) system call, which is similar to execve(2),
but takes an additional argument to indicate the PID of an existing process to colocate with.
This is useful for software that makes explicit use of colocation, like the colocated
Apache SSL sandbox (https://github.com/CTSRD-CHERI/sslproc; see `apache-sslproc` `cheribuild` target).
There is also the coexec(1) command, to explicitly run a binary colocated with another
process, which can serve as a trivial code example; see `usr.bin/coexec/coexec.c`.

The other way is the ordinary execve(2) syscall (or posix\_spawn(2), ie any kind of running a binary)
with `kern.opportunistic_coexecve` sysctl set to 1 - this makes the kernel try to colocate
processes whenever possible.  By default it tries to colocate them with their parents,
falling back to the traditional behaviour of allocating new address spaces.
This is useful for enabling communication between independent programs, eg within
a shell session.

Both mechanisms can be used at the same time - processes that are not explicitly
colocated using coexecve(2) will still get colocated opportunistically.

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
The rightmost column, VMADDR, identifies the address space.  Here you can see processes identified
by PIDs 838, 837, and 840 are sharing the same space - they are colocated.  In this case those
processes don't know anything about colocation; they got colocated opportunistically.

You can view the address space layout like this:
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
Observe the leftmost PID column - it indicates which process owns a memory mapping.
The kernel won't allow processes to interfere with mappings owned (ie created) by others.
Without colocation, all the mappings within an address space would belong to the same
process.

Colocation was designed to follow the usual Unix conventions.  There are a few cases
where this leads to non-intuitive outcomes - for example, after calling fork(2), the
child ends up in its own address space - which means it's no longer colocated with its
parent.  In most cases it will become colocated again after it executes a binary.

There are several ways of transferring capabilities between processes: they can be sent
via the buffers provided to cocall(2), or passed to a child via capv(7), transferred
over unix(4) domain sockets (see `SCM_CAPS`), or published using the obsolete colookup(2)
system call; some of those methods are described further below.
For security reasons the kernel will prevent the transfer if sending and receiving
processes are in different address spaces.

Sending memory capabilities over unix domain socket works similar in concept to
sending file descriptors using `SCM_RIGHTS`; one important difference is that the
capabilities can only be received by a process running in the same address space as
the sending process.
The sending side looks like this (`usr.bin/coregister/coregister.c`; `target`
is the `void * __capability` being sent over unix(4) socket indicated by `clientfd`):
```
	memset(&msg, 0, sizeof(msg));
	msg.msg_control = &cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);
	msg.msg_iov = NULL;
	msg.msg_iovlen = 0;

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(target));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_CAPS;
	memcpy(CMSG_DATA(cmsg), &target, sizeof(target));

	sent = sendmsg(clientfd, &msg, MSG_NOSIGNAL);
	if (sent < 0)
		warn("sendmsg");
```

Corrensponding receiving side (`usr.bin/colookup/colookup.c`; `target` is being
received from `fd`) is:
```
	memset(&msg, 0, sizeof(msg));
	msg.msg_control = &cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);
	msg.msg_iov = NULL;
	msg.msg_iovlen = 0;

	received = recvmsg(fd, &msg, MSG_WAITALL);
	if (received != 0)
		err(1, "%s: recvmsg", filename);
	cmsg = CMSG_FIRSTHDR(&msg);
	memcpy(&target, CMSG_DATA(cmsg), sizeof(target));
```

cocall
======

This builds upon coexecve, as described above, to provide a fast RPC-like mechanism between colocated
processes.

Processes are Unix' natural compartments, and lots of existing software makes use of that model.
The problem is, they are heavy-weight; communication and context switching overhead make
using them for fine-grained compartmentalisation impractical.  Cocalls, being fast (order of magnitude
slower than a function call, order of magnitude faster than a cheapest syscall), aim to fix that problem.

This functionality revolves around two functions: cocall(2) for the caller (client) side,
and coaccept(2) for the callee (service) side.  Underneath they are implemented using CHERI magic
in the form of `ccall` CPU instruction to switch protection domains without the need to enter the kernel,
but from the API user point of view they mostly look like ordinary system calls and follow typical
system call conventions, `errno` et al.

This also applies to security - assume mutual distrust.  On every call, the called side receives
the information on caller's identity, the contents of their output buffer, and length of that buffer.
It can return to the caller once.  Upon return the caller receives the contents of the callee's output
buffer, its size, and errno for the cocall(2) itself.  The buffer contents are copied; the raw
capabilities to buffers are not passed to the other side.  The capabilities _within_ buffers are passed
verbatim though, and can be dereferenced by the other side.  Watch out what you send, or strip
the 'load capability' permission from the output buffer capability before passing it to coaccept(2)
or cocall(2).

The cocall(2) function takes a target capability, which identifies the service
to call, and two buffers; the content of the output buffer gets copied to the service side,
then cocall(2) sleeps waiting for the service to finish, then the input buffer
gets overwritten with data from the service, and the length of that data becomes cocall(2)'s
return value.

The coaccept(2) is the "service side", and it's to be called in a loop.  It also takes two buffers.
Every call to coaccept(2) copies its output buffer to caller's input buffer; then it sleeps
until invoked by another cocall(2).  It then returns with input buffer overwritten from caller's
output buffer.  Note how each invocation of coaccept(2) copies the output to the _previous_
caller, and later, after sleep, returns with input data from the _next_ caller.

Here is a code example of two threads using this mechanism to communicate
(`usr.bin/stevie/stevie.c` in CheriBSD `cocalls` branch):
```
#include <err.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static pthread_t		service_thread;
static void * __capability	target;

static void *
service_function(void *dummy __unused)
{
	/*
	 * Can't use int here, because buffers need to be capability-aligned.
	 * This will happen naturally when using malloc(3), but for now lets keep
	 * it simple and use a capability-sized integer type instead.
	 */
	intcap_t buf = 0;
	ssize_t received;
	int error;

	/*
	 * Every thread needs to do this once before calling coaccept(2).
	 */
	error = cosetup(COSETUP_COACCEPT);
	if (error != 0)
		err(1, "cosetup");

	/*
	 * Ask kernel for the target capability to call into this thread;
	 * the `target` is a global variable, to be used by the calling thread.
	 */
	error = coregister(NULL, &target);
	if (error != 0)
		err(1, "coregister");

	/*
	 * Now loop until the process exits.
	 */
	for (;;) {
		/*
		 * Send back the response, if any, then wait for next caller.
		 */
		received = coaccept(NULL, &buf, sizeof(buf), &buf, sizeof(buf));
		if (received < 0)
			err(1, "cocall");

		/*
		 * Got a call, bump the counter and loop.
		 */
		printf("accepted, counter is %d\n", (int)buf);
		buf++;
	}
}

int
main(int argc __unused, char **argv __unused)
{
	intcap_t buf = 0;
	ssize_t received;
	int error, i;

	/*
	 * Create the thread to wait on coaccept(2).
	 */
	error = pthread_create(&service_thread, NULL, service_function, NULL);
	if (error != 0)
		err(1, "pthread_create");

	/*
	 * Give the service thread a moment to start coaccepting before we proceed;
	 * otherwise cocall(3) might fail with EAGAIN.
	 */
	usleep(1000);

	/*
	 * Every thread needs to do this once before calling cocall(2).
	 * Call it twice if it needs both coaccept(2) and cocall(2).
	 */
	error = cosetup(COSETUP_COCALL);
	if (error != 0)
		err(1, "cosetup");

	/*
	 * Do the thing a couple of times.
	 */
	for (i = 3; i > 0; i--) {
		printf("calling %lp...\n", target);
		received = cocall(target, &buf, sizeof(buf), &buf, sizeof(buf));
		if (received < 0)
			err(1, "cocall");
		printf("returned, counter is %d\n", (int)buf);
	}

	/*
	 * Exit.
	 */
	return (0);
}
```

Despite cocall(2) being advertised as an RPC mechanism, it does not say anything about
opcodes or methods. Instead it's entirely application-defined, left for a higher layer,
with cocall(2) only handling the data and execution transfers.
The reasoning here is that consumers typically already have their own ideas about what to send
and how to pack it - cocall buffers can thus carry DBus packets, or binary ioctl structs, or JSON.
Otherwise nv(9) is a good option.  Note that this also applies to return values - do not try
to overload the value returned by cocall(2); instead pack the application-level return status
(including errno, sense data or whatever else) into coaccept's output buffer.

Buffers to be used with coaccept(2) and cocall(2) must be capability-aligned, and so must their sizes.
If the services might end up in the capability vector, please follow the conventions in <sys/capv.h>.

This interface is strictly synchronous - which kind of follows from being optimised for low latency.
It also avoids the common problem of impedance mismatch between the kind of asynchronicity provided
by APIs and the one optimal for the application.
If you need async, have the service side queue up the transaction in whatever way you see fit,
wake up the worker thread, then return.

Thread-wise, this interface is N:1.  When the target is busy - ie not currently waiting in
coaccept(2) - another cocall(2) to that target will spin until it's free.  When that happens,
it usually means you should have multiple threads waiting on coaccept(2), and send their target
capabilities to callers to cocall them directly.  Targets are cheap.  Different applications
might benefit from different strategies of spreading the workload, but there probably should
be a higher-level wrapper API implementing the few typical ones.

On every return coaccept(2) fills in the `cookie` argument (if provided), which uniquely identifies the cocall(2)-ing
thread.  This value is supposed to be cached.  Threads with unrecognized cookie values can be identified
using cogetpid(2).  Being a system call, cogetpid(2) is an order of magnitude slower than
the cocall itself, thus the need for caching.
Or use cocachedpid(3) instead, which handles it for you.

Both cocall(2) and coaccept(2) calls have their cocall\_slow(2) and coaccept\_slow(2) counterparts.
Their semantics is (supposed to be) exactly the same; the difference is that the slow ones are
implemented as ordinary system calls, they don't use the switcher.  If something works with
cocall\_slow(2), but doesn't with plain cocall(2), it usually means a switcher bug.

Note that switcher bugs often manifest in ways that make one question their own sanity.  This is normal.
Most utilities provide the '-k' option to use kernel-based fallbacks instead.

Everything in UNIX revolves around file descriptors, and so there is a mechanism to "translate"
file descriptors into sealed capabilities and vice versa; grep the source for capfromfd(2)
and captofd(2) system calls.  This can be used to pass a file descriptor to a cocalled service,
similar how one can pass them over unix domain sockets.   This interface is a very much work
in progress, but there is example code in `usr.bin/binds/binds.c` and it looks like this:
```
	received = coaccept(&cookie, out, out->len, &in, sizeof(in));
	if (received < 0) {
		warn("%s", kflag ? "coaccept_slow" : "coaccept");
		...
	}
	if ((size_t)received != sizeof(in)) {
		warnx("size mismatch: received %zd, expected %zd",
		    (size_t)received, sizeof(in));
		...
	}
	error = captofd(in.s, &fd);
	if (error != 0) {
		warn("captofd: %#lp", in.s);
		...
	}

	[..]

	error = close(fd);
```
The other side of that interface is in `lib/libbinds/binds.c`.


capv
====

The capability vector is an array of capabilities inherited by child processes from the parent
process.  In that regard it is somewhat similar to traditional Unix open
file descriptors, environment variables, or security credentials; the exact inheritance policy
is a bit more involved, but as a general rule the vector will never get inherited in any case where
file descriptors wouldn’t; this fact should simplify reasoning about its security properties.

Typically the capability vector contains sealed target capabilities - the ones to pass to cocall(2).
By default the vector is inherited unchanged by the child process,
as long as it's colocated with that parent.  This means that if you run sh(1) with a given vector,
every command you run, and every command run by a shell script you run, will inherit that
vector, and will be able to access the services.  One can execute a program with a different
capability vector by using the coexecvec(2) syscall.  Should it fail for no reason at all,
you probably need to use vfork(2) instead of fork(2).

To fetch the vector in a child process use elf\_aux\_info(3), or the capvfetch(3) libc wrapper;
see `usr.bin/capv/capv.c`.  The capvset(3) function might be of use too.

Initially the vector is empty; login as root, and do:
```
root@cheribsd-riscv64-purecap:~ # capv
capv: no capability vector
```
Now run the `clocks` service - an example service (`usr.bin/clocks/clocks.c`) which implements clock\_gettime(2)
as a cocall instead of the usual syscall - with shell as a child process:
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
in slow mode ('-k'), and ping again; observe the reported speed difference:
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

