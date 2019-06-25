/*	$Id$ */
/*
 * Copyright (c) 2019 Shawn Anastasio <shawn@anastas.io>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * This file contains the Linux implementation of some wrappers for
 * OpenBSD-only functions
 */

#define ARRAY_SIZE(x) (sizeof((x)) / sizeof(*(x)))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

/* Most of these are for seccomp */
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <asm/unistd.h>
#include <asm/ptrace.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ucontext.h>

#define SYS_SECCOMP 1

#include "compat.h"
#include "seccomp_broker.h"

/* Re-implement recallocarray in terms of calloc, malloc, and memset */
void *
recallocarray(void *ptr, size_t oldnmemb, size_t nmemb, size_t size)
{
	size_t newsize, oldsize;
	void *newmem;

	if (!ptr) {
		/* Just allocate new memory with calloc */
		return calloc(nmemb, size);
	}

	if (__builtin_mul_overflow_p(size, nmemb, (size_t)0)) {
		errno = ENOMEM;
		return NULL;
	}
	newsize = size * nmemb;

	if (__builtin_mul_overflow_p(size, oldnmemb, (size_t)0)) {
		errno = ENOMEM;
		return NULL;
	}
	oldsize = size * oldnmemb;

	newmem = malloc(newsize);
	if (!newmem)
		return NULL;

	if (newsize > oldsize) {
		/* copy old memory and pad the end with zero */
		memcpy(newmem, ptr, oldsize);
		memset((char *)newmem + oldsize, 0, newsize - oldsize);
	} else {
		memcpy(newmem, ptr, newsize);
	}

	/* erase the old memory region */
	explicit_bzero(ptr, size * oldnmemb);
	free(ptr);

	return newmem;
}

/* "stdio unix rpath wpath cpath dpath inet fattr chown dns getpw proc exec unveil" */

/*
 * Pledge/Unveil wrappers.
 *
 * Pledge works by generating a seccomp-bpf filter to allow classes
 * of system calls. Note that the syscall lists are not complete and only
 * include calls that are required by this program.
 *
 * Unveil works by having the filter trap on syscalls that accept
 * a path (open(), openat(), etc.) to the SIGSYS handler.
 * The SIGSYS handler forwards the syscall and its arguments to
 * a broker process that is unencumbered by the seccomp filter.
 *
 * If the broker process decides to allow the syscall, it
 * performs it and then forwards the resultant file descriptor
 * to the main process using ancillary data messages.
 */

#if defined(__powerpc64__)
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define TARGET_AUDIT_ARCH AUDIT_ARCH_PPC64LE
#else
#define TARGET_AUDIT_ARCH AUDIT_ARCH_PPC64
#endif

/* on ppc64 syscall errors are positive */
#define POSITIVE_ERRNO 1
#define SECCOMP_SET_ERROR(ucontext)((ucontext)->uc_mcontext.gp_regs[PT_CCR] |= (1 << 28))
#define SECCOMP_CLR_ERROR(ucontext)((ucontext)->uc_mcontext.gp_regs[PT_CCR] &= ~(1 << 28))

/* The following macros are used to access syscall arguments stored in a ucontext */
#define SECCOMP_RET(ucontext) ((ucontext)->uc_mcontext.gp_regs[PT_R3])
#define SECCOMP_SYSNR(ucontext) ((ucontext)->uc_mcontext.gp_regs[PT_R0])
#define SECCOMP_ARG0(ucontext) ((ucontext)->uc_mcontext.gp_regs[PT_R3])
#define SECCOMP_ARG1(ucontext) ((ucontext)->uc_mcontext.gp_regs[PT_R4])
#define SECCOMP_ARG2(ucontext) ((ucontext)->uc_mcontext.gp_regs[PT_R5])
#define SECCOMP_ARG3(ucontext) ((ucontext)->uc_mcontext.gp_regs[PT_R6])
#define SECCOMP_ARG4(ucontext) ((ucontext)->uc_mcontext.gp_regs[PT_R7])
#define SECCOMP_ARG5(ucontext) ((ucontext)->uc_mcontext.gp_regs[PT_R8])

#elif defined(__x86_64__)

#define TARGET_AUDIT_ARCH AUDIT_ARCH_X86_64

#define POSITIVE_ERRNO 0
#define SECCOMP_SET_ERROR(x) (void)(x)
#define SECCOMP_CLR_ERROR(x) (void)(x)

#define SECCOMP_RET(ucontext) ((ucontext)->uc_mcontext.gregs[REG_RAX])
#define SECCOMP_SYSNR(ucontext) ((ucontext)->uc_mcontext.gregs[REG_RAX])
#define SECCOMP_ARG0(ucontext) ((ucontext)->uc_mcontext.gregs[REG_RDI])
#define SECCOMP_ARG1(ucontext) ((ucontext)->uc_mcontext.gregs[REG_RSI])
#define SECCOMP_ARG2(ucontext) ((ucontext)->uc_mcontext.gregs[REG_RDX])
#define SECCOMP_ARG3(ucontext) ((ucontext)->uc_mcontext.gregs[REG_R10])
#define SECCOMP_ARG4(ucontext) ((ucontext)->uc_mcontext.gregs[REG_R8])
#define SECCOMP_ARG5(ucontext) ((ucontext)->uc_mcontext.gregs[REG_R9])

#else
#error "Your architecture isn't known! Add it here"
#endif

#define SD_OFF(x) offsetof(struct seccomp_data, x)

/* fd to the broker socket */
static int broker_fd = -1;

struct bpf_program {
	struct sock_filter *program;
	size_t progsize;

	/*
	 * vpc - virtual program counter
	 * Represents the first free offset in the program
	 */
	uint16_t vpc;
};

static void
seccomp_abort(void)
{
	_exit(1);
}

/*
 * Forward a syscall to the broker and update the ucontext
 *
 * Returns -1 if the broker couldn't be reached or didn't
 * know how to handle the syscall, 0 otherwise.
 */
static int
forward_syscall_to_broker(ucontext_t *uc)
{
	int ret = 0;
	int newfd;
	struct broker_msg bmsg;
	/* Forward the syscall */
	struct client_msg msg = {
		.type = CLIENT_MTYPE_SYSCALL,
		.syscall = {
			.nr = SECCOMP_SYSNR(uc),
			.args = {
				SECCOMP_ARG0(uc),
				SECCOMP_ARG1(uc),
				SECCOMP_ARG2(uc),
				SECCOMP_ARG3(uc),
				SECCOMP_ARG4(uc),
				SECCOMP_ARG5(uc),
			}
		}
	};

	if (broker_send(broker_fd, &msg, sizeof(struct client_msg), -1) < 0)
		return -1;

	/* Recieve the response */
	if (broker_recv(broker_fd, &bmsg, sizeof(struct broker_msg), &newfd) < 0)
		return -1;

	/* Check for invalid type */
	if (bmsg.type != BROKER_MTYPE_SYSCALL)
		return -1;

	if (bmsg.syscall.flags & RESP_FLAG_ERR) {
		/* Syscall was emulated but failed */
		SECCOMP_SET_ERROR(uc);
#if POSITIVE_ERRNO
		SECCOMP_RET(uc) = bmsg.syscall.result;
#else
		SECCOMP_RET(uc) = -bmsg.syscall.result;
#endif
		return 0;
	}

	if (bmsg.syscall.flags & RESP_FLAG_FD) {
		/* Broker sent us a file descriptor to use as the result */
		SECCOMP_CLR_ERROR(uc);
		SECCOMP_RET(uc) = newfd;
		return 0;
	} else {
		SECCOMP_CLR_ERROR(uc);
		SECCOMP_RET(uc) = bmsg.syscall.result;
		return 0;
	}
}

static void
seccomp_sigsys_handler(int sig, siginfo_t *info, void *ucontext_)
{
	int old_errno = errno;
	int sysnr;
	ucontext_t *uc = ucontext_;

	if (info->si_code != SYS_SECCOMP)
		/* This signal wasn't sent from seccomp. Crash. */
		_exit(1);

	/* Handle differently depending on the syscall */
	sysnr = SECCOMP_SYSNR(uc);
	switch (sysnr) {
	case __NR_socket:
		/* Simply forward the syscall to the broker */
		if (forward_syscall_to_broker(uc) < 0)
			seccomp_abort();
	}
out:
	errno = old_errno;
}

enum promise {
	PROMISE_STDIO = 1U << 0,
	PROMISE_RPATH = 1U << 1,
	PROMISE_WPATH = 1U << 2,
	PROMISE_CPATH = 1U << 3,
	PROMISE_DPATH = 1U << 4,
	PROMISE_TMPPATH = 1U << 5,
	PROMISE_INET  = 1U << 6,
	PROMISE_MCAST = 1U << 7,
	PROMISE_FATTR = 1U << 8,
	PROMISE_CHOWN = 1U << 9,
	PROMISE_FLOCK = 1U << 10,
	PROMISE_UNIX = 1U << 11,
	/* TODO: more promise groups */

	PROMISE_INVALID = 1U << 31
};

static const char *promise_names[] = {
	"stdio",
	"rpath",
	"wpath",
	"cpath",
	"dpath",
	"tmppath",
	"inet",
	"mcast",
	"fattr",
	"chown",
	"flock",
	"unix",
};

enum promise
promise_from_str(const char *promise)
{
	size_t i;
	for (i = 0; i < ARRAY_SIZE(promise_names); i++) {
		const char *cur = promise_names[i];
		if (strncmp(promise, cur, strlen(cur)) == 0)
			return (1U << i);
	}
	return PROMISE_INVALID;
}


/*
 * Initialize a bpf_program with an optional preamble that
 * performs sanity checks and whitelists required syscalls.
 *
 * first - whether or not this is the first filter
 * if not, the preamble will not be included
 *
 * broker_fd - file descriptor of socket shared with broker process.
 * will be allowed to use sendmsg/recvmsg unconditionally
 */
static struct bpf_program *
bpf_program_init(int first, int broker_fd)
{
	const struct sock_filter preamble[] = {
		/* Check that architecture matches and load sysnr */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SD_OFF(arch)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TARGET_AUDIT_ARCH, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SD_OFF(nr)),

		/* Certain syscalls should always be allowed, like exit */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit_group, 2, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit, 1, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigreturn, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

		/* Allow prctl(PR_SET_SECCOMP, *) so we can install new filters */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_prctl, 0, 4),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SD_OFF(args[0])),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_SET_SECCOMP, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),

		/* Allow sendmsg/recvmsg to the broker fd */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmsg, 1, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_recvmsg, 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SD_OFF(args[0])),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, broker_fd, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SD_OFF(nr)),
	};

	struct bpf_program *bpfprog = malloc(sizeof(struct bpf_program));
	if (!bpfprog)
		return NULL;

	/* Reserve 100 instructions for initial program */
	bpfprog->progsize = 100;
	bpfprog->program = calloc(bpfprog->progsize, sizeof(struct sock_filter));
	if (!bpfprog->program) {
		free(bpfprog);
		return NULL;
	}

	/* If this is the first filter, copy the preamble */
	if (first) {
		memcpy(bpfprog->program, preamble, sizeof(preamble));
		bpfprog->vpc = ARRAY_SIZE(preamble);
	} else {
		/* For secondary filters, just load nr into ACC */
		*bpfprog->program = (struct sock_filter)
					BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SD_OFF(nr));
		bpfprog->vpc = 1;
	}

	return bpfprog;
}

static void
bpf_program_free(struct bpf_program *bpfprog)
{
	free(bpfprog->program);
	free(bpfprog);
}

static int
bpf_program_append(struct bpf_program *bpfprog,
		struct sock_filter *insns, size_t n)
{
	if (bpfprog->vpc + n <= bpfprog->progsize) {
		while (n-- > 0)
			memcpy(&bpfprog->program[bpfprog->vpc++], insns++,
					sizeof(struct sock_filter));

		return 0;
	}

	if (__builtin_mul_overflow_p(n, sizeof(struct sock_filter),
							(size_t)0)) {
		errno = ENOMEM;
		return -1;
	}

	size_t newprogsize = MIN(bpfprog->progsize * 2, bpfprog->progsize +
				(n * sizeof(struct sock_filter)));
	void *newprog = reallocarray(bpfprog->program, newprogsize,
					sizeof(struct sock_filter));
	if (!newprog)
		return -1;

	bpfprog->program = newprog;
	bpfprog->progsize = newprogsize;

	while (n-- > 0)
		memcpy(&bpfprog->program[bpfprog->vpc++], insns++,
			sizeof(struct sock_filter));

	return 0;
}

/*
 * Compile a block of conditional jumps that compares the accumulator
 * to every int in `syslist` and returns `seccomp_ret` on matches
 */
static int
bpf_program_compile_list_check(struct bpf_program *bpfprog, const int syslist[],
				size_t cnt, uint32_t seccomp_ret)
{
	/* offset of final ret instruction from cur insn */
	size_t target = cnt - 1;
	size_t i;

	if (cnt > 255)
		/* BPF conditional jumps have an 8bit target field */
		return -1;

	/* Assemble the conditional jumps (except for the last one) */
	for (i = 0; i < cnt - 1; i++) {
		struct sock_filter insn[] = {
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syslist[i], target, 0)
		};
		--target;

		if (bpf_program_append(bpfprog, insn, 1) < 0)
			return -1;
	}

	/* Assemble final conditional and ret */
	struct sock_filter insns[] = {
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syslist[i], 0, 1),
		BPF_STMT(BPF_RET | BPF_K, seccomp_ret)
	};

	if (bpf_program_append(bpfprog, insns, 2) < 0)
		return -1;

	return 0;
}

static int
bpf_program_compile_promise_stdio(struct bpf_program *bpfprog, int allow)
{
	/* stdio is simple: just allow all syscalls on the list */
	/* The exception is sendto(2), which isn't even used by us */
	const int stdio_syscalls[] = {
		__NR_dup,
		__NR_close,
		__NR_read,
		__NR_write,
		__NR_socketpair,
		__NR_mmap,
#ifdef __NR_mmap2
		__NR_mmap2,
#endif
		__NR_fstat, /* TODO: this is rpath, not stdio */
	};

	/*
	 * Compile a sequence of conditional jumps that will return
	 * the appropriate seccomp ret (depending on `allow`) for
	 * each of of the syscalls in the stdio promise
	 */
	if (bpf_program_compile_list_check(bpfprog, stdio_syscalls,
				ARRAY_SIZE(stdio_syscalls),
				allow ? SECCOMP_RET_ALLOW : SECCOMP_RET_KILL) < 0) {
		return -1;
	}

	return 0;
}

static int
bpf_program_compile_promise_unix_inet(struct bpf_program *bpfprog, int allow) {
	/*
	 * True emulation of the unix and inet promises seems difficult.
	 * Instead, trap all socket(2) calls to be emulated in the broker.
	 * The broker will record all created fds along with their family.
	 * On promise revoke, it will send this list to the main thread
	 * for all fds to be close(2)'d.
	 *
	 * This means that the distinction between inet and unix occurs
	 * in the broker, not in the seccomp filter, hence the shared
	 * routine.
	 *
	 * As for the other calls (listen, bind, etc.) as long as one
	 * socket promise is present, allow them all unconditionally.
	 * The aforementioned socket(2) limitations should be enough.
	 */

	struct sock_filter socket_check[] = {
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, allow ? SECCOMP_RET_TRAP :
						SECCOMP_RET_KILL)
	};

	if (bpf_program_append(bpfprog, socket_check,
				ARRAY_SIZE(socket_check)) < 0) {
		return -1;
	}

	// Unconditionally allow (or kill if allow=0) the rest of the calls
	const int syscalls_trap[] = {
		__NR_listen,
		__NR_bind,
		__NR_connect,
		__NR_accept,
		__NR_accept4,
		__NR_getpeername,
		__NR_getsockname,
		__NR_getsockopt,
		__NR_setsockopt
	};

	if (bpf_program_compile_list_check(bpfprog, syscalls_trap,
				ARRAY_SIZE(syscalls_trap),
				allow ? SECCOMP_RET_ALLOW : SECCOMP_RET_KILL) < 0) {
		return -1;
	}


	return 0;
}


/*
 * Inserts rules for a promise into the bpf jump table
 *
 * If `allow` is true, a seccomp filter to allow
 * the promise will be compiled. This is useful for building
 * an initial filter.
 *
 * If `allow` is false, a seccomp filter to disallow
 * the promise will be compiled. This is useful for subsequent
 * calls to promise() that revoke promises
 */
static int
bpf_program_compile_promise(struct bpf_program *bpfprog, enum promise p, int allow)
{
	switch(p) {
		case PROMISE_STDIO:
			return bpf_program_compile_promise_stdio(bpfprog, allow);

		case PROMISE_INET:
		case PROMISE_UNIX:
			return bpf_program_compile_promise_unix_inet(bpfprog, allow);

		default:
			/* unimpl */
			return -1;
	}
}

static int
bpf_program_end(struct bpf_program *bpfprog, uint32_t seccomp_ret)
{
	struct sock_filter insn = BPF_STMT(BPF_RET | BPF_K, seccomp_ret);
	if (bpf_program_append(bpfprog, &insn, 1) < 0) {
		return -1;
	}
	return 0;
}

static int
bpf_program_install(struct bpf_program *bpfprog)
{
	struct sock_fprog fprog;

	/* Install seccomp filter */
	fprog.filter = bpfprog->program;
	fprog.len = bpfprog->vpc;
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog) < 0)
		return -1;

	return 0;
}

/* Spawns the non-sandboxed broker process */
static int
spawn_broker(void)
{
	int sv[2];
	pid_t child;
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0)
		return -1;

	/* Spawn the broker */
	if ((child = fork()) < 0) {
		return -1;
	} else if (!child) {
		/* Tell the kernel to kill this thread when the parent dies */
		prctl(PR_SET_PDEATHSIG, SIGHUP);

		/* Close the first socket fd */
		close(sv[0]);

		broker_entry(sv[1]);
		/* NOTREACHED */
	}

	/* Close the second socket fd */
	close(sv[1]);
	return sv[0];
}

int
pledge(const char *promises, const char *execpromises)
{
	static int first_filter = 1;
	static uint32_t active_promises = 0;

	int ret;
	char *saveptr, *token, *promises_c;
	struct bpf_program *bpfprog;
	if (execpromises) {
		/* unimplemented */
		errno = ENOTSUP;
		return -1;
	}

	/* spawn the broker before creating the filter */
	if (first_filter) {
		broker_fd = spawn_broker();
		if (broker_fd < 0)
			return -1;
	}



	/* initialize the bpf program */
	if (!(bpfprog = bpf_program_init(first_filter, broker_fd))) {
		return -1;
	}

	/*
	 * The first seccomp filter we build is special, it defines the
	 * the baseline rule set and includes sanity checks.
	 *
	 * For subsequent filters, these checks are not included.
	 * Instead, only the promises that were removed since the last
	 * call get compiled. This is possible because subsequent seccomp filters
	 * can only remove permissions, not add them. All filters ever
	 * installed will get run on each syscall and the most restrictive
	 * outcome will be used. This means that the sanity checks and other
	 * promises from the initial rule set will be used by default and don't
	 * need to be included in subsequent filters.
	 */
	if (first_filter) {
		struct sigaction sact;

		/* Install a SIGSYS handler */
		sact.sa_sigaction = seccomp_sigsys_handler;
		sact.sa_flags = SA_SIGINFO;
		if (sigaction(SIGSYS, &sact, NULL) < 0)
			return -1;

		/* Drop privileges */
		prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

		/* Go through each promise and compile a filter for it */
		saveptr = promises_c = strdup(promises);
		while ((token = strtok_r(saveptr, " ", &saveptr))) {
			enum promise cur = promise_from_str(token);
			if (cur == PROMISE_INVALID) {
				ret = -1;
				goto out;
			}

			/* Special case for unix/inet. Only compile one of them */
			if ((cur == PROMISE_UNIX && (active_promises & PROMISE_INET)) ||
				(cur == PROMISE_INET && (active_promises & PROMISE_UNIX)))
				continue;

			if (bpf_program_compile_promise(bpfprog, cur, 1) < 0) {
				fprintf(stderr, "seccomp: couldn't compile promise %s, %d\n", token, cur);
				ret = -1;
				goto out;
			}

			/* on success, add the promise to active_promises */
			active_promises |= cur;
		}

		/* Add the default case to the end (deny) */
		if (bpf_program_end(bpfprog, SECCOMP_RET_KILL) < 0) {
			ret = -1;
			goto out;
		}

		/* Notify the broker of our promise set */


		first_filter = 0;
	} else {
		uint32_t i;
		uint32_t new_promises = 0;

		/* Enumerate all promises */
		saveptr = promises_c = strdup(promises);
		while ((token = strtok_r(saveptr, " ", &saveptr))) {
			enum promise cur = promise_from_str(token);
			if (cur == PROMISE_INVALID) {
				ret = -1;
				goto out;
			}

			new_promises |= cur;
			if (!(active_promises & cur)) {
				/* This promise wasn't here before, error */
				ret = -1;
				goto out;
			}
		}

		/* If nothing changed, exit successfully */
		if (new_promises == active_promises) {
			ret = 0;
			goto out;
		}

		/* Go through each promise that was removed and generate a deny filter */
		for (i = 0; i < 31; i++) {
			uint32_t cur = (1U << i);
			if (!(active_promises & cur) || (new_promises & cur))
				/* This promise wasn't removed (or never existed), skip */
				continue;

			/*
			 * Special case for unix/inet. Since they share a bpf filter,
			 * only revoke them if neither is present.
			 */
			if ((cur == PROMISE_INET && (new_promises & PROMISE_UNIX)) ||
				(cur == PROMISE_UNIX && (new_promises & PROMISE_INET)))
				continue;

			/* This promise was removed, generate a filter for it */
			if (bpf_program_compile_promise(bpfprog, cur, 0) < 0) {
				ret = -1;
				goto out;
			}

			fprintf(stderr, "seccomp: Generated reverse filter for promise %s\n", promise_names[i]);
		}

		/*
		 * Add the default case to the end (allow).
		 * In the case of a secondary filter, `allow` simply defers the decision
		 * to the other filters.
		 */
		if (bpf_program_end(bpfprog, SECCOMP_RET_ALLOW) < 0) {
			ret = -1;
			goto out;
		}

		/* Notify the broker of our new promise set */

		active_promises = new_promises;
	}

	/* Install the filter */
#if 1
	if (bpf_program_install(bpfprog) < 0) {
		ret = -1;
		goto out;
	}
#endif

	ret = 0;
out:
	free(promises_c);
	bpf_program_free(bpfprog);
	return ret;
}

int
unveil(const char *path, const char *permissions)
{
	return 0;
}

void
test_seccomp()
{
	if (pledge("stdio unix", NULL) < 0)
		_exit(1);

	puts("Hello from the sandbox!");
	int sfd = socket(AF_UNIX, SOCK_DGRAM, 0);

	if (pledge("stdio", NULL) < 0)
		_exit(2);

	//sfd = socket(AF_UNIX, SOCK_DGRAM, 0);

	_exit(0);
}

