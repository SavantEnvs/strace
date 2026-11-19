/*
 * mayhem/replay_main.c - fuzz strace's syscall decoders without ptrace.
 *
 * strace decodes the syscalls of a traced process: the syscall number, its six arguments and the
 * memory those arguments point to (read from the tracee with process_vm_readv). Tracing a real
 * child needs ptrace, which the Mayhem fuzzing sandbox does not allow (the earlier ptrace-based
 * targets never started there: 0 edges). So this harness feeds strace a simulated tracee:
 *
 *  - strace's own main (renamed strace_main) parses the real command line, so every option
 *    (-v, -yy, -xx, -X, -e read=all, -s, -T ...) is set up exactly as in a normal run;
 *  - when init() has finished (it calls hyperlink_init right after opening the output file and
 *    before starting the traced program; build.sh redirects that call here) the harness replays
 *    the input's syscalls through strace's own entry/exit path (syscall_entering_trace /
 *    syscall_exiting_trace -> every sys_* decoder) and exits;
 *  - process_vm_readv/writev in libstrace.a are redirected (objcopy) to fuzz_process_vm_readv/
 *    writev below, which serve "tracee memory" from the input only: the input is mapped at a fake
 *    address ARENA, every other address faults, and a read crossing its end returns a short read,
 *    like a mapping followed by an unmapped page.
 *
 * Usage:  strace-replay <mode> <input> [strace options...]
 * runs    strace_main("strace", [strace options...], "--", "true") and replays <input>.
 *
 * Input layout (same as the former tracee):
 *   byte 0   flags: bit0 = syscalls "succeed" (strace runs its exit-side decoders on the memory);
 *                   bit1 = place the input so it ends at the end of the arena (boundary reads);
 *                   bit2 = a successful syscall returns the number of bytes after its record
 *                          (recv/read-style results) instead of 0
 *   byte 1   netlink protocol of the pre-opened netlink socket (mod 32)
 *   byte 2   number of records
 *   records  { u16 nr; u64 arg[6]; }  (little endian, 50 bytes each)
 *   rest     free data the arguments may point into
 * An argument whose top byte is 0xff becomes a pointer into the arena (low 32 bits % input size).
 * Modes restrict nr to a syscall family; fd modes replace arg0 with a real descriptor of this
 * process (arg0 % pool size), since strace learns fd types (netlink protocol, socket family) from
 * /proc and sock_diag of the "tracee", which is this process.
 */
#include "defs.h"
#include <stdint.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <linux/netlink.h>

int strace_main(int argc, char **argv);
void hyperlink_init(int out_fd, bool output_separately);

#define ARENA 0x200000000UL
#define MAXIN (1 << 20)
#define REC 50

static const long t_netlink[] = { __NR_sendto, __NR_sendmsg, __NR_sendmmsg, __NR_write,
				  __NR_writev, __NR_recvmsg, __NR_recvfrom };
static const long t_ioctl[] = { __NR_ioctl };
static const long t_bpf[] = { __NR_bpf, __NR_seccomp, __NR_prctl, __NR_setsockopt };
static const long t_socket[] = { __NR_bind, __NR_connect, __NR_sendto, __NR_sendmsg,
				 __NR_recvmsg, __NR_sendmmsg, __NR_recvmmsg, __NR_setsockopt,
				 __NR_getsockopt, __NR_accept4, __NR_getsockname,
				 __NR_getpeername, __NR_recvfrom, __NR_socketpair };
static const long t_execve[] = { __NR_execve, __NR_execveat };

struct mode {
	const char *name;
	const long *tab;
	size_t n;
	int fd_arg0;
};
static const struct mode modes[] = {
	{ "syscall", NULL, 0, 0 },
	{ "netlink", t_netlink, ARRAY_SIZE(t_netlink), 1 },
	{ "ioctl", t_ioctl, 1, 1 },
	{ "bpf", t_bpf, ARRAY_SIZE(t_bpf), 0 },
	{ "socket", t_socket, ARRAY_SIZE(t_socket), 1 },
	{ "execve", t_execve, 2, 0 },
};

static const struct mode *mode;
static const char *in_path;
static unsigned char in[MAXIN];
static size_t in_len;		/* bytes of input */
static unsigned long base;	/* fake address of in[0] */

/* The simulated tracee's address space: [base, base + in_len). */
static size_t
fake_read(void *dst, unsigned long addr, size_t len)
{
	if (addr < base || addr >= base + in_len)
		return 0;
	size_t avail = base + in_len - addr;
	if (len > avail)
		len = avail;
	memcpy(dst, in + (addr - base), len);
	return len;
}

ssize_t
fuzz_process_vm_readv(pid_t pid, const struct iovec *lvec, unsigned long liovcnt,
		      const struct iovec *rvec, unsigned long riovcnt, unsigned long flags)
{
	(void) pid; (void) flags;
	/* strace always passes one local and one remote iovec of the same length. */
	if (liovcnt != 1 || riovcnt != 1 || lvec[0].iov_len < rvec[0].iov_len) {
		errno = EINVAL;
		return -1;
	}
	size_t got = fake_read(lvec[0].iov_base, (unsigned long) rvec[0].iov_base,
			       rvec[0].iov_len);
	if (!got && rvec[0].iov_len) {
		errno = EFAULT;
		return -1;
	}
	return got;
}

ssize_t
fuzz_process_vm_writev(pid_t pid, const struct iovec *lvec, unsigned long liovcnt,
		       const struct iovec *rvec, unsigned long riovcnt, unsigned long flags)
{
	(void) pid; (void) lvec; (void) liovcnt; (void) rvec; (void) riovcnt; (void) flags;
	errno = EFAULT;
	return -1;
}

static void
replay(FILE *outf)
{
	FILE *f = fopen(in_path, "rb");
	if (!f)
		return;
	in_len = fread(in, 1, sizeof in, f);
	fclose(f);
	if (in_len < 3)
		return;

	const size_t pg = 4096, len = (in_len + pg - 1) / pg * pg;
	base = (in[0] & 2) ? ARENA + len - in_len : ARENA;

	/* Descriptors whose type strace inspects must be real (the tracee is this process). */
	int pool[8], np = 0, fd;
#define ADD(x) do { fd = (x); if (fd >= 0) pool[np++] = fd; } while (0)
	ADD(socket(AF_NETLINK, SOCK_RAW, in[1] % 32));
	ADD(socket(AF_INET, SOCK_STREAM, 0));
	ADD(socket(AF_INET6, SOCK_DGRAM, 0));
	ADD(socket(AF_UNIX, SOCK_STREAM, 0));
	ADD(memfd_create("tracee", 0));
	ADD(eventfd(0, 0));
	if (!np)
		pool[np++] = 0;

	struct tcb *tcp = xzalloc(sizeof(*tcp));
	tcp->pid = getpid();
	tcp->outf = outf;
	tcp->flags = TCB_ATTACHED;
#ifdef ENABLE_SECONTEXT
	tcp->last_dirfd = AT_FDCWD;
#endif

	size_t off = 3;
	for (unsigned r = 0; r < in[2] && off + REC <= in_len; r++, off += REC) {
		uint16_t nr;
		uint64_t a[6];
		memcpy(&nr, in + off, 2);
		memcpy(a, in + off + 2, sizeof a);
		long sc = mode->tab ? mode->tab[nr % mode->n] : (long) (nr % 470);
		if (!scno_is_valid(sc))
			continue;
		for (int i = 0; i < 6; i++)
			if ((a[i] >> 56) == 0xff)
				a[i] = base + (uint32_t) a[i] % in_len;
		if (mode->fd_arg0)
			a[0] = pool[a[0] % np];

		invalidate_umove_cache();
		tcp->scno = tcp->true_scno = sc;
		tcp->s_ent = &sysent[sc];
		tcp->qual_flg = qual_flags(sc);
		for (int i = 0; i < 6; i++)
			tcp->u_arg[i] = a[i];

		/* Syscall entry, as trace_syscall() does after syscall_entering_decode(). */
		unsigned int sig = 0;
		int res = syscall_entering_trace(tcp, &sig);
		syscall_entering_finish(tcp, res);

		/* Syscall exit, as trace_syscall() does after syscall_exiting_decode(). */
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		if (in[0] & 1) {
			tcp->u_error = 0;
			tcp->u_rval = (in[0] & 4) ? (kernel_long_t) (in_len - off - REC) : 0;
		} else {
			tcp->u_error = ENOSYS;
			tcp->u_rval = -1;
		}
		if (!filtered(tcp))
			syscall_exiting_trace(tcp, &ts, 1);
		syscall_exiting_finish(tcp);
	}
}

/* Called by strace's init() (call redirected by build.sh) once all options are processed. */
void
fuzz_replay_hook(int out_fd, bool output_separately)
{
	hyperlink_init(out_fd, output_separately);
	int fd = dup(out_fd);
	FILE *outf = fd >= 0 ? fdopen(fd, "w") : NULL;
	if (outf)
		replay(outf);
	if (outf)
		fflush(outf);
	_exit(0);
}

int
main(int argc, char **argv)
{
	if (argc < 3)
		return 0;
	for (size_t i = 0; i < ARRAY_SIZE(modes); i++)
		if (!strcmp(argv[1], modes[i].name))
			mode = &modes[i];
	if (!mode)
		return 0;
	in_path = argv[2];

	char *av[64];
	int ac = 0;
	av[ac++] = argv[0];
	for (int i = 3; i < argc && ac < 60; i++)
		av[ac++] = argv[i];
	av[ac++] = (char *) "--";
	av[ac++] = (char *) "true";
	av[ac] = NULL;
	return strace_main(ac, av);
}
