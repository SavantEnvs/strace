/*
 * mayhem/cli_main.c - drive strace's command-line parser from a file.
 *
 * strace parses and validates its options (init() in src/strace.c) before it starts the traced
 * program. This wrapper is linked in front of strace's own main, renamed strace_main with objcopy
 * (src/strace.c is not edited). It turns the input file into argv and calls strace_main.
 *
 * The command strace is asked to run is a path that does not exist: strace parses everything,
 * then fails to find the program and exits, so nothing is traced. (A traced program killed by
 * an injected fault would make strace re-raise that signal on itself, a false crash.)
 *
 * Two builds:
 *  - strace-qualify (default): the file content is the value of `-e` (one per line): the
 *    filter/inject/fault/signal/status/quiet/decode-fds/read/write expression language
 *    (filter_qualify.c, basic_filters.c, number_set.c).
 *        strace -o /dev/null -e <line1> -e <line2> ... -- ./.strace-fuzz-no-such-command
 *  - strace-options (-DCLI_OPTIONS): each line is one option, allow-listed so the input can't
 *    pick an output file or pipe (-o/--output), a pid to attach to (-p/--attach), a user to
 *    switch to (-u/--user) or daemonize (-D): a line is kept only if it is
 *      "-L<value>"  L an allowed short option; <value> only for options taking an argument
 *                   (a no-argument letter followed by more letters would parse as a cluster),
 *      "--name" or "--name=<value>"  name an allowed long option, spelled out in full
 *                   (getopt_long accepts unique prefixes, so prefixes are not allowed).
 *    A line consumed as an option's argument is fine: getopt treats it as a value.
 *        strace -o /dev/null <kept lines...> -- ./.strace-fuzz-no-such-command
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int strace_main(int argc, char **argv);

#define MAXARGS 256

#ifdef CLI_OPTIONS
/* strace.c optstring "+a:Ab:cCdDe:E:fFhiI:knNo:O:p:P:qrs:S:tTu:U:vVwxX:yYzZ" minus D, o, p, u. */
static const char short_noarg[] = "AcCdfFhiknNqrtTvVwxyYzZ";
static const char short_arg[] = "abeEIOPsSUX";
static const char *const long_ok[] = {
	"columns", "output-append-mode", "detach-on", "summary-only", "summary", "debug", "env",
	"follow-forks", "help", "instruction-pointer", "interruptible", "kill-on-exit",
	"stack-trace", "stack-traces", "stack-trace-frame-limit", "syscall-limit",
	"syscall-number", "arg-names", "summary-syscall-overhead", "trace-path",
	"relative-timestamps", "string-limit", "summary-sort-by", "absolute-timestamps",
	"timestamps", "syscall-times", "summary-columns", "no-abbrev", "version",
	"summary-wall-clock", "strings-in-hex", "const-print-style", "pidns-translation",
	"successful-only", "failed-only", "failing-only", "seccomp-bpf", "tips", "argv0",
	"always-show-pid", "color", "hyperlink", "trace", "trace-fds", "abbrev", "verbose", "raw",
	"signals", "status", "read", "write", "fault", "inject", "kvm", "namespace", "quiet",
	"silent", "silence", "decode-fds", "decode-pids", "secontext", NULL
};

static int allowed(const char *a)
{
	if (a[0] != '-' || !a[1])
		return 0;
	if (a[1] == '-') {
		size_t n = strcspn(a + 2, "=");
		for (const char *const *l = long_ok; *l; l++)
			if (strlen(*l) == n && !strncmp(*l, a + 2, n))
				return 1;
		return 0;
	}
	if (strchr(short_arg, a[1]))
		return 1;
	return strchr(short_noarg, a[1]) && !a[2];
}
#endif

int main(int argc, char **argv)
{
	if (argc < 2)
		return 0;
	FILE *f = fopen(argv[1], "rb");
	if (!f)
		return 0;
	static char buf[65536];
	size_t n = fread(buf, 1, sizeof buf - 1, f);
	fclose(f);
	buf[n] = '\0';

	char *av[MAXARGS + 8];
	int ac = 0;
	av[ac++] = argv[0];
	av[ac++] = (char *) "-o";
	av[ac++] = (char *) "/dev/null";
	for (char *line = buf, *next; line && ac < MAXARGS; line = next) {
		next = strchr(line, '\n');
		if (next)
			*next++ = '\0';
#ifdef CLI_OPTIONS
		if (allowed(line))
			av[ac++] = line;
#else
		av[ac++] = (char *) "-e";
		av[ac++] = line;
#endif
	}
	av[ac++] = (char *) "--";
	av[ac++] = (char *) "./.strace-fuzz-no-such-command";
	av[ac] = NULL;
	return strace_main(ac, av);
}
