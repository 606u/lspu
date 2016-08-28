#include <sys/param.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <err.h>
#include <getopt.h>
#include <libprocstat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

static int hflag = 0;

#define EXIT_MATCHES 2

static int
strpp_compare(const void *lhs, const void *rhs)
{
	return strcmp(*(char**)lhs, *(char**)rhs);
}


static int
search_for(const char *needle,
	   char *haystack[],
	   size_t n)
{
	/* notice |strpp_compare()| expects a pointer to char* */
	return bsearch(&needle, haystack, n, sizeof(char*), &strpp_compare) ? 1 : 0;
}


static int
scan_process(struct procstat *prstat,
	     struct kinfo_proc *proc,
	     char *haystack[],
	     size_t n)
{
	struct kinfo_vmentry *head;
	unsigned i, cnt;
	static const int prot = KVME_PROT_READ | KVME_PROT_EXEC;

	head = procstat_getvmmap(prstat, proc, &cnt);
	if (!head)
		return -1;

	for (i = 0; i < cnt; ++i) {
		struct kinfo_vmentry *it = head + i;
		/* requirements to consider VM mapping for further test:
		 *  - to have a backing vnode,
		 *  - to be shared (even tho I don't quite understand that :),
		 *  - to be read-only + execute */
		if (it->kve_type == KVME_TYPE_VNODE &&
		    it->kve_shadow_count &&
		    (it->kve_protection & prot) == prot) {
			if (search_for(it->kve_path, haystack, n))
				return 1;
		}
	}
	return 0;
}


static int
injail(void)
{
	int jailed;
	size_t len = sizeof(jailed);
	int rv = sysctlbyname("security.jail.jailed", &jailed, &len, 0, 0);
	return rv == 0 ? jailed : -1;
}


static int
usage(void)
{
	fprintf(stderr, "Lists processes using given binaries or shared objects\n");
	fprintf(stderr, "usage: lspu path...\n");
	return EX_USAGE;
}


int
main(int argc, char *argv[])
{
	struct procstat *prstat;
	struct kinfo_proc *p, *proc;
	unsigned i, cnt, matches = 0;
	char path[PATH_MAX];
	char **haystack;
	size_t n;
	int rv, opt;

	while ((opt = getopt(argc, argv, "h")) != -1) {
		switch (opt) {
		case 'h': hflag = 1; break;
		default: return usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (!argc)
		return usage();

	if (injail() > 0) {
		fputs("lspu does not currently work in a jail\n", stderr);
		return EXIT_FAILURE;
	}

	haystack = argv;
	n = argc;

	/* sort the list of files to search for alphabetically,
	 * this will allow using of |bsearch()| for better performance */
	qsort(haystack, n, sizeof(char*), &strpp_compare);

	prstat = procstat_open_sysctl();
	if (prstat == NULL)
		errx(1, "procstat_open()");

	p = procstat_getprocs(prstat, KERN_PROC_PROC, 0, &cnt);
	if (p == NULL)
		errx(1, "procstat_getprocs()");

	for (i = 0; i < cnt; i++) {
		proc = p + i;

		if (procstat_getpathname(prstat, proc, path, sizeof(path)) != 0)
			strcpy(path, "?");
		if (strlen(path) == 0)
			strcpy(path, "-");

		rv = search_for(path, haystack, n);
		if (!rv)
			rv = scan_process(prstat, proc, haystack, n);
		if (rv == 1) {
			if (!hflag) {
				fprintf(stdout, "%6s %6s %s\n",
					"pid", "jid", "command");
				hflag = 1;
			}

			++matches;
			fprintf(stdout, "%6u %6u %s\n",
				(unsigned)proc->ki_pid,
				(unsigned)proc->ki_jid,
				path);
		}
	}
	procstat_freeprocs(prstat, p);
	procstat_close(prstat);

	if (matches)
		return EXIT_MATCHES;
	return EXIT_SUCCESS;
}
