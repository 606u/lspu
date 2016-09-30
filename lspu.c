/* -*- mode: C; eval: (c-set-style "bsd"); -*- */

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <err.h>
#include <fcntl.h>
#include <getopt.h>
#include <libprocstat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

static int hflag = 0, vflag = 0;

#define trace(lvl, ...)				\
	do {					\
		if (lvl <= vflag) {		\
			warnx(__VA_ARGS__);	\
		}				\
	} while (0)

#define EXIT_MATCHES 2

struct FileId
{
	uint32_t device_id;
	ino_t inode;
};
struct FileInfo
{
	struct FileInfo *next;	/* used on hash collisions */

	struct FileId id;
	char path[1];		/* taken into account when malloc'd */
};
static struct FileInfo **needle_ht;
static size_t needle_ht_sz;

// nonlinear table lookup hasher, as described here:
// http://en.wikipedia.org/wiki/Hash_function#Hashing_By_Nonlinear_Table_Lookup 
static uint32_t table[256];

static void
hash_init (void)
{
	int i;
	for (i = 0; i < 256; ++i)
		table[i] = (uint32_t)rand ();
}


static size_t
hash_buf (const void *ptr, size_t size)
{
	uint32_t n = 0;
	const uint8_t *p = (const uint8_t*)ptr, *endp = p + size;
	for (; p != endp; ++p)
		n ^= table[*p];
	return (size_t)n;
}


static struct FileInfo*
alloc_fileinfo (const struct FileId *id,
		const char *path)
{
	const size_t path_len = strlen(path);
	const size_t sz = sizeof (struct FileInfo) + path_len;
	struct FileInfo *res = (struct FileInfo*)malloc (sz);
	if (res) {
		res->next = 0;
		res->id = *id;
		strcpy(res->path, path);
	}
	return res;
}


static int
add_file(const struct FileId *id,
	 const char *path)
{
	struct FileInfo *fi = alloc_fileinfo(id, path);
	if (fi) {
		const uint32_t hash = hash_buf(&fi->id, sizeof (fi->id));
		struct FileInfo **entry = needle_ht + (hash % needle_ht_sz);
		while (*entry) {
			entry = &(*entry)->next;
		}
		*entry = fi;
		return 0;
	}
	return -1;
}


static int
alloc_ht (size_t n_elems)
{
	/* auto-deduce hash table size */
	size_t n_buckets = 1;
	while (n_buckets < n_elems)
		n_buckets *= 2;
	n_buckets *= 2;

	needle_ht = (struct FileInfo**)calloc (n_buckets,
					       sizeof (struct FileInfo*));
	if (needle_ht) {
		needle_ht_sz = n_buckets;
		return 0;
	}
	errno = ENOMEM;
	return -1;
}


static struct FileInfo*
lookup (uint32_t device_id, ino_t inode)
{
	struct FileId id;
	uint32_t hash;
	struct FileInfo *it;

	id.device_id = device_id;
	id.inode = inode;
	hash = hash_buf(&id, sizeof (id));
	it = needle_ht[hash % needle_ht_sz];
	while (it &&
	       memcmp(&it->id, &id, sizeof (id)))
		it = it->next;
	return it;
}


static int
scan_process(struct procstat *prstat,
	     struct kinfo_proc *proc,
	     struct FileInfo **match)
{
	struct kinfo_vmentry *head;
	unsigned i, cnt;
	static const int prot = KVME_PROT_READ | KVME_PROT_EXEC;

	head = procstat_getvmmap(prstat, proc, &cnt);
	if (!head)
		return -1;

	trace(2, "checking '%s', pid %u", proc->ki_comm, proc->ki_pid);
	for (i = 0; i < cnt; ++i) {
		struct kinfo_vmentry *it = head + i;
		/* requirements to consider VM mapping for further test:
		 *  - to have a backing vnode,
		 *  - to be read-only + execute */
		if (it->kve_type == KVME_TYPE_VNODE &&
		    (it->kve_protection & prot) == prot) {
			struct FileInfo *fi;
			trace(2, "  ... using dev %lu, ino %lu",
			      (unsigned long)it->kve_vn_fsid,
			      (unsigned long)it->kve_vn_fileid);
			fi = lookup(it->kve_vn_fsid,
				    (ino_t)it->kve_vn_fileid);
			if (fi) {
				if (match)
					*match = fi;
				/* TODO: print all matches if verbose */
				procstat_freevmmap(prstat, head);
				return 1;
			}
		}
	}
	procstat_freevmmap(prstat, head);
	return 0;
}


/*
 * returns device_id and inode of file at |path| via |id|
 *
 * returns 0 on success; on error returns -1 and prints err details
 *
 * since |stat()| might return virtual device_id on nullfs mounts,
 * (ezjail's basejail) |get_fileid()| memory-maps file in its own
 * address space and asks kernel for the "real" device_id and inode
 */
static int
get_fileid(struct procstat *prstat,
	   struct kinfo_proc *self,
	   const char *path,
	   struct FileId *id)
{
	int res = 0, found = 0;
	int fd = open(path, O_RDONLY);
	if (fd != -1) {
		void *ptr = mmap(/*addr*/0, /*len*/1, PROT_READ, /*flags*/0,
				 fd, /*offset*/0);
		if (ptr) {
			unsigned cnt;
			struct kinfo_vmentry *head =
				procstat_getvmmap(prstat, self, &cnt);
			if (head) {
				for (unsigned i = 0; i < cnt; ++i) {
					struct kinfo_vmentry *it = head + i;
					if (it->kve_type == KVME_TYPE_VNODE &&
					    it->kve_start == (uint64_t)ptr) {
						id->device_id = it->kve_vn_fsid;
						id->inode = it->kve_vn_fileid;
						found = 1;
						break;
					}
				}
				procstat_freevmmap(prstat, head);
			} else {
				warn("cannot get process memory map");
				res = -1;
			}
			munmap(ptr, /*len*/1);
		} else {
			warn("cannot mmap file '%s'", path);
		}
		close(fd);
	} else {
		warn("cannot open file '%s'", path);
	}

	if (res)
		return res;
	if (found)
		return 0;
	errno = ENOENT;
	return -1;
}


static int
fill_hashtable_from_cmdline_paths(struct procstat *prstat,
				  int argc, char *argv[])
{
	/* allocate hashtable where to insert target paths */
	int n_buckets = 1;
	while (n_buckets < argc)
		n_buckets *= 2;
	n_buckets *= 2;
	if (alloc_ht(n_buckets) != 0) {
		warn("cannot allocate memory");
		return -1;
	}

	/* get |lspu| process info needed by |get_fileid()| */
	unsigned n_procs = 0;
	struct kinfo_proc *self =
		procstat_getprocs(prstat, KERN_PROC_PID, getpid(), &n_procs);
	if (!self) {
		warn("cannot acquire 'lspu' process info");
		return -1;
	}

	/* iterate over files on the command-line and keep their ids
	 * in the hashtable */
	int i, res = 0;
	for (i = 0; i < argc; ++i) {
		const char *path = argv[i];
		struct FileId id;
		int rv = get_fileid(prstat, self, path, &id);
		if (!rv) {
			rv = add_file(&id, path);
			if (rv) {
				warn("cannot allocate memory");
				procstat_freeprocs(prstat, self);
				return -1;
			}
			trace(1, "file '%s' found at dev %lu, ino %lu",
			      path,
			      (unsigned long)id.device_id,
			      (unsigned long)id.inode);
		} else {
			res = 1;
		}
	}
	procstat_freeprocs(prstat, self);
	return res;
}


static int
usage(void)
{
	puts("Lists processes using given binaries or shared objects");
	puts("usage: lspu path...");
	return EX_USAGE;
}


int
main(int argc, char *argv[])
{
	struct procstat *prstat;
	struct kinfo_proc *p, *proc;
	unsigned i, cnt, matches = 0;
	int rv, opt;

	while ((opt = getopt(argc, argv, "hv")) != -1) {
		switch (opt) {
		case 'h': hflag = 1; break;
		case 'v': ++vflag; break;
		default: return usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (!argc)
		return usage();

	hash_init();
	if (alloc_ht(argc) != 0)
		err(EXIT_FAILURE, "cannot initialize");

	prstat = procstat_open_sysctl();
	if (prstat == NULL)
		errx(EXIT_FAILURE, "procstat_open");

	rv = fill_hashtable_from_cmdline_paths(prstat, argc, argv);
	if (rv == -1)
		return EXIT_FAILURE;

	p = procstat_getprocs(prstat, KERN_PROC_PROC, 0, &cnt);
	if (p == NULL)
		errx(EXIT_FAILURE, "procstat_getprocs");

	for (i = 0; i < cnt; i++) {
		struct FileInfo *match;
		proc = p + i;

		rv = scan_process(prstat, proc, &match);
		if (rv == 1) {
			/* TODO: refactor to function */
			if (!hflag) {
				/* TODO: omit jid if in a jail */
				fprintf(stdout, "%6s %6s %-20s %s\n",
					"pid", "jid", "command", "object");
				hflag = 1;
			}

			/* TODO: print summary if verbose */
			++matches;
			/* TODO: print dash if not jailed */
			fprintf(stdout, "%6u %6u %-20.20s %s\n",
				(unsigned)proc->ki_pid,
				(unsigned)proc->ki_jid,
				proc->ki_comm,
				match->path);
		}
	}
	procstat_freeprocs(prstat, p);
	procstat_close(prstat);

	if (matches)
		return EXIT_MATCHES;
	return EXIT_SUCCESS;
}
