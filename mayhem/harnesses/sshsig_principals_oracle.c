/*
 * sshsig_principals_oracle.c — known-answer oracle over sshsig.c's allowed_signers matching: a fixed
 * ed25519 key is looked up in allowed_signers files written here, with sshsig_find_principals() and
 * sshsig_check_allowed_keys(), and the returned principals / status are asserted. find-principals
 * on a line with a namespaces= restriction is left out: on this base it is the NULL dereference the
 * mined bug is about. Prints "ok   - name" / "FAIL - name" lines; exit 0 iff none failed.
 */
#include "includes.h"

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sshkey.h"
#include "sshsig.h"
#include "ssherr.h"
#include "log.h"

#define KEY1 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMD"
#define KEY2 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGlPGVzTaI7is4A3c3zSv/JJ59Qp3QYxJfV9qLfF1/vk"
#define VERIFY_TIME 1700000000ULL

static int failures, total;
static struct sshkey *k1;

static void
check(const char *name, int ok)
{
	total++;
	if (!ok)
		failures++;
	printf("%s - %s\n", ok ? "ok  " : "FAIL", name);
}

static void
write_file(char *buf, size_t len, const char *contents)
{
	const char *tmp = getenv("TMPDIR");
	FILE *f;
	int fd;

	snprintf(buf, len, "%s/sshsig_principals_oracle.XXXXXX", tmp != NULL ? tmp : "/tmp");
	if ((fd = mkstemp(buf)) == -1 || (f = fdopen(fd, "w")) == NULL)
		abort();
	fputs(contents, f);
	fclose(f);
}

/* find-principals: returns the status; *out is the principals string (or NULL) */
static int
find(const char *contents, char **out)
{
	char buf[4096];
	int r;

	*out = NULL;
	write_file(buf, sizeof(buf), contents);
	r = sshsig_find_principals(buf, k1, VERIFY_TIME, out);
	unlink(buf);
	return r;
}

static int
allowed(const char *contents, const char *principal, const char *ns)
{
	char buf[4096];
	int r;

	write_file(buf, sizeof(buf), contents);
	r = sshsig_check_allowed_keys(buf, k1, principal, ns, VERIFY_TIME);
	unlink(buf);
	return r;
}

static int
finds(const char *contents, const char *want)
{
	char *p;
	int r = find(contents, &p);
	int ok = r == 0 && p != NULL && strcmp(p, want) == 0;

	free(p);
	return ok;
}

int
main(void)
{
	char *cp = KEY1, *p;

	log_init("sshsig_principals_oracle", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_USER, 1);
	if ((k1 = sshkey_new(KEY_UNSPEC)) == NULL || sshkey_read(k1, &cp) != 0)
		abort();
	check("ed25519 key parses", k1->type == KEY_ED25519);

	check("find: one principal", finds("alice " KEY1 "\n", "alice"));
	check("find: principal list", finds("alice,bob " KEY1 "\n", "alice,bob"));
	check("find: second line matches", finds("bob " KEY2 "\ncarol " KEY1 "\n", "carol"));
	check("find: unexpired valid-before", finds("alice valid-before=\"20991231\" " KEY1 "\n", "alice"));
	check("find: other key is KEY_NOT_FOUND", find("alice " KEY2 "\n", &p) == SSH_ERR_KEY_NOT_FOUND);
	check("find: empty file is KEY_NOT_FOUND", find("", &p) == SSH_ERR_KEY_NOT_FOUND);
	check("find: expired valid-before is KEY_NOT_FOUND",
	    find("alice valid-before=\"20000101\" " KEY1 "\n", &p) == SSH_ERR_KEY_NOT_FOUND);
	check("find: future valid-after is KEY_NOT_FOUND",
	    find("alice valid-after=\"20991231\" " KEY1 "\n", &p) == SSH_ERR_KEY_NOT_FOUND);

	check("allowed: principal matches", allowed("alice " KEY1 "\n", "alice", "git") == 0);
	check("allowed: pattern principal matches",
	    allowed("*@example.com " KEY1 "\n", "x@example.com", "git") == 0);
	check("allowed: other principal is KEY_NOT_FOUND",
	    allowed("alice " KEY1 "\n", "bob", "git") == SSH_ERR_KEY_NOT_FOUND);
	check("allowed: other key is KEY_NOT_FOUND",
	    allowed("alice " KEY2 "\n", "alice", "git") == SSH_ERR_KEY_NOT_FOUND);
	check("allowed: namespace in list matches",
	    allowed("alice namespaces=\"git,file\" " KEY1 "\n", "alice", "file") == 0);
	check("allowed: namespace outside list is KEY_NOT_FOUND",
	    allowed("alice namespaces=\"file\" " KEY1 "\n", "alice", "git") == SSH_ERR_KEY_NOT_FOUND);

	sshkey_free(k1);
	printf("1..%d\n# passed %d, failed %d\n", total, total - failures, failures);
	return failures == 0 ? 0 : 1;
}
