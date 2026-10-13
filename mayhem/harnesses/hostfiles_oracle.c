/*
 * hostfiles_oracle.c — known-answer oracle over auth.c's check_key_in_hostfiles(): a fixed ed25519
 * key is looked up for a host name in known_hosts files written here, and the returned HostStatus
 * is asserted. The revoked-key case is left out: on this base it is the NULL dereference the
 * mined bug is about. Prints "ok   - name" / "FAIL - name" lines; exit 0 iff none failed.
 */
#include "includes.h"

#include <sys/types.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sshkey.h"
#include "hostfile.h"
#include "log.h"
#include "auth.h"

#define KEY1 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGlPGVzTaI7is4A3c3zSv/JJ59Qp3QYxJfV9qLfF1/vk"
#define KEY2 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMD"

static int failures, total;

static void
check(const char *name, int ok)
{
	total++;
	if (!ok)
		failures++;
	printf("%s - %s\n", ok ? "ok  " : "FAIL", name);
}

static HostStatus
lookup(struct sshkey *key, const char *contents)
{
	struct passwd pw;
	const char *tmp = getenv("TMPDIR");
	char buf[4096];
	HostStatus st;
	FILE *f;
	int fd;

	memset(&pw, 0, sizeof(pw));
	snprintf(buf, sizeof(buf), "%s/hostfiles_oracle.XXXXXX", tmp != NULL ? tmp : "/tmp");
	if ((fd = mkstemp(buf)) == -1 || (f = fdopen(fd, "w")) == NULL)
		abort();
	fputs(contents, f);
	fclose(f);
	st = check_key_in_hostfiles(&pw, key, "host.example", buf, NULL);
	unlink(buf);
	return st;
}

static struct sshkey *
read_pub(const char *txt)
{
	char *cp = (char *)txt;
	struct sshkey *k = sshkey_new(KEY_UNSPEC);

	if (k == NULL || sshkey_read(k, &cp) != 0)
		abort();
	return k;
}

int
main(void)
{
	struct sshkey *k1;

	log_init("hostfiles_oracle", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 1);
	k1 = read_pub(KEY1);
	check("ed25519 key parses", k1->type == KEY_ED25519);
	check("known host + key is HOST_OK", lookup(k1, "host.example " KEY1 "\n") == HOST_OK);
	check("wildcard host + key is HOST_OK", lookup(k1, "*.example " KEY1 "\n") == HOST_OK);
	check("host in a list + key is HOST_OK", lookup(k1, "a.example,host.example " KEY1 "\n") == HOST_OK);
	check("empty file is HOST_NEW", lookup(k1, "") == HOST_NEW);
	check("other host is HOST_NEW", lookup(k1, "other.example " KEY1 "\n") == HOST_NEW);
	check("comments only is HOST_NEW", lookup(k1, "# host.example " KEY1 "\n") == HOST_NEW);
	check("same host, different key is HOST_CHANGED", lookup(k1, "host.example " KEY2 "\n") == HOST_CHANGED);
	check("revoked entry for another host is HOST_NEW",
	    lookup(k1, "@revoked other.example " KEY1 "\n") == HOST_NEW);
	sshkey_free(k1);
	printf("1..%d\n# passed %d, failed %d\n", total, total - failures, failures);
	return failures == 0 ? 0 : 1;
}
