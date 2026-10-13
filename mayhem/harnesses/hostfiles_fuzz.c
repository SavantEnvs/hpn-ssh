/*
 * hostfiles_fuzz.c — fuzz auth.c's check_key_in_hostfiles(): the input is the contents of a
 * known_hosts file (the system host file the sshd hostbased-auth path consults), checked against a
 * fixed ed25519 key for a fixed host name. A "@revoked" entry for that key makes the status
 * HOST_REVOKED, the path that logs the revoked entry.
 */
#include "includes.h"

#include <sys/types.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sshkey.h"
#include "hostfile.h"
#include "log.h"
#include "auth.h"

#define HOSTKEY "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGlPGVzTaI7is4A3c3zSv/JJ59Qp3QYxJfV9qLfF1/vk"
#define HOSTNAME "host.example"

static struct sshkey *key;
static struct passwd pw;
static char path[4096];
static int fd = -1;

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	const char *tmp = getenv("TMPDIR");
	char *cp = HOSTKEY;

	log_init("hostfiles_fuzz", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 1);
	if ((key = sshkey_new(KEY_UNSPEC)) == NULL || sshkey_read(key, &cp) != 0)
		abort();
	snprintf(path, sizeof(path), "%s/hostfiles_fuzz.XXXXXX", tmp != NULL ? tmp : "/tmp");
	if ((fd = mkstemp(path)) == -1)
		abort();
	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size > 65536)
		return -1;
	if (ftruncate(fd, 0) != 0 || (size > 0 && pwrite(fd, data, size, 0) != (ssize_t)size))
		abort();
	(void)check_key_in_hostfiles(&pw, key, HOSTNAME, path, NULL);
	return 0;
}
