/*
 * sshsig_principals_fuzz.c — fuzz sshsig.c's allowed_signers matching (check_allowed_keys_line()).
 * The input is the "principals [options]" part of allowed_signers lines, one per input line; the
 * harness appends a fixed ed25519 key to each line, so every line that parses can match the key
 * being checked. The file is then used the way `ssh-keygen -Y find-principals` (no namespace) and
 * `-Y check-novalidate`/`verify` (namespace "git") use it.
 */
#include "includes.h"

#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sshkey.h"
#include "sshsig.h"
#include "log.h"

#define KEY "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMD"
#define VERIFY_TIME 1700000000ULL

static struct sshkey *key;
static char path[4096];
static int fd = -1;

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	const char *tmp = getenv("TMPDIR");
	char *cp = KEY;

	log_init("sshsig_principals_fuzz", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_USER, 1);
	if ((key = sshkey_new(KEY_UNSPEC)) == NULL || sshkey_read(key, &cp) != 0)
		abort();
	snprintf(path, sizeof(path), "%s/sshsig_principals_fuzz.XXXXXX", tmp != NULL ? tmp : "/tmp");
	if ((fd = mkstemp(path)) == -1)
		abort();
	return 0;
}

static void
put(const void *buf, size_t len)
{
	if (write(fd, buf, len) != (ssize_t)len)
		abort();
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	size_t i, start = 0;
	char *principals = NULL;

	if (size > 65536)
		return -1;
	if (ftruncate(fd, 0) != 0 || lseek(fd, 0, SEEK_SET) != 0)
		abort();
	for (i = 0; i <= size; i++) {
		if (i < size && data[i] != '\n')
			continue;
		if (i > start) {
			put(data + start, i - start);
			put(" " KEY "\n", sizeof(" " KEY "\n") - 1);
		}
		start = i + 1;
	}
	if (sshsig_find_principals(path, key, VERIFY_TIME, &principals) == 0)
		free(principals);
	(void)sshsig_check_allowed_keys(path, key, "alice", "git", VERIFY_TIME);
	return 0;
}
