/* Security-key (FIDO/U2F) stubs: libssh.a references them, the harnesses never use a token. */
#include "includes.h"

#include <sys/types.h>

#include "ssherr.h"
#include "ssh-sk.h"

int
sshsk_enroll(int type, const char *provider_path, const char *device,
    const char *application, const char *userid, uint8_t flags,
    const char *pin, struct sshbuf *challenge_buf,
    struct sshkey **keyp, struct sshbuf *attest)
{
	return SSH_ERR_FEATURE_UNSUPPORTED;
}

int
sshsk_sign(const char *provider_path, struct sshkey *key,
    u_char **sigp, size_t *lenp, const u_char *data, size_t datalen,
    u_int compat, const char *pin)
{
	return SSH_ERR_FEATURE_UNSUPPORTED;
}

int
sshsk_load_resident(const char *provider_path, const char *device,
    const char *pin, u_int flags, struct sshsk_resident_key ***srksp,
    size_t *nsrksp)
{
	return SSH_ERR_FEATURE_UNSUPPORTED;
}
