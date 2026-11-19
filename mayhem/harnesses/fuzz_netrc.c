/* .netrc parser (netrc_init/netrc_parse in src/netrc.c). */
#include "fuzz_common.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const char *path = fuzz_write_tmp(data, size);
	if (!path)
		return 0;
	netrc_t *n = netrc_init(path);
	if (n) {
		char user[MAX_STRING], pass[MAX_STRING];
		char suser[8], spass[8];
		user[0] = pass[0] = 0;
		netrc_parse(n, "example.com", user, sizeof(user), pass, sizeof(pass));
		user[0] = pass[0] = 0;
		netrc_parse(n, "127.0.0.1", suser, sizeof(suser), spass, sizeof(spass));
		netrc_free(n);
	}
	unlink(path);
	return 0;
}
