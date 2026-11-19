/* URL parsing (conn_set/conn_url, http_decode): the URL on the command line
 * and in every redirect's Location header. No network. */
#include "fuzz_common.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	conf_t conf;
	conn_t *conn;
	char *s = malloc(size + 1);
	if (!s)
		return 0;
	memcpy(s, data, size);
	s[size] = 0;

	if (!fuzz_conf_defaults(&conf)) {
		free(s);
		return 0;
	}
	conn = calloc(1, sizeof(*conn));
	if (conn) {
		conn->conf = &conf;
		if (conn_set(conn, s)) {
			char url[MAX_STRING];
			conn_url(url, sizeof(url), conn);
			conn_url(url, 8, conn);
		}
		free(conn);
	}
	http_decode(s);
	conf_free(&conf);
	free(s);
	return 0;
}
