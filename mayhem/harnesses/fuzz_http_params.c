/* Content-Disposition / header-parameter parser (src/http_params.c): the
 * filename a server names in its response header, RFC 8187 filename*. */
#include "fuzz_common.h"
#include "http_params.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *hdr = malloc(size + 1);
	if (!hdr)
		return 0;
	memcpy(hdr, data, size);
	hdr[size] = 0;

	/* The sizes axel itself uses (MAX_STRING) and small ones that force
	 * the truncation paths. */
	static const size_t sizes[] = { MAX_STRING, 16, 2, 1 };
	for (size_t i = 0; i < sizeof(sizes) / sizeof(*sizes); i++) {
		char *out = malloc(sizes[i]);
		if (!out)
			break;
		http_content_disposition_filename(hdr, out, sizes[i]);
		free(out);
	}

	static const char *names[] = { "filename", "filename*", "name" };
	for (size_t i = 0; i < sizeof(names) / sizeof(*names); i++) {
		struct http_parameter p;
		char out[MAX_STRING];
		if (http_find_parameter(hdr, names[i], &p)) {
			http_copy_parameter(out, sizeof(out), &p);
			http_decode_extended_parameter(out, sizeof(out), &p);
		}
	}
	free(hdr);
	return 0;
}
