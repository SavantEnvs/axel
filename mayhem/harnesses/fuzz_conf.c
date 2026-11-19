/* axelrc configuration file parser (conf_loadfile in src/conf.c). */
#include "fuzz_common.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	conf_t conf;
	const char *path = fuzz_write_tmp(data, size);
	if (!path)
		return 0;
	if (fuzz_conf_defaults(&conf)) {
		conf_loadfile(&conf, path);
		/* conf_loadfile may have replaced the interface ring; free it
		 * the way the list is built (a ring of message_t). */
		axel_if_t *first = conf.interfaces, *i = first;
		if (i) {
			do {
				axel_if_t *n = i->next;
				if (i != first)
					free(i);
				i = n;
			} while (i && i != first);
		}
		conf_free(&conf);
	}
	unlink(path);
	return 0;
}
