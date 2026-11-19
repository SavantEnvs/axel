/* Shared helpers for the axel fuzz harnesses (mayhem layer, not upstream). */
#ifndef AXEL_FUZZ_COMMON_H
#define AXEL_FUZZ_COMMON_H

#include "config.h"
#include "axel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* conf_init() minus the files it reads (/etc/axelrc, $HOME/.axelrc) and the
 * proxy environment: the same defaults, so each input starts from one state. */
static int
fuzz_conf_defaults(conf_t *conf)
{
	memset(conf, 0, sizeof(*conf));
	strlcpy(conf->default_filename, "default", sizeof(conf->default_filename));
	conf->strip_cgi_parameters = 1;
	conf->save_state_interval = 10;
	conf->connection_timeout = 45;
	conf->reconnect_delay = 20;
	conf->num_connections = 4;
	conf->max_redirect = MAX_REDIRECT;
	conf->io_timeout = DEFAULT_IO_TIMEOUT;
	conf->buffer_size = 5120;
	conf->verbose = 1;
	conf->search_timeout = 10;
	conf->search_threads = 3;
	conf->search_amount = 15;
	conf->search_top = 3;
	conf->ai_family = AF_UNSPEC;
	conf_hdr_make(conf->add_header[HDR_USER_AGENT], "User-Agent",
		      DEFAULT_USER_AGENT);
	conf->add_header_count = HDR_count_init;
	conf->interfaces = calloc(1, sizeof(*conf->interfaces));
	if (!conf->interfaces)
		return 0;
	conf->interfaces->next = conf->interfaces;
	return 1;
}

/* Write the input to a fresh file under $TMPDIR; returns its path (static). */
static const char *
fuzz_write_tmp(const uint8_t *data, size_t size)
{
	static char path[512];
	const char *dir = getenv("TMPDIR");
	if (!dir || !*dir)
		dir = "/tmp";
	snprintf(path, sizeof(path), "%s/axel-fuzz-XXXXXX", dir);
	int fd = mkstemp(path);
	if (fd < 0)
		return NULL;
	size_t off = 0;
	while (off < size) {
		ssize_t w = write(fd, data + off, size - off);
		if (w <= 0) {
			close(fd);
			unlink(path);
			return NULL;
		}
		off += (size_t)w;
	}
	close(fd);
	return path;
}

#endif
