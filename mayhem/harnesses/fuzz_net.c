/* Server responses, fed to axel's own client through axel_new():
 * the same calls axel's main() makes to open a download (conn_init,
 * conn_info, http_exec header parsing, Content-Disposition, redirects,
 * conn_info_status_get; FTP replies, SIZE/LIST/PASV parsing).
 *
 * A loopback server thread answers every connection with the fuzz input and
 * then half-closes, so the client always reads the input followed by EOF.
 * Build with -DFUZZ_SCHEME=\"http\" or \"ftp\" to pick the protocol.
 *
 * -DFUZZ_HTTP_RESPONSE ends every answer with an empty line (see below).
 *
 * -DFUZZ_STFILE turns it into the resume-state target: the server answers
 * with a fixed resumable 206 response and the input becomes the download's
 * <file>.st state file, which axel_open() loads (stfile_load).
 *
 * -DFUZZ_SEARCH is the mirror-search (-S) target: with http_proxy pointing at
 * the loopback server, search_makelist() first probes the URL (fixed 200
 * answer) and then fetches the filesearching.com result page, whose body is
 * the input. */
#include "fuzz_common.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>

#ifndef FUZZ_SCHEME
#define FUZZ_SCHEME "http"
#endif

#define MAX_CLIENTS 64

static const uint8_t *srv_data;
static size_t srv_size;
/* Optional: a fixed answer for the first connection, and a fixed prefix
 * sent before srv_data on every later one. */
static const char *srv_first;
static const char *srv_prefix;
/* Optional: a fixed suffix sent after srv_data (see FUZZ_HTTP_RESPONSE). */
static const char *srv_suffix;

static void
send_all(int c, const void *buf, size_t n)
{
	size_t off = 0;
	while (off < n) {
		ssize_t w = send(c, (const char *)buf + off, n - off,
				 MSG_NOSIGNAL);
		if (w <= 0)
			return;
		off += (size_t)w;
	}
}
static int srv_fd = -1;
static int srv_clients[MAX_CLIENTS];
static int srv_nclients;
#ifdef FUZZ_STFILE
static char st_out[600], st_state[640];
#endif

static void *
serve(void *arg)
{
	(void)arg;
	for (;;) {
		int c = accept(srv_fd, NULL, NULL);
		if (c < 0)
			break;	/* listening socket shut down: input done */
		if (srv_first && srv_nclients == 0) {
			send_all(c, srv_first, strlen(srv_first));
		} else {
			if (srv_prefix)
				send_all(c, srv_prefix, strlen(srv_prefix));
			send_all(c, srv_data, srv_size);
			if (srv_suffix)
				send_all(c, srv_suffix, strlen(srv_suffix));
		}
		shutdown(c, SHUT_WR);
		/* Keep it open (unread request bytes would turn a close into
		 * a RST that can eat the response) until the input is done. */
		if (srv_nclients < MAX_CLIENTS)
			srv_clients[srv_nclients++] = c;
		else
			close(c);
	}
	return NULL;
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	signal(SIGPIPE, SIG_IGN);
#ifdef FUZZ_STFILE
	/* Private scratch dir for the download and its .st state file */
	static char dir[512];
	const char *tmp = getenv("TMPDIR");
	snprintf(dir, sizeof(dir), "%s/axel-stfile-XXXXXX",
		 tmp && *tmp ? tmp : "/tmp");
	if (!mkdtemp(dir)) {
		perror("axel-stfile scratch dir");
		abort();
	}
	snprintf(st_out, sizeof(st_out), "%s/file.bin", dir);
	snprintf(st_state, sizeof(st_state), "%s/file.bin.st", dir);
#endif
	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct sockaddr_in sa;
	socklen_t len = sizeof(sa);
	pthread_t th;
	conf_t conf;
	search_t url[1];

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	srv_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (srv_fd < 0)
		return 0;
	if (bind(srv_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 ||
	    listen(srv_fd, 16) < 0 ||
	    getsockname(srv_fd, (struct sockaddr *)&sa, &len) < 0) {
		close(srv_fd);
		return 0;
	}
#ifdef FUZZ_STFILE
	static const char resp[] =
		"HTTP/1.1 206 Partial Content\r\n"
		"Content-Range: bytes 1-1048575/1048576\r\n"
		"Content-Length: 1048575\r\n\r\n";
	srv_data = (const uint8_t *)resp;
	srv_size = sizeof(resp) - 1;
	{
		FILE *f = fopen(st_state, "wb");
		if (!f || fwrite(data, 1, size, f) != size) {
			if (f)
				fclose(f);
			close(srv_fd);
			return 0;
		}
		fclose(f);
		f = fopen(st_out, "wb");
		if (f)
			fclose(f);
	}
#else
	srv_data = data;
	srv_size = size;
#endif
#ifdef FUZZ_SEARCH
	srv_first = "HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n";
	srv_prefix = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
#endif
#ifdef FUZZ_HTTP_RESPONSE
	/* The input is the server's header block, always ended by an empty
	 * line. Without it nearly every input stops mid-header, and
	 * http_exec() then returns with conn->http->headers unterminated, so
	 * axel_new()'s error path (conn_info_status_get, conn.c:579) reads
	 * past the buffer: a real upstream bug (see
	 * mayhem/fuzz_http_response/known-findings/), but one so shallow that
	 * it stops the target from fuzzing anything else. Everything after
	 * the input's own first empty line is unread body, as before. */
	srv_suffix = "\r\n\r\n";
#endif
	srv_nclients = 0;
	if (pthread_create(&th, NULL, serve, NULL) != 0) {
		close(srv_fd);
		return 0;
	}

	if (fuzz_conf_defaults(&conf)) {
		conf.num_connections = 1;
		conf.verbose = 0;
		conf.connection_timeout = 2;
		conf.io_timeout = 2;
		conf.reconnect_delay = 0;
		conf.max_redirect = 3;
		memset(url, 0, sizeof(url));
		snprintf(url[0].url, sizeof(url[0].url),
			 FUZZ_SCHEME "://127.0.0.1:%d/dir/file.bin",
			 ntohs(sa.sin_port));

#ifdef FUZZ_CONN_API
		/* The opening sequence of axel_new() through the conn API it is
		 * built on (conn_set, conn_init, conn_info, conn_url). Used for
		 * FTP because axel_new() itself reads conn->message after a
		 * failed conn_init() has freed it (axel.c:157), a use-after-free
		 * every FTP input that does not log in reaches first. */
		conn_t *conn = calloc(1, sizeof(*conn));
		if (conn) {
			conn->conf = &conf;
			pthread_mutex_init(&conn->lock, NULL);
			conn->local_if = conf.interfaces->text;
			if (conn_set(conn, url[0].url)) {
				int status = 0;
				for (int tries = 0; tries < 2; tries++) {
					if (!conn_init(conn))
						break;
					status = conn_info(conn);
					if (status != -1)
						break;
				}
				char buf[MAX_STRING];
				if (status > 0)
					conn_url(buf, sizeof(buf) - 1, conn);
				else if (status == 0)
					conn_info_status_get(buf, 80, conn);
			}
			conn_disconnect(conn);
			if (!PROTO_IS_FTP(conn->proto) || conn->proxy) {
				abuf_setup(conn->http->request, ABUF_FREE);
				abuf_setup(conn->http->headers, ABUF_FREE);
			}
			pthread_mutex_destroy(&conn->lock);
			free(conn);
		}
#else
#ifdef FUZZ_SEARCH
		snprintf(conf.http_proxy, sizeof(conf.http_proxy),
			 "127.0.0.1:%d", ntohs(sa.sin_port));
		search_t *res = calloc(conf.search_amount + 1, sizeof(*res));
		if (res) {
			res->conf = &conf;
			search_makelist(res, url[0].url);
			free(res);
		}
		axel_t *axel = NULL;
#else
		axel_t *axel = axel_new(&conf, 1, url);
#endif
#ifdef FUZZ_STFILE
		if (axel && axel->ready != -1) {
			/* what main() does for -o <file> */
			strlcpy(axel->filename, st_out, sizeof(axel->filename));
			axel_open(axel);
			if (axel->outfd >= 0)
				close(axel->outfd);
		}
#endif
		if (axel) {
			/* axel_close() minus two things that only work once per
			 * process, as in axel's main(): it frees axel.c's static
			 * buffer without clearing it (a second axel_new would
			 * reuse the freed pointer) and closes outfd, which is 0
			 * (stdin) until axel_open(). */
			for (int i = 0; i < axel->conf->num_connections; i++)
				conn_disconnect(&axel->conn[i]);
			free(axel->url);
			print_messages(axel);
			if (!PROTO_IS_FTP(axel->conn->proto) || axel->conn->proxy) {
				abuf_setup(axel->conn->http->request, ABUF_FREE);
				abuf_setup(axel->conn->http->headers, ABUF_FREE);
			}
			free(axel->conn);
			free(axel);
		}
#endif
		conf_free(&conf);
	}

	shutdown(srv_fd, SHUT_RDWR);
	pthread_join(th, NULL);
	close(srv_fd);
	srv_fd = -1;
	for (int i = 0; i < srv_nclients; i++)
		close(srv_clients[i]);
#ifdef FUZZ_STFILE
	unlink(st_state);
	unlink(st_out);
#endif
	return 0;
}
