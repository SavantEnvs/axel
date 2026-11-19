# Heap over-read in `conn_info_status_get` on a truncated HTTP response

A server that closes the connection before the empty line ending its headers
(here: it sends just `)\x0f`) makes `http_exec()` return with
`conn->http->headers` not NUL-terminated. `axel_new()` then formats the error
with `conn_info_status_get()`, whose `strcspn()` (src/conn.c:579) reads past the
1024-byte header buffer:

    ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 1025
      #0 strcspn
      #1 conn_info_status_get src/conn.c:579
      #2 axel_new src/axel.c:167

The same happens with a plain `axel http://127.0.0.1:1/x` (connection refused).
It was found by the `fuzz_http_response` harness before that harness started
ending every answer with an empty line; reproduce it with an axel_new() call on
a server that sends this file and closes.
