// Copyright (c) 2004-2013 Sergey Lyubka
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.


#include "mongoose_os.h"
#include "mongoose_ssl.h"
#include "mongoose_thread.h"
#include "mongoose.h"

#define MONGOOSE_VERSION "3.6"
#define PASSWORDS_FILE_NAME ".htpasswd"
#define CGI_ENVIRONMENT_SIZE 4096
#define MAX_CGI_ENVIR_VARS 64
#define MG_BUF_LEN 8192
#define MAX_REQUEST_SIZE 16384

#ifdef DEBUG_TRACE
#undef DEBUG_TRACE
#define DEBUG_TRACE(x)
#else
#if defined(DEBUG)
#define DEBUG_TRACE(x) do { \
  flockfile(stdout); \
  printf("*** %lu.%p.%s.%d: ", \
         (unsigned long) time(NULL), (void *) mg_thread_self(), \
         __func__, __LINE__); \
  printf x; \
  putchar('\n'); \
  fflush(stdout); \
  funlockfile(stdout); \
} while (0)
#else
#define DEBUG_TRACE(x)
#endif // DEBUG
#endif // DEBUG_TRACE

static const char *http_500_error = "Internal Server Error";

// NOTE(lsm): this enum shoulds be in sync with the config_options below.
enum {
  CGI_EXTENSIONS, CGI_ENVIRONMENT, PUT_DELETE_PASSWORDS_FILE, CGI_INTERPRETER,
  PROTECT_URI, AUTHENTICATION_DOMAIN, SSI_EXTENSIONS, THROTTLE,
  ACCESS_LOG_FILE, ENABLE_DIRECTORY_LISTING, ERROR_LOG_FILE,
  GLOBAL_PASSWORDS_FILE, INDEX_FILES, ENABLE_KEEP_ALIVE, ACCESS_CONTROL_LIST,
  EXTRA_MIME_TYPES, LISTENING_PORTS, DOCUMENT_ROOT, SSL_CERTIFICATE,
  NUM_THREADS, RUN_AS_USER, REWRITE, HIDE_FILES,
  NUM_OPTIONS
};

static const char *config_options[] = {
  "C", "cgi_pattern", "**.cgi$|**.pl$|**.php$",
  "E", "cgi_environment", NULL,
  "G", "put_delete_passwords_file", NULL,
  "I", "cgi_interpreter", NULL,
  "P", "protect_uri", NULL,
  "R", "authentication_domain", "mydomain.com",
  "S", "ssi_pattern", "**.shtml$|**.shtm$",
  "T", "throttle", NULL,
  "a", "access_log_file", NULL,
  "d", "enable_directory_listing", "yes",
  "e", "error_log_file", NULL,
  "g", "global_passwords_file", NULL,
  "i", "index_files", "index.html,index.htm,index.cgi,index.shtml,index.php",
  "k", "enable_keep_alive", "no",
  "l", "access_control_list", NULL,
  "m", "extra_mime_types", NULL,
  "p", "listening_ports", "8080",
  "r", "document_root",  ".",
  "s", "ssl_certificate", NULL,
  "t", "num_threads", "20",
  "u", "run_as_user", NULL,
  "w", "url_rewrite_patterns", NULL,
  "x", "hide_files_patterns", NULL,
  NULL
};
#define ENTRIES_PER_CONFIG_OPTION 3

struct mg_context {
  volatile int stop_flag;       // Should we stop event loop
  SSL_CTX *ssl_ctx;             // SSL context
  SSL_CTX *client_ssl_ctx;      // Client SSL context
  char *config[NUM_OPTIONS];    // Mongoose configuration parameters
  mg_callback_t user_callback;  // User-defined callback function
  void *user_data;              // User-defined data

  struct socket *listening_sockets;

  volatile int num_threads;  // Number of threads
  mg_thread_mutex_t mutex;     // Protects (max|num)_threads
  mg_thread_cond_t  cond;      // Condvar for tracking workers terminations

  struct socket queue[20];   // Accepted sockets
  volatile int sq_head;      // Head of the socket queue
  volatile int sq_tail;      // Tail of the socket queue
  mg_thread_cond_t sq_full;    // Signaled when socket is produced
  mg_thread_cond_t sq_empty;   // Signaled when socket is consumed
};

struct mg_connection {
  struct mg_request_info request_info;
  struct mg_context *ctx;
  SSL *ssl;                   // SSL descriptor
  struct socket client;       // Connected client
  time_t birth_time;          // Time when request was received
  int64_t num_bytes_sent;     // Total bytes sent to client
  int64_t content_len;        // Content-Length header value
  int64_t consumed_content;   // How many bytes of content have been read
  char *buf;                  // Buffer for received data
  char *path_info;            // PATH_INFO part of the URL
  int must_close;             // 1 if connection must be closed
  int buf_size;               // Buffer size
  int request_len;            // Size of the request + headers in a buffer
  int data_len;               // Total size of data in a buffer
  int status_code;            // HTTP reply status code, e.g. 200
  int throttle;               // Throttling, bytes/sec. <= 0 means no throttle
  time_t last_throttle_time;  // Last time throttled data was sent
  int64_t last_throttle_bytes;// Bytes sent this second
};

const char **mg_get_valid_option_names(void) {
  return config_options;
}

static void *call_user(struct mg_connection *conn, enum mg_event event) {
  if (conn != NULL && conn->ctx != NULL) {
    conn->request_info.user_data = conn->ctx->user_data;
  }
  return conn == NULL || conn->ctx == NULL || conn->ctx->user_callback == NULL ?
    NULL : conn->ctx->user_callback(event, conn);
}

static int is_file_in_memory(struct mg_connection *conn, const char *path,
                             struct file *filep) {
  conn->request_info.ev_data = (void *) path;
  if ((filep->membuf = call_user(conn, MG_OPEN_FILE)) != NULL) {
    filep->size = (long) conn->request_info.ev_data;
  }
  return filep->membuf != NULL;
}

static int is_file_opened(const struct file *filep) {
  return filep->membuf != NULL || filep->fp != NULL;
}

static int mg_conn_fopen(struct mg_connection *conn, const char *path,
                    const char *mode, struct file *filep) {
  if (!is_file_in_memory(conn, path, filep))  mg_fopen(path, mode, filep);
  return is_file_opened(filep);
}

static int get_option_index(const char *name) {
  int i;

  for (i = 0; config_options[i] != NULL; i += ENTRIES_PER_CONFIG_OPTION) {
    if (strcmp(config_options[i], name) == 0 ||
        strcmp(config_options[i + 1], name) == 0) {
      return i / ENTRIES_PER_CONFIG_OPTION;
    }
  }
  return -1;
}

const char *mg_get_option(const struct mg_context *ctx, const char *name) {
  int i;
  if ((i = get_option_index(name)) == -1) {
    return NULL;
  } else if (ctx->config[i] == NULL) {
    return "";
  } else {
    return ctx->config[i];
  }
}

static void cry(struct mg_connection *conn,
                PRINTF_FORMAT_STRING(const char *fmt), ...) PRINTF_ARGS(2, 3);

// Print error message to the opened error log stream.
static void cry(struct mg_connection *conn, const char *fmt, ...) {
  char buf[MG_BUF_LEN], src_addr[20];
  va_list ap;
  FILE *fp;
  time_t timestamp;

  va_start(ap, fmt);
  (void) vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  // Do not lock when getting the callback value, here and below.
  // I suppose this is fine, since function cannot disappear in the
  // same way string option can.
  conn->request_info.ev_data = buf;
  if (call_user(conn, MG_EVENT_LOG) == NULL) {
    fp = conn->ctx == NULL || conn->ctx->config[ERROR_LOG_FILE] == NULL ? NULL :
      fopen(conn->ctx->config[ERROR_LOG_FILE], "a+");

    if (fp != NULL) {
      flockfile(fp);
      timestamp = time(NULL);

      mg_sockaddr_to_string(src_addr, sizeof(src_addr), &conn->client.rsa);
      fprintf(fp, "[%010lu] [error] [client %s] ", (unsigned long) timestamp,
              src_addr);

      if (conn->request_info.request_method != NULL) {
        fprintf(fp, "%s %s: ", conn->request_info.request_method,
                conn->request_info.uri);
      }

      fprintf(fp, "%s", buf);
      fputc('\n', fp);
      funlockfile(fp);
      fclose(fp);
    }
  }
  conn->request_info.ev_data = NULL;
}

// Return fake connection structure. Used for logging, if connection
// is not applicable at the moment of logging.
static struct mg_connection *fc(struct mg_context *ctx) {
  static struct mg_connection fake_connection;
  fake_connection.ctx = ctx;
  return &fake_connection;
}

const char *mg_version(void) {
  return MONGOOSE_VERSION;
}

struct mg_request_info *mg_get_request_info(struct mg_connection *conn) {
  return &conn->request_info;
}

// Like snprintf(), but never returns negative value, or a value
// that is larger than a supplied buffer.
// Thanks to Adam Zeldis to pointing snprintf()-caused vulnerability
// in his audit report.
static int mg_vsnprintf(struct mg_connection *conn, char *buf, size_t buflen,
                        const char *fmt, va_list ap) {
  int n;

  if (buflen == 0)
    return 0;

  n = vsnprintf(buf, buflen, fmt, ap);

  if (n < 0) {
    cry(conn, "vsnprintf error");
    n = 0;
  } else if (n >= (int) buflen) {
    cry(conn, "truncating vsnprintf buffer: [%.*s]",
        n > 200 ? 200 : n, buf);
    n = (int) buflen - 1;
  }
  buf[n] = '\0';

  return n;
}

static int mg_snprintf(struct mg_connection *conn, char *buf, size_t buflen,
                       PRINTF_FORMAT_STRING(const char *fmt), ...)
  PRINTF_ARGS(4, 5);

static int mg_snprintf(struct mg_connection *conn, char *buf, size_t buflen,
                       const char *fmt, ...) {
  va_list ap;
  int n;

  va_start(ap, fmt);
  n = mg_vsnprintf(conn, buf, buflen, fmt, ap);
  va_end(ap);

  return n;
}

// Simplified version of skip_quoted without quote char
// and whitespace == delimiters
static char *skip(char **buf, const char *delimiters) {
  return mg_skip_quoted(buf, delimiters, delimiters, 0);
}


// Return HTTP header value, or NULL if not found.
static const char *get_header(const struct mg_request_info *ri,
                              const char *name) {
  int i;

  for (i = 0; i < ri->num_headers; i++)
    if (!mg_strcasecmp(name, ri->http_headers[i].name))
      return ri->http_headers[i].value;

  return NULL;
}

const char *mg_get_header(const struct mg_connection *conn, const char *name) {
  return get_header(&conn->request_info, name);
}


// HTTP 1.1 assumes keep alive if "Connection:" header is not set
// This function must tolerate situations when connection info is not
// set up, for example if request parsing failed.
static int should_keep_alive(const struct mg_connection *conn) {
  const char *http_version = conn->request_info.http_version;
  const char *header = mg_get_header(conn, "Connection");
  if (conn->must_close ||
      conn->status_code == 401 ||
      mg_strcasecmp(conn->ctx->config[ENABLE_KEEP_ALIVE], "yes") != 0 ||
      (header != NULL && mg_strcasecmp(header, "keep-alive") != 0) ||
      (header == NULL && http_version && strcmp(http_version, "1.1"))) {
    return 0;
  }
  return 1;
}

static const char *suggest_connection_header(const struct mg_connection *conn) {
  return should_keep_alive(conn) ? "keep-alive" : "close";
}

static void send_http_error(struct mg_connection *, int, const char *,
                            PRINTF_FORMAT_STRING(const char *fmt), ...)
  PRINTF_ARGS(4, 5);


static void send_http_error(struct mg_connection *conn, int status,
                            const char *reason, const char *fmt, ...) {
  char buf[MG_BUF_LEN];
  va_list ap;
  int len;

  conn->status_code = status;
  conn->request_info.ev_data = (void *) (long) status;
  if (call_user(conn, MG_HTTP_ERROR) == NULL) {
    buf[0] = '\0';
    len = 0;

    // Errors 1xx, 204 and 304 MUST NOT send a body
    if (status > 199 && status != 204 && status != 304) {
      len = mg_snprintf(conn, buf, sizeof(buf), "Error %d: %s", status, reason);
      buf[len++] = '\n';

      va_start(ap, fmt);
      len += mg_vsnprintf(conn, buf + len, sizeof(buf) - len, fmt, ap);
      va_end(ap);
    }
    DEBUG_TRACE(("[%s]", buf));

    mg_printf(conn, "HTTP/1.1 %d %s\r\n"
              "Content-Length: %d\r\n"
              "Connection: %s\r\n\r\n", status, reason, len,
              suggest_connection_header(conn));
    conn->num_bytes_sent += mg_printf(conn, "%s", buf);
  }
}

static int mg_conn_stat(struct mg_connection *conn, const char *path,
                   struct file *filep) {
  if (!is_file_in_memory(conn, path, filep)) mg_file_stat(path, filep);
  return filep->membuf != NULL || filep->modification_time != (time_t) 0;
}

pid_t mg_spawn_process(struct mg_connection *conn, const char *prog,
                           char *envblk, char *envp[], int fd_stdin,
                           int fd_stdout, const char *dir);


// Write data to the IO channel - opened file descriptor, socket or SSL
// descriptor. Return number of bytes written.
static int64_t push(FILE *fp, SOCKET sock, SSL *ssl, const char *buf,
                    int64_t len) {
  int64_t sent;
  int n, k;

  sent = 0;
  while (sent < len) {

    // How many bytes we send in this iteration
    k = len - sent > INT_MAX ? INT_MAX : (int) (len - sent);

    if (ssl != NULL) {
      n = SSL_write(ssl, buf + sent, k);
    } else if (fp != NULL) {
      n = (int) fwrite(buf + sent, 1, (size_t) k, fp);
      if (ferror(fp))
        n = -1;
    } else {
      n = send(sock, buf + sent, (size_t) k, MSG_NOSIGNAL);
    }

    if (n < 0)
      break;

    sent += n;
  }

  return sent;
}

// This function is needed to prevent Mongoose to be stuck in a blocking
// socket read when user requested exit. To do that, we sleep in select
// with a timeout, and when returned, check the context for the stop flag.
// If it is set, we return 0, and this means that we must not continue
// reading, must give up and close the connection and exit serving thread.
static int wait_until_socket_is_readable(struct mg_connection *conn) {
  int result;
  struct timeval tv;
  fd_set set;

  do {
    tv.tv_sec = 0;
    tv.tv_usec = 300 * 1000;
    FD_ZERO(&set);
    FD_SET(conn->client.sock, &set);
    result = select(conn->client.sock + 1, &set, NULL, NULL, &tv);
    if(result == 0 && conn->ssl != NULL) {
        result = SSL_pending(conn->ssl);
    }
  } while ((result == 0 || (result < 0 && ERRNO == EINTR)) &&
           conn->ctx->stop_flag == 0);

  return conn->ctx->stop_flag || result < 0 ? 0 : 1;
}

// Read from IO channel - opened file descriptor, socket, or SSL descriptor.
// Return negative value on error, or number of bytes read on success.
static int pull(FILE *fp, struct mg_connection *conn, char *buf, int len) {
  int nread;

  if (fp != NULL) {
    // Use read() instead of fread(), because if we're reading from the CGI
    // pipe, fread() may block until IO buffer is filled up. We cannot afford
    // to block and must pass all read bytes immediately to the client.
    nread = read(fileno(fp), buf, (size_t) len);
  } else if (!conn->must_close && !wait_until_socket_is_readable(conn)) {
    nread = -1;
  } else if (conn->ssl != NULL) {
    nread = SSL_read(conn->ssl, buf, len);
  } else {
    nread = recv(conn->client.sock, buf, (size_t) len, 0);
  }

  return conn->ctx->stop_flag ? -1 : nread;
}

int mg_read(struct mg_connection *conn, void *buf, size_t len) {
  int n, buffered_len, nread;
  const char *body;

  nread = 0;
  if (conn->consumed_content < conn->content_len) {
    // Adjust number of bytes to read.
    int64_t to_read = conn->content_len - conn->consumed_content;
    if (to_read < (int64_t) len) {
      len = (size_t) to_read;
    }

    // Return buffered data
    body = conn->buf + conn->request_len + conn->consumed_content;
    buffered_len = &conn->buf[conn->data_len] - body;
    if (buffered_len > 0) {
      if (len < (size_t) buffered_len) {
        buffered_len = (int) len;
      }
      memcpy(buf, body, (size_t) buffered_len);
      len -= buffered_len;
      conn->consumed_content += buffered_len;
      nread += buffered_len;
      buf = (char *) buf + buffered_len;
    }

    // We have returned all buffered data. Read new data from the remote socket.
    while (len > 0) {
      n = pull(NULL, conn, (char *) buf, (int) len);
      if (n < 0) {
        nread = n;  // Propagate the error
        break;
      } else if (n == 0) {
        break;  // No more data to read
      } else {
        buf = (char *) buf + n;
        conn->consumed_content += n;
        nread += n;
        len -= n;
      }
    }
  }
  return nread;
}

int mg_write(struct mg_connection *conn, const void *buf, size_t len) {
  time_t now;
  int64_t n, total, allowed;

  if (conn->throttle > 0) {
    if ((now = time(NULL)) != conn->last_throttle_time) {
      conn->last_throttle_time = now;
      conn->last_throttle_bytes = 0;
    }
    allowed = conn->throttle - conn->last_throttle_bytes;
    if (allowed > (int64_t) len) {
      allowed = len;
    }
    if ((total = push(NULL, conn->client.sock, conn->ssl, (const char *) buf,
                      (int64_t) allowed)) == allowed) {
      buf = (char *) buf + total;
      conn->last_throttle_bytes += total;
      while (total < (int64_t) len && conn->ctx->stop_flag == 0) {
        allowed = conn->throttle > (int64_t) len - total ?
          (int64_t) len - total : conn->throttle;
        if ((n = push(NULL, conn->client.sock, conn->ssl, (const char *) buf,
                      (int64_t) allowed)) != allowed) {
          break;
        }
        sleep(1);
        conn->last_throttle_bytes = allowed;
        conn->last_throttle_time = time(NULL);
        buf = (char *) buf + n;
        total += n;
      }
    }
  } else {
    total = push(NULL, conn->client.sock, conn->ssl, (const char *) buf,
                 (int64_t) len);
  }
  return (int) total;
}

int mg_printf(struct mg_connection *conn, const char *fmt, ...) {
  char mem[MG_BUF_LEN], *buf = mem;
  int len;
  va_list ap;

  // Print in a local buffer first, hoping that it is large enough to
  // hold the whole message
  va_start(ap, fmt);
  len = vsnprintf(mem, sizeof(mem), fmt, ap);
  va_end(ap);

  if (len == 0) {
    // Do nothing. mg_printf(conn, "%s", "") was called.
  } else if (len < 0) {
    // vsnprintf() error, give up
    len = -1;
    cry(conn, "%s(%s, ...): vsnprintf() error", __func__, fmt);
  } else if (len > (int) sizeof(mem) && (buf = (char *) malloc(len + 1)) != NULL) {
    // Local buffer is not large enough, allocate big buffer on heap
    va_start(ap, fmt);
    vsnprintf(buf, len + 1, fmt, ap);
    va_end(ap);
    len = mg_write(conn, buf, (size_t) len);
    free(buf);
  } else if (len > (int) sizeof(mem)) {
    // Failed to allocate large enough buffer, give up
    cry(conn, "%s(%s, ...): Can't allocate %d bytes, not printing anything",
        __func__, fmt, len);
    len = -1;
  } else {
    // Copy to the local buffer succeeded
    len = mg_write(conn, buf, (size_t) len);
  }

  return len;
}

int mg_get_cookie(const struct mg_connection *conn, const char *cookie_name,
                  char *dst, size_t dst_size) {
  const char *s, *p, *end;
  int name_len, len = -1;

  if (dst == NULL || dst_size == 0) {
      len = -2;
  } else if (cookie_name == NULL || (s = mg_get_header(conn, "Cookie")) == NULL) {
      len = -1;
      dst[0] = '\0';
  } else {
    name_len = (int) strlen(cookie_name);
    end = s + strlen(s);
    dst[0] = '\0';

    for (; (s = strstr(s, cookie_name)) != NULL; s += name_len) {
      if (s[name_len] == '=') {
        s += name_len + 1;
        if ((p = strchr(s, ' ')) == NULL)
          p = end;
        if (p[-1] == ';')
          p--;
        if (*s == '"' && p[-1] == '"' && p > s + 1) {
          s++;
          p--;
        }
        if ((size_t) (p - s) < dst_size) {
          len = p - s;
          mg_strlcpy(dst, s, (size_t) len + 1);
        } else {
          len = -2;
        }
        break;
      }
    }
  }
  return len;
}

static void convert_uri_to_file_name(struct mg_connection *conn, char *buf,
                                     size_t buf_len, struct file *filep) {
  struct vec a, b;
  const char *rewrite, *uri = conn->request_info.uri;
  char *p;
  int match_len;

  // Using buf_len - 1 because memmove() for PATH_INFO may shift part
  // of the path one byte on the right.
  mg_snprintf(conn, buf, buf_len - 1, "%s%s", conn->ctx->config[DOCUMENT_ROOT],
              uri);

  rewrite = conn->ctx->config[REWRITE];
  while ((rewrite = mg_next_option(rewrite, &a, &b)) != NULL) {
    if ((match_len = mg_match_prefix(a.ptr, a.len, uri)) > 0) {
      mg_snprintf(conn, buf, buf_len - 1, "%.*s%s", (int) b.len, b.ptr,
                  uri + match_len);
      break;
    }
  }

  if (!mg_conn_stat(conn, buf, filep)) {
    // Support PATH_INFO for CGI scripts.
    for (p = buf + strlen(buf); p > buf + 1; p--) {
      if (*p == '/') {
        *p = '\0';
        if (mg_match_prefix(conn->ctx->config[CGI_EXTENSIONS],
                         strlen(conn->ctx->config[CGI_EXTENSIONS]), buf) > 0 &&
            mg_conn_stat(conn, buf, filep)) {
          // Shift PATH_INFO block one character right, e.g.
          //  "/x.cgi/foo/bar\x00" => "/x.cgi\x00/foo/bar\x00"
          // conn->path_info is pointing to the local variable "path" declared
          // in handle_request(), so PATH_INFO is not valid after
          // handle_request returns.
          conn->path_info = p + 1;
          memmove(p + 2, p + 1, strlen(p + 1) + 1);  // +1 is for trailing \0
          p[1] = '/';
          break;
        } else {
          *p = '/';
        }
      }
    }
  }
}

static int sslize(struct mg_connection *conn, SSL_CTX *s, int (*func)(SSL *)) {
  return (conn->ssl = SSL_new(s)) != NULL &&
    SSL_set_fd(conn->ssl, conn->client.sock) == 1 &&
    func(conn->ssl) == 1;
}


static const struct {
  const char *extension;
  size_t ext_len;
  const char *mime_type;
} builtin_mime_types[] = {
  {".html", 5, "text/html"},
  {".htm", 4, "text/html"},
  {".shtm", 5, "text/html"},
  {".shtml", 6, "text/html"},
  {".css", 4, "text/css"},
  {".js",  3, "application/x-javascript"},
  {".ico", 4, "image/x-icon"},
  {".gif", 4, "image/gif"},
  {".jpg", 4, "image/jpeg"},
  {".jpeg", 5, "image/jpeg"},
  {".png", 4, "image/png"},
  {".svg", 4, "image/svg+xml"},
  {".txt", 4, "text/plain"},
  {".torrent", 8, "application/x-bittorrent"},
  {".wav", 4, "audio/x-wav"},
  {".mp3", 4, "audio/x-mp3"},
  {".mid", 4, "audio/mid"},
  {".m3u", 4, "audio/x-mpegurl"},
  {".ogg", 4, "audio/ogg"},
  {".ram", 4, "audio/x-pn-realaudio"},
  {".xml", 4, "text/xml"},
  {".json",  5, "text/json"},
  {".xslt", 5, "application/xml"},
  {".xsl", 4, "application/xml"},
  {".ra",  3, "audio/x-pn-realaudio"},
  {".doc", 4, "application/msword"},
  {".exe", 4, "application/octet-stream"},
  {".zip", 4, "application/x-zip-compressed"},
  {".xls", 4, "application/excel"},
  {".tgz", 4, "application/x-tar-gz"},
  {".tar", 4, "application/x-tar"},
  {".gz",  3, "application/x-gunzip"},
  {".arj", 4, "application/x-arj-compressed"},
  {".rar", 4, "application/x-arj-compressed"},
  {".rtf", 4, "application/rtf"},
  {".pdf", 4, "application/pdf"},
  {".swf", 4, "application/x-shockwave-flash"},
  {".mpg", 4, "video/mpeg"},
  {".webm", 5, "video/webm"},
  {".mpeg", 5, "video/mpeg"},
  {".mp4", 4, "video/mp4"},
  {".m4v", 4, "video/x-m4v"},
  {".asf", 4, "video/x-ms-asf"},
  {".avi", 4, "video/x-msvideo"},
  {".bmp", 4, "image/bmp"},
  {NULL,  0, NULL}
};

const char *mg_get_builtin_mime_type(const char *path) {
  const char *ext;
  size_t i, path_len;

  path_len = strlen(path);

  for (i = 0; builtin_mime_types[i].extension != NULL; i++) {
    ext = path + (path_len - builtin_mime_types[i].ext_len);
    if (path_len > builtin_mime_types[i].ext_len &&
        mg_strcasecmp(ext, builtin_mime_types[i].extension) == 0) {
      return builtin_mime_types[i].mime_type;
    }
  }

  return "text/plain";
}

// Look at the "path" extension and figure what mime type it has.
// Store mime type in the vector.
static void get_mime_type(struct mg_context *ctx, const char *path,
                          struct vec *vec) {
  struct vec ext_vec, mime_vec;
  const char *list, *ext;
  size_t path_len;

  path_len = strlen(path);

  // Scan user-defined mime types first, in case user wants to
  // override default mime types.
  list = ctx->config[EXTRA_MIME_TYPES];
  while ((list = mg_next_option(list, &ext_vec, &mime_vec)) != NULL) {
    // ext now points to the path suffix
    ext = path + path_len - ext_vec.len;
    if (mg_strncasecmp(ext, ext_vec.ptr, ext_vec.len) == 0) {
      *vec = mime_vec;
      return;
    }
  }

  vec->ptr = mg_get_builtin_mime_type(path);
  vec->len = strlen(vec->ptr);
}

// Stringify binary data. Output buffer must be twice as big as input,
// because each byte takes 2 bytes in string representation
static void bin2str(char *to, const unsigned char *p, size_t len) {
  static const char *hex = "0123456789abcdef";

  for (; len--; p++) {
    *to++ = hex[p[0] >> 4];
    *to++ = hex[p[0] & 0x0f];
  }
  *to = '\0';
}

// Return stringified MD5 hash for list of strings. Buffer must be 33 bytes.
void mg_md5(char buf[33], ...) {
  unsigned char hash[16];
  const char *p;
  va_list ap;
  MD5_CTX ctx;

  MD5Init(&ctx);

  va_start(ap, buf);
  while ((p = va_arg(ap, const char *)) != NULL) {
    MD5Update(&ctx, (const unsigned char *) p, (unsigned) strlen(p));
  }
  va_end(ap);

  MD5Final(hash, &ctx);
  bin2str(buf, hash, sizeof(hash));
}

// Check the user's password, return 1 if OK
static int check_password(const char *method, const char *ha1, const char *uri,
                          const char *nonce, const char *nc, const char *cnonce,
                          const char *qop, const char *response) {
  char ha2[32 + 1], expected_response[32 + 1];

  // Some of the parameters may be NULL
  if (method == NULL || nonce == NULL || nc == NULL || cnonce == NULL ||
      qop == NULL || response == NULL) {
    return 0;
  }

  // NOTE(lsm): due to a bug in MSIE, we do not compare the URI
  // TODO(lsm): check for authentication timeout
  if (// strcmp(dig->uri, c->ouri) != 0 ||
      strlen(response) != 32
      // || now - strtoul(dig->nonce, NULL, 10) > 3600
      ) {
    return 0;
  }

  mg_md5(ha2, method, ":", uri, NULL);
  mg_md5(expected_response, ha1, ":", nonce, ":", nc,
      ":", cnonce, ":", qop, ":", ha2, NULL);

  return mg_strcasecmp(response, expected_response) == 0;
}

// Use the global passwords file, if specified by auth_gpass option,
// or search for .htpasswd in the requested directory.
static void open_auth_file(struct mg_connection *conn, const char *path,
                           struct file *filep) {
  char name[PATH_MAX];
  const char *p, *e, *gpass = conn->ctx->config[GLOBAL_PASSWORDS_FILE];

  if (gpass != NULL) {
    // Use global passwords file
    if (!mg_conn_fopen(conn, gpass, "r", filep)) {
      cry(conn, "fopen(%s): %s", gpass, strerror(ERRNO));
    }
  } else if (mg_conn_stat(conn, path, filep) && filep->is_directory) {
    mg_snprintf(conn, name, sizeof(name), "%s%c%s",
                path, '/', PASSWORDS_FILE_NAME);
    mg_conn_fopen(conn, name, "r", filep);
  } else {
     // Try to find .htpasswd in requested directory.
    for (p = path, e = p + strlen(p) - 1; e > p; e--)
      if (e[0] == '/')
        break;
    mg_snprintf(conn, name, sizeof(name), "%.*s%c%s",
                (int) (e - p), p, '/', PASSWORDS_FILE_NAME);
    mg_conn_fopen(conn, name, "r", filep);
  }
}

// Parsed Authorization header
struct ah {
  char *user, *uri, *cnonce, *response, *qop, *nc, *nonce;
};

// Return 1 on success. Always initializes the ah structure.
static int parse_auth_header(struct mg_connection *conn, char *buf,
                             size_t buf_size, struct ah *ah) {
  char *name, *value, *s;
  const char *auth_header;

  (void) memset(ah, 0, sizeof(*ah));
  if ((auth_header = mg_get_header(conn, "Authorization")) == NULL ||
      mg_strncasecmp(auth_header, "Digest ", 7) != 0) {
    return 0;
  }

  // Make modifiable copy of the auth header
  (void) mg_strlcpy(buf, auth_header + 7, buf_size);
  s = buf;

  // Parse authorization header
  for (;;) {
    // Gobble initial spaces
    while (isspace(* (unsigned char *) s)) {
      s++;
    }
    name = mg_skip_quoted(&s, "=", " ", 0);
    // Value is either quote-delimited, or ends at first comma or space.
    if (s[0] == '\"') {
      s++;
      value = mg_skip_quoted(&s, "\"", " ", '\\');
      if (s[0] == ',') {
        s++;
      }
    } else {
      value = mg_skip_quoted(&s, ", ", " ", 0);  // IE uses commas, FF uses spaces
    }
    if (*name == '\0') {
      break;
    }

    if (!strcmp(name, "username")) {
      ah->user = value;
    } else if (!strcmp(name, "cnonce")) {
      ah->cnonce = value;
    } else if (!strcmp(name, "response")) {
      ah->response = value;
    } else if (!strcmp(name, "uri")) {
      ah->uri = value;
    } else if (!strcmp(name, "qop")) {
      ah->qop = value;
    } else if (!strcmp(name, "nc")) {
      ah->nc = value;
    } else if (!strcmp(name, "nonce")) {
      ah->nonce = value;
    }
  }

  // CGI needs it as REMOTE_USER
  if (ah->user != NULL) {
    conn->request_info.remote_user = mg_strdup(ah->user);
  } else {
    return 0;
  }

  return 1;
}

static char *mg_fgets(char *buf, size_t size, struct file *filep, char **p) {
  char *eof;
  size_t len;

  if (filep->membuf != NULL && *p != NULL) {
    eof = memchr(*p, '\n', &filep->membuf[filep->size] - *p);
    len = (size_t) (eof - *p) > size - 1 ? size - 1 : (size_t) (eof - *p);
    memcpy(buf, *p, len);
    buf[len] = '\0';
    *p = eof;
    return eof;
  } else if (filep->fp != NULL) {
    return fgets(buf, size, filep->fp);
  } else {
    return NULL;
  }
}

// Authorize against the opened passwords file. Return 1 if authorized.
static int authorize(struct mg_connection *conn, struct file *filep) {
  struct ah ah;
  char line[256], f_user[256], ha1[256], f_domain[256], buf[MG_BUF_LEN], *p;

  if (!parse_auth_header(conn, buf, sizeof(buf), &ah)) {
    return 0;
  }

  // Loop over passwords file
  p = (char *) filep->membuf;
  while (mg_fgets(line, sizeof(line), filep, &p) != NULL) {
    if (sscanf(line, "%[^:]:%[^:]:%s", f_user, f_domain, ha1) != 3) {
      continue;
    }

    if (!strcmp(ah.user, f_user) &&
        !strcmp(conn->ctx->config[AUTHENTICATION_DOMAIN], f_domain))
      return check_password(conn->request_info.request_method, ha1, ah.uri,
                            ah.nonce, ah.nc, ah.cnonce, ah.qop, ah.response);
  }

  return 0;
}

// Return 1 if request is authorised, 0 otherwise.
static int check_authorization(struct mg_connection *conn, const char *path) {
  char fname[PATH_MAX];
  struct vec uri_vec, filename_vec;
  const char *list;
  struct file file = STRUCT_FILE_INITIALIZER;
  int authorized = 1;

  list = conn->ctx->config[PROTECT_URI];
  while ((list = mg_next_option(list, &uri_vec, &filename_vec)) != NULL) {
    if (!memcmp(conn->request_info.uri, uri_vec.ptr, uri_vec.len)) {
      mg_snprintf(conn, fname, sizeof(fname), "%.*s",
                  (int) filename_vec.len, filename_vec.ptr);
      if (!mg_conn_fopen(conn, fname, "r", &file)) {
        cry(conn, "%s: cannot open %s: %s", __func__, fname, strerror(errno));
      }
      break;
    }
  }

  if (!is_file_opened(&file)) {
    open_auth_file(conn, path, &file);
  }

  if (is_file_opened(&file)) {
    authorized = authorize(conn, &file);
    mg_fclose(&file);
  }

  return authorized;
}

static void send_authorization_request(struct mg_connection *conn) {
  conn->status_code = 401;
  mg_printf(conn,
            "HTTP/1.1 401 Unauthorized\r\n"
            "Content-Length: 0\r\n"
            "WWW-Authenticate: Digest qop=\"auth\", "
            "realm=\"%s\", nonce=\"%lu\"\r\n\r\n",
            conn->ctx->config[AUTHENTICATION_DOMAIN],
            (unsigned long) time(NULL));
}

static int is_authorized_for_put(struct mg_connection *conn) {
  struct file file = STRUCT_FILE_INITIALIZER;
  const char *passfile = conn->ctx->config[PUT_DELETE_PASSWORDS_FILE];
  int ret = 0;

  if (passfile != NULL && mg_conn_fopen(conn, passfile, "r", &file)) {
    ret = authorize(conn, &file);
    mg_fclose(&file);
  }

  return ret;
}

int mg_modify_passwords_file(const char *fname, const char *domain,
                             const char *user, const char *pass) {
  int found;
  char line[512], u[512], d[512], ha1[33], tmp[PATH_MAX];
  FILE *fp, *fp2;

  found = 0;
  fp = fp2 = NULL;

  // Regard empty password as no password - remove user record.
  if (pass != NULL && pass[0] == '\0') {
    pass = NULL;
  }

  (void) snprintf(tmp, sizeof(tmp), "%s.tmp", fname);

  // Create the file if does not exist
  if ((fp = fopen(fname, "a+")) != NULL) {
    (void) fclose(fp);
  }

  // Open the given file and temporary file
  if ((fp = fopen(fname, "r")) == NULL) {
    return 0;
  } else if ((fp2 = fopen(tmp, "w+")) == NULL) {
    fclose(fp);
    return 0;
  }

  // Copy the stuff to temporary file
  while (fgets(line, sizeof(line), fp) != NULL) {
    if (sscanf(line, "%[^:]:%[^:]:%*s", u, d) != 2) {
      continue;
    }

    if (!strcmp(u, user) && !strcmp(d, domain)) {
      found++;
      if (pass != NULL) {
        mg_md5(ha1, user, ":", domain, ":", pass, NULL);
        fprintf(fp2, "%s:%s:%s\n", user, domain, ha1);
      }
    } else {
      fprintf(fp2, "%s", line);
    }
  }

  // If new user, just add it
  if (!found && pass != NULL) {
    mg_md5(ha1, user, ":", domain, ":", pass, NULL);
    fprintf(fp2, "%s:%s:%s\n", user, domain, ha1);
  }

  // Close files
  fclose(fp);
  fclose(fp2);

  // Put the temp file in place of real file
  remove(fname);
  rename(tmp, fname);

  return 1;
}

struct de {
  struct mg_connection *conn;
  char *file_name;
  struct file file;
};

static void print_dir_entry(struct de *de) {
  char size[64], mod[64], href[PATH_MAX];

  if (de->file.is_directory) {
    mg_snprintf(de->conn, size, sizeof(size), "%s", "[DIRECTORY]");
  } else {
     // We use (signed) cast below because MSVC 6 compiler cannot
     // convert unsigned __int64 to double. Sigh.
    if (de->file.size < 1024) {
      mg_snprintf(de->conn, size, sizeof(size), "%d", (int) de->file.size);
    } else if (de->file.size < 0x100000) {
      mg_snprintf(de->conn, size, sizeof(size),
                  "%.1fk", (double) de->file.size / 1024.0);
    } else if (de->file.size < 0x40000000) {
      mg_snprintf(de->conn, size, sizeof(size),
                  "%.1fM", (double) de->file.size / 1048576);
    } else {
      mg_snprintf(de->conn, size, sizeof(size),
                  "%.1fG", (double) de->file.size / 1073741824);
    }
  }
  strftime(mod, sizeof(mod), "%d-%b-%Y %H:%M",
           localtime(&de->file.modification_time));
  mg_url_encode(de->file_name, href, sizeof(href));
  de->conn->num_bytes_sent += mg_printf(de->conn,
      "<tr><td><a href=\"%s%s%s\">%s%s</a></td>"
      "<td>&nbsp;%s</td><td>&nbsp;&nbsp;%s</td></tr>\n",
      de->conn->request_info.uri, href, de->file.is_directory ? "/" : "",
      de->file_name, de->file.is_directory ? "/" : "", mod, size);
}

// This function is called from send_directory() and used for
// sorting directory entries by size, or name, or modification time.
// On windows, __cdecl specification is needed in case if project is built
// with __stdcall convention. qsort always requires __cdels callback.
static int WINCDECL compare_dir_entries(const void *p1, const void *p2) {
  const struct de *a = (const struct de *) p1, *b = (const struct de *) p2;
  const char *query_string = a->conn->request_info.query_string;
  int cmp_result = 0;

  if (query_string == NULL) {
    query_string = "na";
  }

  if (a->file.is_directory && !b->file.is_directory) {
    return -1;  // Always put directories on top
  } else if (!a->file.is_directory && b->file.is_directory) {
    return 1;   // Always put directories on top
  } else if (*query_string == 'n') {
    cmp_result = strcmp(a->file_name, b->file_name);
  } else if (*query_string == 's') {
    cmp_result = a->file.size == b->file.size ? 0 :
      a->file.size > b->file.size ? 1 : -1;
  } else if (*query_string == 'd') {
    cmp_result = a->file.modification_time == b->file.modification_time ? 0 :
      a->file.modification_time > b->file.modification_time ? 1 : -1;
  }

  return query_string[1] == 'd' ? -cmp_result : cmp_result;
}

static int must_hide_file(struct mg_connection *conn, const char *path) {
  const char *pw_pattern = "**" PASSWORDS_FILE_NAME "$";
  const char *pattern = conn->ctx->config[HIDE_FILES];
  return mg_match_prefix(pw_pattern, strlen(pw_pattern), path) > 0 ||
    (pattern != NULL && mg_match_prefix(pattern, strlen(pattern), path) > 0);
}

static int scan_directory(struct mg_connection *conn, const char *dir,
                          void *data, void (*cb)(struct de *, void *)) {
  char path[PATH_MAX];
  struct dirent *dp;
  DIR *dirp;
  struct de de;

  if ((dirp = opendir(dir)) == NULL) {
    return 0;
  } else {
    de.conn = conn;

    while ((dp = readdir(dirp)) != NULL) {
      // Do not show current dir and hidden files
      if (!strcmp(dp->d_name, ".") ||
          !strcmp(dp->d_name, "..") ||
          must_hide_file(conn, dp->d_name)) {
        continue;
      }

      mg_snprintf(conn, path, sizeof(path), "%s%c%s", dir, '/', dp->d_name);

      // If we don't memset stat structure to zero, mtime will have
      // garbage and strftime() will segfault later on in
      // print_dir_entry(). memset is required only if mg_stat()
      // fails. For more details, see
      // http://code.google.com/p/mongoose/issues/detail?id=79
      // mg_stat will memset the whole struct file with zeroes.
      mg_conn_stat(conn, path, &de.file);

      de.file_name = dp->d_name;
      cb(&de, data);
    }
    (void) closedir(dirp);
  }
  return 1;
}

struct dir_scan_data {
  struct de *entries;
  int num_entries;
  int arr_size;
};

static void dir_scan_callback(struct de *de, void *data) {
  struct dir_scan_data *dsd = (struct dir_scan_data *) data;

  if (dsd->entries == NULL || dsd->num_entries >= dsd->arr_size) {
    dsd->arr_size *= 2;
    dsd->entries = (struct de *) realloc(dsd->entries, dsd->arr_size *
                                         sizeof(dsd->entries[0]));
  }
  if (dsd->entries == NULL) {
    // TODO(lsm): propagate an error to the caller
    dsd->num_entries = 0;
  } else {
    dsd->entries[dsd->num_entries].file_name = mg_strdup(de->file_name);
    dsd->entries[dsd->num_entries].file = de->file;
    dsd->entries[dsd->num_entries].conn = de->conn;
    dsd->num_entries++;
  }
}

static void handle_directory_request(struct mg_connection *conn,
                                     const char *dir) {
  int i, sort_direction;
  struct dir_scan_data data = { NULL, 0, 128 };

  if (!scan_directory(conn, dir, &data, dir_scan_callback)) {
    send_http_error(conn, 500, "Cannot open directory",
                    "Error: opendir(%s): %s", dir, strerror(ERRNO));
    return;
  }

  sort_direction = conn->request_info.query_string != NULL &&
    conn->request_info.query_string[1] == 'd' ? 'a' : 'd';

  conn->must_close = 1;
  mg_printf(conn, "%s",
            "HTTP/1.1 200 OK\r\n"
            "Connection: close\r\n"
            "Content-Type: text/html; charset=utf-8\r\n\r\n");

  conn->num_bytes_sent += mg_printf(conn,
      "<html><head><title>Index of %s</title>"
      "<style>th {text-align: left;}</style></head>"
      "<body><h1>Index of %s</h1><pre><table cellpadding=\"0\">"
      "<tr><th><a href=\"?n%c\">Name</a></th>"
      "<th><a href=\"?d%c\">Modified</a></th>"
      "<th><a href=\"?s%c\">Size</a></th></tr>"
      "<tr><td colspan=\"3\"><hr></td></tr>",
      conn->request_info.uri, conn->request_info.uri,
      sort_direction, sort_direction, sort_direction);

  // Print first entry - link to a parent directory
  conn->num_bytes_sent += mg_printf(conn,
      "<tr><td><a href=\"%s%s\">%s</a></td>"
      "<td>&nbsp;%s</td><td>&nbsp;&nbsp;%s</td></tr>\n",
      conn->request_info.uri, "..", "Parent directory", "-", "-");

  // Sort and print directory entries
  qsort(data.entries, (size_t) data.num_entries, sizeof(data.entries[0]),
        compare_dir_entries);
  for (i = 0; i < data.num_entries; i++) {
    print_dir_entry(&data.entries[i]);
    free(data.entries[i].file_name);
  }
  free(data.entries);

  conn->num_bytes_sent += mg_printf(conn, "%s", "</table></body></html>");
  conn->status_code = 200;
}

// Send len bytes from the opened file to the client.
static void send_file_data(struct mg_connection *conn, struct file *filep,
                           int64_t offset, int64_t len) {
  char buf[MG_BUF_LEN];
  int to_read, num_read, num_written;

  if (len > 0 && filep->membuf != NULL && filep->size > 0) {
    if (len > filep->size - offset) {
      len = filep->size - offset;
    }
    mg_write(conn, filep->membuf + offset, (size_t) len);
  } else if (len > 0 && filep->fp != NULL) {
    fseeko(filep->fp, offset, SEEK_SET);
    while (len > 0) {
      // Calculate how much to read from the file in the buffer
      to_read = sizeof(buf);
      if ((int64_t) to_read > len) {
        to_read = (int) len;
      }

      // Read from file, exit the loop on error
      if ((num_read = fread(buf, 1, (size_t) to_read, filep->fp)) <= 0) {
        break;
      }

      // Send read bytes to the client, exit the loop on error
      if ((num_written = mg_write(conn, buf, (size_t) num_read)) != num_read) {
        break;
      }

      // Both read and were successful, adjust counters
      conn->num_bytes_sent += num_written;
      len -= num_written;
    }
  }
}

static int parse_range_header(const char *header, int64_t *a, int64_t *b) {
  return sscanf(header, "bytes=%" INT64_FMT "-%" INT64_FMT, a, b);
}

static void gmt_time_string(char *buf, size_t buf_len, time_t *t) {
  strftime(buf, buf_len, "%a, %d %b %Y %H:%M:%S GMT", gmtime(t));
}

static void construct_etag(char *buf, size_t buf_len,
                           const struct file *filep) {
  snprintf(buf, buf_len, "\"%lx.%" INT64_FMT "\"",
           (unsigned long) filep->modification_time, filep->size);
}

static void fclose_on_exec(struct file *filep) {
  if (filep != NULL && filep->fp != NULL) {
#ifndef _WIN32
    fcntl(fileno(filep->fp), F_SETFD, FD_CLOEXEC);
#endif
  }
}

static void handle_file_request(struct mg_connection *conn, const char *path,
                                struct file *filep) {
  char date[64], lm[64], etag[64], range[64];
  const char *msg = "OK", *hdr;
  time_t curtime = time(NULL);
  int64_t cl, r1, r2;
  struct vec mime_vec;
  int n;

  get_mime_type(conn->ctx, path, &mime_vec);
  cl = filep->size;
  conn->status_code = 200;
  range[0] = '\0';

  if (!mg_conn_fopen(conn, path, "rb", filep)) {
    send_http_error(conn, 500, http_500_error,
        "fopen(%s): %s", path, strerror(ERRNO));
    return;
  }
  fclose_on_exec(filep);

  // If Range: header specified, act accordingly
  r1 = r2 = 0;
  hdr = mg_get_header(conn, "Range");
  if (hdr != NULL && (n = parse_range_header(hdr, &r1, &r2)) > 0 &&
      r1 >= 0 && r2 > 0) {
    conn->status_code = 206;
    cl = n == 2 ? (r2 > cl ? cl : r2) - r1 + 1: cl - r1;
    mg_snprintf(conn, range, sizeof(range),
                "Content-Range: bytes "
                "%" INT64_FMT "-%"
                INT64_FMT "/%" INT64_FMT "\r\n",
                r1, r1 + cl - 1, filep->size);
    msg = "Partial Content";
  }

  // Prepare Etag, Date, Last-Modified headers. Must be in UTC, according to
  // http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.3
  gmt_time_string(date, sizeof(date), &curtime);
  gmt_time_string(lm, sizeof(lm), &filep->modification_time);
  construct_etag(etag, sizeof(etag), filep);

  (void) mg_printf(conn,
      "HTTP/1.1 %d %s\r\n"
      "Date: %s\r\n"
      "Last-Modified: %s\r\n"
      "Etag: %s\r\n"
      "Content-Type: %.*s\r\n"
      "Content-Length: %" INT64_FMT "\r\n"
      "Connection: %s\r\n"
      "Accept-Ranges: bytes\r\n"
      "%s\r\n",
      conn->status_code, msg, date, lm, etag, (int) mime_vec.len,
      mime_vec.ptr, cl, suggest_connection_header(conn), range);

  if (strcmp(conn->request_info.request_method, "HEAD") != 0) {
    send_file_data(conn, filep, r1, cl);
  }
  mg_fclose(filep);
}

void mg_send_file(struct mg_connection *conn, const char *path) {
  struct file file;
  if (mg_conn_stat(conn, path, &file)) {
    handle_file_request(conn, path, &file);
  } else {
    send_http_error(conn, 404, "Not Found", "%s", "File not found");
  }
}


// Parse HTTP headers from the given buffer, advance buffer to the point
// where parsing stopped.
static void parse_http_headers(char **buf, struct mg_request_info *ri) {
  int i;

  for (i = 0; i < (int) ARRAY_SIZE(ri->http_headers); i++) {
    ri->http_headers[i].name = mg_skip_quoted(buf, ":", " ", 0);
    ri->http_headers[i].value = skip(buf, "\r\n");
    if (ri->http_headers[i].name[0] == '\0')
      break;
    ri->num_headers = i + 1;
  }
}

static int is_valid_http_method(const char *method) {
  return !strcmp(method, "GET") || !strcmp(method, "POST") ||
    !strcmp(method, "HEAD") || !strcmp(method, "CONNECT") ||
    !strcmp(method, "PUT") || !strcmp(method, "DELETE") ||
    !strcmp(method, "OPTIONS") || !strcmp(method, "PROPFIND");
}

// Parse HTTP request, fill in mg_request_info structure.
// This function modifies the buffer by NUL-terminating
// HTTP request components, header names and header values.
static int parse_http_message(char *buf, int len, struct mg_request_info *ri) {
  int request_length = mg_get_request_len(buf, len);
  if (request_length > 0) {
    // Reset attributes. DO NOT TOUCH is_ssl, remote_ip, remote_port
    ri->remote_user = ri->request_method = ri->uri = ri->http_version = NULL;
    ri->num_headers = 0;

    buf[request_length - 1] = '\0';

    // RFC says that all initial whitespaces should be ingored
    while (*buf != '\0' && isspace(* (unsigned char *) buf)) {
      buf++;
    }
    ri->request_method = skip(&buf, " ");
    ri->uri = skip(&buf, " ");
    ri->http_version = skip(&buf, "\r\n");
    parse_http_headers(&buf, ri);
  }
  return request_length;
}

static int parse_http_request(char *buf, int len, struct mg_request_info *ri) {
  int result = parse_http_message(buf, len, ri);
  if (result > 0 &&
      is_valid_http_method(ri->request_method) &&
      !strncmp(ri->http_version, "HTTP/", 5)) {
    ri->http_version += 5;   // Skip "HTTP/"
  } else {
    result = -1;
  }
  return result;
}

static int parse_http_response(char *buf, int len, struct mg_request_info *ri) {
  int result = parse_http_message(buf, len, ri);
  return result > 0 && !strncmp(ri->request_method, "HTTP/", 5) ? result : -1;
}

// Keep reading the input (either opened file descriptor fd, or socket sock,
// or SSL descriptor ssl) into buffer buf, until \r\n\r\n appears in the
// buffer (which marks the end of HTTP request). Buffer buf may already
// have some data. The length of the data is stored in nread.
// Upon every read operation, increase nread by the number of bytes read.
static int read_request(FILE *fp, struct mg_connection *conn,
                        char *buf, int bufsiz, int *nread) {
  int request_len, n = 1;

  request_len = mg_get_request_len(buf, *nread);
  while (*nread < bufsiz && request_len == 0 && n > 0) {
    n = pull(fp, conn, buf + *nread, bufsiz - *nread);
    if (n > 0) {
      *nread += n;
      request_len = mg_get_request_len(buf, *nread);
    }
  }

  if (n < 0) {
    // recv() error -> propagate error; do not process a b0rked-with-very-high-probability request
    return -1;
  }
  return request_len;
}

// For given directory path, substitute it to valid index file.
// Return 0 if index file has been found, -1 if not found.
// If the file is found, it's stats is returned in stp.
static int substitute_index_file(struct mg_connection *conn, char *path,
                                 size_t path_len, struct file *filep) {
  const char *list = conn->ctx->config[INDEX_FILES];
  struct file file = STRUCT_FILE_INITIALIZER;
  struct vec filename_vec;
  size_t n = strlen(path);
  int found = 0;

  // The 'path' given to us points to the directory. Remove all trailing
  // directory separator characters from the end of the path, and
  // then append single directory separator character.
  while (n > 0 && path[n - 1] == '/') {
    n--;
  }
  path[n] = '/';

  // Traverse index files list. For each entry, append it to the given
  // path and see if the file exists. If it exists, break the loop
  while ((list = mg_next_option(list, &filename_vec, NULL)) != NULL) {

    // Ignore too long entries that may overflow path buffer
    if (filename_vec.len > path_len - (n + 2))
      continue;

    // Prepare full path to the index file
    mg_strlcpy(path + n + 1, filename_vec.ptr, filename_vec.len + 1);

    // Does it exist?
    if (mg_conn_stat(conn, path, &file)) {
      // Yes it does, break the loop
      *filep = file;
      found = 1;
      break;
    }
  }

  // If no index file exists, restore directory path
  if (!found) {
    path[n] = '\0';
  }

  return found;
}

// Return True if we should reply 304 Not Modified.
static int is_not_modified(const struct mg_connection *conn,
                           const struct file *filep) {
  char etag[64];
  const char *ims = mg_get_header(conn, "If-Modified-Since");
  const char *inm = mg_get_header(conn, "If-None-Match");
  construct_etag(etag, sizeof(etag), filep);
  return (inm != NULL && !mg_strcasecmp(etag, inm)) ||
    (ims != NULL && filep->modification_time <= mg_parse_date_string(ims));
}

static int forward_body_data(struct mg_connection *conn, FILE *fp,
                             SOCKET sock, SSL *ssl) {
  const char *expect, *body;
  char buf[MG_BUF_LEN];
  int to_read, nread, buffered_len, success = 0;

  expect = mg_get_header(conn, "Expect");
  assert(fp != NULL);

  if (conn->content_len == -1) {
    send_http_error(conn, 411, "Length Required", "%s", "");
  } else if (expect != NULL && mg_strcasecmp(expect, "100-continue")) {
    send_http_error(conn, 417, "Expectation Failed", "%s", "");
  } else {
    if (expect != NULL) {
      (void) mg_printf(conn, "%s", "HTTP/1.1 100 Continue\r\n\r\n");
    }

    body = conn->buf + conn->request_len + conn->consumed_content;
    buffered_len = &conn->buf[conn->data_len] - body;
    assert(buffered_len >= 0);
    assert(conn->consumed_content == 0);

    if (buffered_len > 0) {
      if ((int64_t) buffered_len > conn->content_len) {
        buffered_len = (int) conn->content_len;
      }
      push(fp, sock, ssl, body, (int64_t) buffered_len);
      conn->consumed_content += buffered_len;
    }

    nread = 0;
    while (conn->consumed_content < conn->content_len) {
      to_read = sizeof(buf);
      if ((int64_t) to_read > conn->content_len - conn->consumed_content) {
        to_read = (int) (conn->content_len - conn->consumed_content);
      }
      nread = pull(NULL, conn, buf, to_read);
      if (nread <= 0 || push(fp, sock, ssl, buf, nread) != nread) {
        break;
      }
      conn->consumed_content += nread;
    }

    if (conn->consumed_content == conn->content_len) {
      success = nread >= 0;
    }

    // Each error code path in this function must send an error
    if (!success) {
      send_http_error(conn, 577, http_500_error, "%s", "");
    }
  }

  return success;
}

#if !defined(NO_CGI)
#include "mongoose_cgi.h"
#endif

// For a given PUT path, create all intermediate subdirectories
// for given path. Return 0 if the path itself is a directory,
// or -1 on error, 1 if OK.
static int put_dir(struct mg_connection *conn, const char *path) {
  char buf[PATH_MAX];
  const char *s, *p;
  struct file file;
  int len, res = 1;

  for (s = p = path + 2; (p = strchr(s, '/')) != NULL; s = ++p) {
    len = p - path;
    if (len >= (int) sizeof(buf)) {
      res = -1;
      break;
    }
    memcpy(buf, path, len);
    buf[len] = '\0';

    // Try to create intermediate directory
    DEBUG_TRACE(("mkdir(%s)", buf));
    if (!mg_conn_stat(conn, buf, &file) && mg_mkdir(buf, 0755) != 0) {
      res = -1;
      break;
    }

    // Is path itself a directory?
    if (p[1] == '\0') {
      res = 0;
    }
  }

  return res;
}

static void put_file(struct mg_connection *conn, const char *path) {
  struct file file;
  const char *range;
  int64_t r1, r2;
  int rc;

  conn->status_code = mg_conn_stat(conn, path, &file) ? 200 : 201;

  if ((rc = put_dir(conn, path)) == 0) {
    mg_printf(conn, "HTTP/1.1 %d OK\r\n\r\n", conn->status_code);
  } else if (rc == -1) {
    send_http_error(conn, 500, http_500_error,
                    "put_dir(%s): %s", path, strerror(ERRNO));
  } else if (!mg_conn_fopen(conn, path, "wb+", &file) || file.fp == NULL) {
    mg_fclose(&file);
    send_http_error(conn, 500, http_500_error,
                    "fopen(%s): %s", path, strerror(ERRNO));
  } else {
    fclose_on_exec(&file);
    range = mg_get_header(conn, "Content-Range");
    r1 = r2 = 0;
    if (range != NULL && parse_range_header(range, &r1, &r2) > 0) {
      conn->status_code = 206;
      fseeko(file.fp, r1, SEEK_SET);
    }
    if (forward_body_data(conn, file.fp, INVALID_SOCKET, NULL)) {
      mg_printf(conn, "HTTP/1.1 %d OK\r\n\r\n", conn->status_code);
    }
    mg_fclose(&file);
  }
}

static void send_ssi_file(struct mg_connection *, const char *,
                          struct file *, int);

static void do_ssi_include(struct mg_connection *conn, const char *ssi,
                           char *tag, int include_level) {
  char file_name[MG_BUF_LEN], path[PATH_MAX], *p;
  struct file file;

  // sscanf() is safe here, since send_ssi_file() also uses buffer
  // of size MG_BUF_LEN to get the tag. So strlen(tag) is always < MG_BUF_LEN.
  if (sscanf(tag, " virtual=\"%[^\"]\"", file_name) == 1) {
    // File name is relative to the webserver root
    (void) mg_snprintf(conn, path, sizeof(path), "%s%c%s",
        conn->ctx->config[DOCUMENT_ROOT], '/', file_name);
  } else if (sscanf(tag, " file=\"%[^\"]\"", file_name) == 1) {
    // File name is relative to the webserver working directory
    // or it is absolute system path
    (void) mg_snprintf(conn, path, sizeof(path), "%s", file_name);
  } else if (sscanf(tag, " \"%[^\"]\"", file_name) == 1) {
    // File name is relative to the currect document
    (void) mg_snprintf(conn, path, sizeof(path), "%s", ssi);
    if ((p = strrchr(path, '/')) != NULL) {
      p[1] = '\0';
    }
    (void) mg_snprintf(conn, path + strlen(path),
        sizeof(path) - strlen(path), "%s", file_name);
  } else {
    cry(conn, "Bad SSI #include: [%s]", tag);
    return;
  }

  if (!mg_conn_fopen(conn, path, "rb", &file)) {
    cry(conn, "Cannot open SSI #include: [%s]: fopen(%s): %s",
        tag, path, strerror(ERRNO));
  } else {
    fclose_on_exec(&file);
    if (mg_match_prefix(conn->ctx->config[SSI_EXTENSIONS],
                     strlen(conn->ctx->config[SSI_EXTENSIONS]), path) > 0) {
      send_ssi_file(conn, path, &file, include_level + 1);
    } else {
      send_file_data(conn, &file, 0, INT64_MAX);
    }
    mg_fclose(&file);
  }
}

#if !defined(NO_POPEN)
static void do_ssi_exec(struct mg_connection *conn, char *tag) {
  char cmd[MG_BUF_LEN];
  struct file file = STRUCT_FILE_INITIALIZER;

  if (sscanf(tag, " \"%[^\"]\"", cmd) != 1) {
    cry(conn, "Bad SSI #exec: [%s]", tag);
  } else if ((file.fp = popen(cmd, "r")) == NULL) {
    cry(conn, "Cannot SSI #exec: [%s]: %s", cmd, strerror(ERRNO));
  } else {
    send_file_data(conn, &file, 0, INT64_MAX);
    pclose(file.fp);
  }
}
#endif // !NO_POPEN

static void send_ssi_file(struct mg_connection *conn, const char *path,
                          struct file *filep, int include_level) {
  char buf[MG_BUF_LEN];
  int ch, offset, len, in_ssi_tag;

  if (include_level > 10) {
    cry(conn, "SSI #include level is too deep (%s)", path);
    return;
  }

  in_ssi_tag = len = offset = 0;
  while ((ch = mg_fgetc(filep, offset)) != EOF) {
    if (in_ssi_tag && ch == '>') {
      in_ssi_tag = 0;
      buf[len++] = (char) ch;
      buf[len] = '\0';
      assert(len <= (int) sizeof(buf));
      if (len < 6 || memcmp(buf, "<!--#", 5) != 0) {
        // Not an SSI tag, pass it
        (void) mg_write(conn, buf, (size_t) len);
      } else {
        if (!memcmp(buf + 5, "include", 7)) {
          do_ssi_include(conn, path, buf + 12, include_level);
#if !defined(NO_POPEN)
        } else if (!memcmp(buf + 5, "exec", 4)) {
          do_ssi_exec(conn, buf + 9);
#endif // !NO_POPEN
        } else {
          cry(conn, "%s: unknown SSI " "command: \"%s\"", path, buf);
        }
      }
      len = 0;
    } else if (in_ssi_tag) {
      if (len == 5 && memcmp(buf, "<!--#", 5) != 0) {
        // Not an SSI tag
        in_ssi_tag = 0;
      } else if (len == (int) sizeof(buf) - 2) {
        cry(conn, "%s: SSI tag is too large", path);
        len = 0;
      }
      buf[len++] = ch & 0xff;
    } else if (ch == '<') {
      in_ssi_tag = 1;
      if (len > 0) {
        mg_write(conn, buf, (size_t) len);
      }
      len = 0;
      buf[len++] = ch & 0xff;
    } else {
      buf[len++] = ch & 0xff;
      if (len == (int) sizeof(buf)) {
        mg_write(conn, buf, (size_t) len);
        len = 0;
      }
    }
  }

  // Send the rest of buffered data
  if (len > 0) {
    mg_write(conn, buf, (size_t) len);
  }
}

static void handle_ssi_file_request(struct mg_connection *conn,
                                    const char *path) {
  struct file file;

  if (!mg_conn_fopen(conn, path, "rb", &file)) {
    send_http_error(conn, 500, http_500_error, "fopen(%s): %s", path,
                    strerror(ERRNO));
  } else {
    conn->must_close = 1;
    fclose_on_exec(&file);
    mg_printf(conn, "HTTP/1.1 200 OK\r\n"
              "Content-Type: text/html\r\nConnection: %s\r\n\r\n",
              suggest_connection_header(conn));
    send_ssi_file(conn, path, &file, 0);
    mg_fclose(&file);
  }
}

static void send_options(struct mg_connection *conn) {
  conn->status_code = 200;

  mg_printf(conn, "%s", "HTTP/1.1 200 OK\r\n"
            "Allow: GET, POST, HEAD, CONNECT, PUT, DELETE, OPTIONS\r\n"
            "DAV: 1\r\n\r\n");
}

// Writes PROPFIND properties for a collection element
static void print_props(struct mg_connection *conn, const char* uri,
                        struct file *filep) {
  char mtime[64];
  gmt_time_string(mtime, sizeof(mtime), &filep->modification_time);
  conn->num_bytes_sent += mg_printf(conn,
      "<d:response>"
       "<d:href>%s</d:href>"
       "<d:propstat>"
        "<d:prop>"
         "<d:resourcetype>%s</d:resourcetype>"
         "<d:getcontentlength>%" INT64_FMT "</d:getcontentlength>"
         "<d:getlastmodified>%s</d:getlastmodified>"
        "</d:prop>"
        "<d:status>HTTP/1.1 200 OK</d:status>"
       "</d:propstat>"
      "</d:response>\n",
      uri,
      filep->is_directory ? "<d:collection/>" : "",
      filep->size,
      mtime);
}

static void print_dav_dir_entry(struct de *de, void *data) {
  char href[PATH_MAX];
  struct mg_connection *conn = (struct mg_connection *) data;
  mg_snprintf(conn, href, sizeof(href), "%s%s",
              conn->request_info.uri, de->file_name);
  print_props(conn, href, &de->file);
}

static void handle_propfind(struct mg_connection *conn, const char *path,
                            struct file *filep) {
  const char *depth = mg_get_header(conn, "Depth");

  conn->must_close = 1;
  conn->status_code = 207;
  mg_printf(conn, "HTTP/1.1 207 Multi-Status\r\n"
            "Connection: close\r\n"
            "Content-Type: text/xml; charset=utf-8\r\n\r\n");

  conn->num_bytes_sent += mg_printf(conn,
      "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
      "<d:multistatus xmlns:d='DAV:'>\n");

  // Print properties for the requested resource itself
  print_props(conn, conn->request_info.uri, filep);

  // If it is a directory, print directory entries too if Depth is not 0
  if (filep->is_directory &&
      !mg_strcasecmp(conn->ctx->config[ENABLE_DIRECTORY_LISTING], "yes") &&
      (depth == NULL || strcmp(depth, "0") != 0)) {
    scan_directory(conn, path, conn, &print_dav_dir_entry);
  }

  conn->num_bytes_sent += mg_printf(conn, "%s\n", "</d:multistatus>");
}

#if defined(USE_WEBSOCKET)
#include "mongoose_websocket.h"
#endif

static int set_throttle(const char *spec, uint32_t remote_ip, const char *uri) {
  int throttle = 0;
  struct vec vec, val;
  uint32_t net, mask;
  char mult;
  double v;

  while ((spec = mg_next_option(spec, &vec, &val)) != NULL) {
    mult = ',';
    if (sscanf(val.ptr, "%lf%c", &v, &mult) < 1 || v < 0 ||
        (mg_lowercase(&mult) != 'k' && mg_lowercase(&mult) != 'm' && mult != ',')) {
      continue;
    }
    v *= mg_lowercase(&mult) == 'k' ? 1024 : mg_lowercase(&mult) == 'm' ? 1048576 : 1;
    if (vec.len == 1 && vec.ptr[0] == '*') {
      throttle = (int) v;
    } else if (mg_parse_net(vec.ptr, &net, &mask) > 0) {
      if ((remote_ip & mask) == net) {
        throttle = (int) v;
      }
    } else if (mg_match_prefix(vec.ptr, vec.len, uri) > 0) {
      throttle = (int) v;
    }
  }

  return throttle;
}

static uint32_t get_remote_ip(const struct mg_connection *conn) {
  return ntohl(* (uint32_t *) &conn->client.rsa.sin.sin_addr);
}

#ifdef USE_LUA
#include "mongoose_lua.h"
#elif defined(USE_SQUIRREL)
#include "mongoose_squirrel.h"
#endif

int mg_upload(struct mg_connection *conn, const char *destination_dir) {
  const char *content_type_header, *boundary_start;
  char buf[8192], path[PATH_MAX], fname[1024], boundary[100], *s;
  FILE *fp;
  int bl, n, i, j, headers_len, boundary_len, len = 0, num_uploaded_files = 0;

  // Request looks like this:
  //
  // POST /upload HTTP/1.1
  // Host: 127.0.0.1:8080
  // Content-Length: 244894
  // Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryRVr
  //
  // ------WebKitFormBoundaryRVr
  // Content-Disposition: form-data; name="file"; filename="accum.png"
  // Content-Type: image/png
  //
  //  <89>PNG
  //  <PNG DATA>
  // ------WebKitFormBoundaryRVr

  // Extract boundary string from the Content-Type header
  if ((content_type_header = mg_get_header(conn, "Content-Type")) == NULL ||
      (boundary_start = strstr(content_type_header, "boundary=")) == NULL ||
      (sscanf(boundary_start, "boundary=\"%99[^\"]\"", boundary) == 0 &&
       sscanf(boundary_start, "boundary=%99s", boundary) == 0) ||
      boundary[0] == '\0') {
    return num_uploaded_files;
  }

  boundary_len = strlen(boundary);
  bl = boundary_len + 4;  // \r\n--<boundary>
  for (;;) {
    // Pull in headers
    assert(len >= 0 && len <= (int) sizeof(buf));
    while ((n = mg_read(conn, buf + len, sizeof(buf) - len)) > 0) {
      len += n;
    }
    if ((headers_len = mg_get_request_len(buf, len)) <= 0) {
      break;
    }

    // Fetch file name.
    fname[0] = '\0';
    for (i = j = 0; i < headers_len; i++) {
      if (buf[i] == '\r' && buf[i + 1] == '\n') {
        buf[i] = buf[i + 1] = '\0';
        // TODO(lsm): don't expect filename to be the 3rd field,
        // parse the header properly instead.
        sscanf(&buf[j], "Content-Disposition: %*s %*s filename=\"%1023[^\"]",
               fname);
        j = i + 2;
      }
    }

    // Give up if the headers are not what we expect
    if (fname[0] == '\0') {
      break;
    }

    // Move data to the beginning of the buffer
    assert(len >= headers_len);
    memmove(buf, &buf[headers_len], len - headers_len);
    len -= headers_len;

    // We open the file with exclusive lock held. This guarantee us
    // there is no other thread can save into the same file simultaneously.
    fp = NULL;
    // Construct destination file name. Do not allow paths to have slashes.
    if ((s = strrchr(fname, '/')) == NULL) {
      s = fname;
    }
    // Open file in binary mode with exclusive lock set
    snprintf(path, sizeof(path), "%s/%s", destination_dir, s);
    if ((fp = fopen(path, "wbx")) == NULL) {
      break;
    }

    // Read POST data, write into file until boundary is found.
    n = 0;
    do {
      len += n;
      for (i = 0; i < len - bl; i++) {
        if (!memcmp(&buf[i], "\r\n--", 4) &&
            !memcmp(&buf[i + 4], boundary, boundary_len)) {
          // Found boundary, that's the end of file data.
          (void) fwrite(buf, 1, i, fp);
          num_uploaded_files++;
          conn->request_info.ev_data = (void *) path;
          call_user(conn, MG_UPLOAD);
          memmove(buf, &buf[i + bl], len - (i + bl));
          len -= i + bl;
          break;
        }
      }
      if (len > bl) {
        fwrite(buf, 1, len - bl, fp);
        memmove(buf, &buf[len - bl], len - bl);
        len = bl;
      }
    } while ((n = mg_read(conn, buf + len, sizeof(buf) - len)) > 0);
    fclose(fp);
  }

  return num_uploaded_files;
}

static int is_put_or_delete_request(const struct mg_connection *conn) {
  const char *s = conn->request_info.request_method;
  return s != NULL && (!strcmp(s, "PUT") || !strcmp(s, "DELETE"));
}

// This is the heart of the Mongoose's logic.
// This function is called when the request is read, parsed and validated,
// and Mongoose must decide what action to take: serve a file, or
// a directory, or call embedded function, etcetera.
static void handle_request(struct mg_connection *conn) {
  struct mg_request_info *ri = &conn->request_info;
  char path[PATH_MAX];
  int uri_len;
  struct file file = STRUCT_FILE_INITIALIZER;

  if ((conn->request_info.query_string = strchr(ri->uri, '?')) != NULL) {
    * ((char *) conn->request_info.query_string++) = '\0';
  }
  uri_len = (int) strlen(ri->uri);
  mg_url_decode(ri->uri, uri_len, (char *) ri->uri, uri_len + 1, 0);
  mg_remove_double_dots_and_double_slashes((char *) ri->uri);
  convert_uri_to_file_name(conn, path, sizeof(path), &file);
  conn->throttle = set_throttle(conn->ctx->config[THROTTLE],
                                get_remote_ip(conn), ri->uri);

  DEBUG_TRACE(("%s", ri->uri));
  if (!is_put_or_delete_request(conn) && !check_authorization(conn, path)) {
    send_authorization_request(conn);
#if defined(USE_WEBSOCKET)
  } else if (is_websocket_request(conn)) {
    handle_websocket_request(conn);
#endif
  } else if (call_user(conn, MG_NEW_REQUEST) != NULL) {
    // Do nothing, callback has served the request
  } else if (!strcmp(ri->request_method, "OPTIONS")) {
    send_options(conn);
  } else if (conn->ctx->config[DOCUMENT_ROOT] == NULL) {
    send_http_error(conn, 404, "Not Found", "Not Found");
  } else if (is_put_or_delete_request(conn) &&
             (conn->ctx->config[PUT_DELETE_PASSWORDS_FILE] == NULL ||
              is_authorized_for_put(conn) != 1)) {
    send_authorization_request(conn);
  } else if (!strcmp(ri->request_method, "PUT")) {
    put_file(conn, path);
  } else if (!strcmp(ri->request_method, "DELETE")) {
    if (mg_remove(path) == 0) {
      send_http_error(conn, 200, "OK", "%s", "");
    } else {
      send_http_error(conn, 500, http_500_error, "remove(%s): %s", path,
                      strerror(ERRNO));
    }
  } else if ((file.membuf == NULL && file.modification_time == (time_t) 0) ||
             must_hide_file(conn, path)) {
    send_http_error(conn, 404, "Not Found", "%s", "File not found");
  } else if (file.is_directory && ri->uri[uri_len - 1] != '/') {
    mg_printf(conn, "HTTP/1.1 301 Moved Permanently\r\n"
              "Location: %s/\r\n\r\n", ri->uri);
  } else if (!strcmp(ri->request_method, "PROPFIND")) {
    handle_propfind(conn, path, &file);
  } else if (file.is_directory &&
             !substitute_index_file(conn, path, sizeof(path), &file)) {
    if (!mg_strcasecmp(conn->ctx->config[ENABLE_DIRECTORY_LISTING], "yes")) {
      handle_directory_request(conn, path);
    } else {
      send_http_error(conn, 403, "Directory Listing Denied",
          "Directory listing denied");
    }
#ifdef USE_LUA
  } else if (match_prefix("**.lp$", 6, path) > 0) {
    handle_lsp_request(conn, path, &file);
#elif defined(USE_SQUIRREL)
  } else if (match_prefix("**.sqp$", 7, path) > 0) {
    handle_sqsp_request(conn, path, &file);
#endif
#if !defined(NO_CGI)
  } else if (mg_match_prefix(conn->ctx->config[CGI_EXTENSIONS],
                          strlen(conn->ctx->config[CGI_EXTENSIONS]),
                          path) > 0) {
    if (strcmp(ri->request_method, "POST") &&
        strcmp(ri->request_method, "HEAD") &&
        strcmp(ri->request_method, "GET")) {
      send_http_error(conn, 501, "Not Implemented",
                      "Method %s is not implemented", ri->request_method);
    } else {
      handle_cgi_request(conn, path);
    }
#endif // !NO_CGI
  } else if (mg_match_prefix(conn->ctx->config[SSI_EXTENSIONS],
                          strlen(conn->ctx->config[SSI_EXTENSIONS]),
                          path) > 0) {
    handle_ssi_file_request(conn, path);
  } else if (is_not_modified(conn, &file)) {
    send_http_error(conn, 304, "Not Modified", "%s", "");
  } else {
    handle_file_request(conn, path, &file);
  }
}

static void close_all_listening_sockets(struct mg_context *ctx) {
  struct socket *sp, *tmp;
  for (sp = ctx->listening_sockets; sp != NULL; sp = tmp) {
    tmp = sp->next;
    (void) closesocket(sp->sock);
    free(sp);
  }
}

// Valid listening port specification is: [ip_address:]port[s]
// Examples: 80, 443s, 127.0.0.1:3128, 1.2.3.4:8080s
// TODO(lsm): add parsing of the IPv6 address
static int parse_port_string(const struct vec *vec, struct socket *so) {
  int a, b, c, d, port, len;

  // MacOS needs that. If we do not zero it, subsequent bind() will fail.
  // Also, all-zeroes in the socket address means binding to all addresses
  // for both IPv4 and IPv6 (INADDR_ANY and IN6ADDR_ANY_INIT).
  memset(so, 0, sizeof(*so));

  if (sscanf(vec->ptr, "%d.%d.%d.%d:%d%n", &a, &b, &c, &d, &port, &len) == 5) {
    // Bind to a specific IPv4 address
    so->lsa.sin.sin_addr.s_addr = htonl((a << 24) | (b << 16) | (c << 8) | d);
  } else if (sscanf(vec->ptr, "%d%n", &port, &len) != 1 ||
             len <= 0 ||
             len > (int) vec->len ||
             (vec->ptr[len] && vec->ptr[len] != 's' && vec->ptr[len] != ',')) {
    return 0;
  }

  so->is_ssl = vec->ptr[len] == 's';
#if defined(USE_IPV6)
  so->lsa.sin6.sin6_family = AF_INET6;
  so->lsa.sin6.sin6_port = htons((uint16_t) port);
#else
  so->lsa.sin.sin_family = AF_INET;
  so->lsa.sin.sin_port = htons((uint16_t) port);
#endif

  return 1;
}

static int set_ports_option(struct mg_context *ctx) {
  const char *list = ctx->config[LISTENING_PORTS];
  int on = 1, success = 1;
  SOCKET sock;
  struct vec vec;
  struct socket so, *listener;

  while (success && (list = mg_next_option(list, &vec, NULL)) != NULL) {
    if (!parse_port_string(&vec, &so)) {
      cry(fc(ctx), "%s: %.*s: invalid port spec. Expecting list of: %s",
          __func__, (int) vec.len, vec.ptr, "[IP_ADDRESS:]PORT[s|p]");
      success = 0;
    } else if (so.is_ssl &&
               (ctx->ssl_ctx == NULL || ctx->config[SSL_CERTIFICATE] == NULL)) {
      cry(fc(ctx), "Cannot add SSL socket, is -ssl_certificate option set?");
      success = 0;
    } else if ((sock = socket(so.lsa.sa.sa_family, SOCK_STREAM, 6)) ==
               INVALID_SOCKET ||
               // On Windows, SO_REUSEADDR is recommended only for
               // broadcast UDP sockets
               setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *) &on,
                          sizeof(on)) != 0 ||
               // Set TCP keep-alive. This is needed because if HTTP-level
               // keep-alive is enabled, and client resets the connection,
               // server won't get TCP FIN or RST and will keep the connection
               // open forever. With TCP keep-alive, next keep-alive
               // handshake will figure out that the client is down and
               // will close the server end.
               // Thanks to Igor Klopov who suggested the patch.
               setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char *) &on,
                          sizeof(on)) != 0 ||
               bind(sock, &so.lsa.sa, sizeof(so.lsa)) != 0 ||
               listen(sock, SOMAXCONN) != 0) {
      closesocket(sock);
      cry(fc(ctx), "%s: cannot bind to %.*s: %s", __func__,
          (int) vec.len, vec.ptr, strerror(ERRNO));
      success = 0;
    } else if ((listener = (struct socket *)
                calloc(1, sizeof(*listener))) == NULL) {
      // NOTE(lsm): order is important: call cry before closesocket(),
      // cause closesocket() alters the errno.
      cry(fc(ctx), "%s: %s", __func__, strerror(ERRNO));
      closesocket(sock);
      success = 0;
    } else {
      *listener = so;
      listener->sock = sock;
      mg_set_close_on_exec(listener->sock);
      listener->next = ctx->listening_sockets;
      ctx->listening_sockets = listener;
    }
  }

  if (!success) {
    close_all_listening_sockets(ctx);
  }

  return success;
}

static void log_header(const struct mg_connection *conn, const char *header,
                       FILE *fp) {
  const char *header_value;

  if ((header_value = mg_get_header(conn, header)) == NULL) {
    (void) fprintf(fp, "%s", " -");
  } else {
    (void) fprintf(fp, " \"%s\"", header_value);
  }
}

static void log_access(const struct mg_connection *conn) {
  const struct mg_request_info *ri;
  FILE *fp;
  char date[64], src_addr[20];

  fp = conn->ctx->config[ACCESS_LOG_FILE] == NULL ?  NULL :
    fopen(conn->ctx->config[ACCESS_LOG_FILE], "a+");

  if (fp == NULL)
    return;

  strftime(date, sizeof(date), "%d/%b/%Y:%H:%M:%S %z",
           localtime(&conn->birth_time));

  ri = &conn->request_info;
  flockfile(fp);

  mg_sockaddr_to_string(src_addr, sizeof(src_addr), &conn->client.rsa);
  fprintf(fp, "%s - %s [%s] \"%s %s HTTP/%s\" %d %" INT64_FMT,
          src_addr, ri->remote_user == NULL ? "-" : ri->remote_user, date,
          ri->request_method ? ri->request_method : "-",
          ri->uri ? ri->uri : "-", ri->http_version,
          conn->status_code, conn->num_bytes_sent);
  log_header(conn, "Referer", fp);
  log_header(conn, "User-Agent", fp);
  fputc('\n', fp);
  fflush(fp);

  funlockfile(fp);
  fclose(fp);
}

// Verify given socket address against the ACL.
// Return -1 if ACL is malformed, 0 if address is disallowed, 1 if allowed.
static int check_acl(struct mg_context *ctx, uint32_t remote_ip) {
  int allowed, flag;
  uint32_t net, mask;
  struct vec vec;
  const char *list = ctx->config[ACCESS_CONTROL_LIST];

  // If any ACL is set, deny by default
  allowed = list == NULL ? '+' : '-';

  while ((list = mg_next_option(list, &vec, NULL)) != NULL) {
    flag = vec.ptr[0];
    if ((flag != '+' && flag != '-') ||
        mg_parse_net(&vec.ptr[1], &net, &mask) == 0) {
      cry(fc(ctx), "%s: subnet must be [+|-]x.x.x.x[/x]", __func__);
      return -1;
    }

    if (net == (remote_ip & mask)) {
      allowed = flag;
    }
  }

  return allowed == '+';
}

static void add_to_set(SOCKET fd, fd_set *set, int *max_fd) {
  FD_SET(fd, set);
  if (fd > (SOCKET) *max_fd) {
    *max_fd = (int) fd;
  }
}

#if !defined(_WIN32)
static int set_uid_option(struct mg_context *ctx) {
  struct passwd *pw;
  const char *uid = ctx->config[RUN_AS_USER];
  int success = 0;

  if (uid == NULL) {
    success = 1;
  } else {
    if ((pw = getpwnam(uid)) == NULL) {
      cry(fc(ctx), "%s: unknown user [%s]", __func__, uid);
    } else if (setgid(pw->pw_gid) == -1) {
      cry(fc(ctx), "%s: setgid(%s): %s", __func__, uid, strerror(errno));
    } else if (setuid(pw->pw_uid) == -1) {
      cry(fc(ctx), "%s: setuid(%s): %s", __func__, uid, strerror(errno));
    } else {
      success = 1;
    }
  }

  return success;
}
#endif // !_WIN32

#if !defined(NO_SSL)
static mg_thread_mutex_t *ssl_mutexes;

// Return OpenSSL error message
static const char *ssl_error(void) {
  unsigned long err;
  err = ERR_get_error();
  return err == 0 ? "" : ERR_error_string(err, NULL);
}

static void ssl_locking_callback(int mode, int mutex_num, const char *file,
                                 int line) {
  line = 0;    // Unused
  file = NULL; // Unused

  if (mode & CRYPTO_LOCK) {
    (void) mg_thread_mutex_lock(&ssl_mutexes[mutex_num]);
  } else {
    (void) mg_thread_mutex_unlock(&ssl_mutexes[mutex_num]);
  }
}

static unsigned long ssl_id_callback(void) {
  return (unsigned long) mg_thread_self();
}

#if !defined(NO_SSL_DL)
static int load_dll(struct mg_context *ctx, const char *dll_name,
                    struct ssl_func *sw) {
  union {void *p; void (*fp)(void);} u;
  void  *dll_handle;
  struct ssl_func *fp;

  if ((dll_handle = dlopen(dll_name, RTLD_LAZY)) == NULL) {
    cry(fc(ctx), "%s: cannot load %s", __func__, dll_name);
    return 0;
  }

  for (fp = sw; fp->name != NULL; fp++) {
#ifdef _WIN32
    // GetProcAddress() returns pointer to function
    u.fp = (void (*)(void)) dlsym(dll_handle, fp->name);
#else
    // dlsym() on UNIX returns void *. ISO C forbids casts of data pointers to
    // function pointers. We need to use a union to make a cast.
    u.p = dlsym(dll_handle, fp->name);
#endif // _WIN32
    if (u.fp == NULL) {
      cry(fc(ctx), "%s: %s: cannot find %s", __func__, dll_name, fp->name);
      return 0;
    } else {
      fp->ptr = u.fp;
    }
  }

  return 1;
}
#endif // NO_SSL_DL

// Dynamically load SSL library. Set up ctx->ssl_ctx pointer.
static int set_ssl_option(struct mg_context *ctx) {
  struct mg_connection *conn;
  int i, size;
  const char *pem;

  // If PEM file is not specified, skip SSL initialization.
  if ((pem = ctx->config[SSL_CERTIFICATE]) == NULL) {
    return 1;
  }

#if !defined(NO_SSL_DL)
  if (!load_dll(ctx, SSL_LIB, ssl_sw) ||
      !load_dll(ctx, CRYPTO_LIB, crypto_sw)) {
    return 0;
  }
#endif // NO_SSL_DL

  // Initialize SSL crap
  SSL_library_init();
  SSL_load_error_strings();

  if ((ctx->client_ssl_ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
    cry(fc(ctx), "SSL_CTX_new (client) error: %s", ssl_error());
  }

  if ((ctx->ssl_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
    cry(fc(ctx), "SSL_CTX_new (server) error: %s", ssl_error());
    return 0;
  }

  // If user callback returned non-NULL, that means that user callback has
  // set up certificate itself. In this case, skip sertificate setting.
  conn = fc(ctx);
  conn->request_info.ev_data = ctx->ssl_ctx;
  if (call_user(conn, MG_INIT_SSL) == NULL &&
      (SSL_CTX_use_certificate_file(ctx->ssl_ctx, pem, SSL_FILETYPE_PEM) == 0 ||
       SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, pem, SSL_FILETYPE_PEM) == 0)) {
    cry(fc(ctx), "%s: cannot open %s: %s", __func__, pem, ssl_error());
    return 0;
  }

  if (pem != NULL) {
    (void) SSL_CTX_use_certificate_chain_file(ctx->ssl_ctx, pem);
  }

  // Initialize locking callbacks, needed for thread safety.
  // http://www.openssl.org/support/faq.html#PROG1
  size = sizeof(mg_thread_mutex_t) * CRYPTO_num_locks();
  if ((ssl_mutexes = (mg_thread_mutex_t *) malloc((size_t)size)) == NULL) {
    cry(fc(ctx), "%s: cannot allocate mutexes: %s", __func__, ssl_error());
    return 0;
  }

  for (i = 0; i < CRYPTO_num_locks(); i++) {
    mg_thread_mutex_init(&ssl_mutexes[i], NULL);
  }

  CRYPTO_set_locking_callback(&ssl_locking_callback);
  CRYPTO_set_id_callback(&ssl_id_callback);

  return 1;
}

static void uninitialize_ssl(struct mg_context *ctx) {
  int i;
  if (ctx->ssl_ctx != NULL) {
    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++) {
      mg_thread_mutex_destroy(&ssl_mutexes[i]);
    }
    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);
  }
}
#endif // !NO_SSL

static int set_gpass_option(struct mg_context *ctx) {
  struct file file;
  const char *path = ctx->config[GLOBAL_PASSWORDS_FILE];
  if (path != NULL && !mg_conn_stat(fc(ctx), path, &file)) {
    cry(fc(ctx), "Cannot open %s: %s", path, strerror(ERRNO));
    return 0;
  }
  return 1;
}

static int set_acl_option(struct mg_context *ctx) {
  return check_acl(ctx, (uint32_t) 0x7f000001UL) != -1;
}

static void reset_per_request_attributes(struct mg_connection *conn) {
  conn->path_info = conn->request_info.ev_data = NULL;
  conn->num_bytes_sent = conn->consumed_content = 0;
  conn->status_code = -1;
  conn->must_close = conn->request_len = conn->throttle = 0;
}

static void close_socket_gracefully(struct mg_connection *conn) {
#if defined(_WIN32)
  char buf[MG_BUF_LEN];
  int n;
#endif
  struct linger linger;
  int sock = conn->client.sock;

  // Set linger option to avoid socket hanging out after close. This prevent
  // ephemeral port exhaust problem under high QPS.
  linger.l_onoff = 1;
  linger.l_linger = 1;
  setsockopt(sock, SOL_SOCKET, SO_LINGER, (char *) &linger, sizeof(linger));

  // Send FIN to the client
  (void) shutdown(sock, SHUT_WR);
  mg_set_non_blocking_mode(sock);

#if defined(_WIN32)
  // Read and discard pending incoming data. If we do not do that and close the
  // socket, the data in the send buffer may be discarded. This
  // behaviour is seen on Windows, when client keeps sending data
  // when server decides to close the connection; then when client
  // does recv() it gets no data back.
  do {
    n = pull(NULL, conn, buf, sizeof(buf));
  } while (n > 0);
#endif

  // Now we know that our FIN is ACK-ed, safe to close
  (void) closesocket(sock);
}

static void close_connection(struct mg_connection *conn) {
  conn->must_close = 1;

  if (conn->ssl) {
    SSL_free(conn->ssl);
    conn->ssl = NULL;
  }

  if (conn->client.sock != INVALID_SOCKET) {
    close_socket_gracefully(conn);
  }
}

void mg_close_connection(struct mg_connection *conn) {
  close_connection(conn);
  free(conn);
}

struct mg_connection *mg_connect(struct mg_context *ctx,
                                 const char *host, int port, int use_ssl) {
  struct mg_connection *newconn = NULL;
  struct sockaddr_in sin;
  struct hostent *he;
  int sock;

  if (use_ssl && (ctx == NULL || ctx->client_ssl_ctx == NULL)) {
    cry(fc(ctx), "%s: SSL is not initialized", __func__);
  } else if ((he = gethostbyname(host)) == NULL) {
    cry(fc(ctx), "%s: gethostbyname(%s): %s", __func__, host, strerror(ERRNO));
  } else if ((sock = socket(PF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
    cry(fc(ctx), "%s: socket: %s", __func__, strerror(ERRNO));
  } else {
    sin.sin_family = AF_INET;
    sin.sin_port = htons((uint16_t) port);
    sin.sin_addr = * (struct in_addr *) he->h_addr_list[0];
    if (connect(sock, (struct sockaddr *) &sin, sizeof(sin)) != 0) {
      cry(fc(ctx), "%s: connect(%s:%d): %s", __func__, host, port,
          strerror(ERRNO));
      closesocket(sock);
    } else if ((newconn = (struct mg_connection *)
                calloc(1, sizeof(*newconn))) == NULL) {
      cry(fc(ctx), "%s: calloc: %s", __func__, strerror(ERRNO));
      closesocket(sock);
    } else {
      newconn->ctx = ctx;
      newconn->client.sock = sock;
      newconn->client.rsa.sin = sin;
      newconn->client.is_ssl = use_ssl;
      if (use_ssl) {
        sslize(newconn, ctx->client_ssl_ctx, SSL_connect);
      }
    }
  }

  return newconn;
}

FILE *mg_fetch(struct mg_context *ctx, const char *url, const char *path,
               char *buf, size_t buf_len, struct mg_request_info *ri) {
  struct mg_connection *newconn;
  int n, req_length, data_length, port;
  char host[1025], proto[10], buf2[MG_BUF_LEN];
  FILE *fp = NULL;

  if (sscanf(url, "%9[htps]://%1024[^:]:%d/%n", proto, host, &port, &n) == 3) {
  } else if (sscanf(url, "%9[htps]://%1024[^/]/%n", proto, host, &n) == 2) {
    port = mg_strcasecmp(proto, "https") == 0 ? 443 : 80;
  } else {
    cry(fc(ctx), "%s: invalid URL: [%s]", __func__, url);
    return NULL;
  }

  if ((newconn = mg_connect(ctx, host, port,
                            !strcmp(proto, "https"))) == NULL) {
    cry(fc(ctx), "%s: mg_connect(%s): %s", __func__, url, strerror(ERRNO));
  } else {
    mg_printf(newconn, "GET /%s HTTP/1.0\r\nHost: %s\r\n\r\n", url + n, host);
    data_length = 0;
    req_length = read_request(NULL, newconn, buf, buf_len, &data_length);
    if (req_length <= 0) {
      cry(fc(ctx), "%s(%s): invalid HTTP reply", __func__, url);
    } else if (parse_http_response(buf, req_length, ri) <= 0) {
      cry(fc(ctx), "%s(%s): cannot parse HTTP headers", __func__, url);
    } else if ((fp = fopen(path, "w+b")) == NULL) {
      cry(fc(ctx), "%s: fopen(%s): %s", __func__, path, strerror(ERRNO));
    } else {
      // Write chunk of data that may be in the user's buffer
      data_length -= req_length;
      if (data_length > 0 &&
        fwrite(buf + req_length, 1, data_length, fp) != (size_t) data_length) {
        cry(fc(ctx), "%s: fwrite(%s): %s", __func__, path, strerror(ERRNO));
        fclose(fp);
        fp = NULL;
      }
      // Read the rest of the response and write it to the file. Do not use
      // mg_read() cause we didn't set newconn->content_len properly.
      while (fp && (data_length = pull(0, newconn, buf2, sizeof(buf2))) > 0) {
        if (fwrite(buf2, 1, data_length, fp) != (size_t) data_length) {
          cry(fc(ctx), "%s: fwrite(%s): %s", __func__, path, strerror(ERRNO));
          fclose(fp);
          fp = NULL;
          break;
        }
      }
    }
    mg_close_connection(newconn);
  }

  return fp;
}

static int is_valid_uri(const char *uri) {
  // Conform to http://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html#sec5.1.2
  // URI can be an asterisk (*) or should start with slash.
  return uri[0] == '/' || (uri[0] == '*' && uri[1] == '\0');
}

static void process_new_connection(struct mg_connection *conn) {
  struct mg_request_info *ri = &conn->request_info;
  int keep_alive_enabled, keep_alive, discard_len;
  const char *cl;

  keep_alive_enabled = !strcmp(conn->ctx->config[ENABLE_KEEP_ALIVE], "yes");
  keep_alive = 0;

  // Important: on new connection, reset the receiving buffer. Credit goes
  // to crule42.
  conn->data_len = 0;
  do {
    reset_per_request_attributes(conn);
    conn->request_len = read_request(NULL, conn, conn->buf, conn->buf_size,
                                     &conn->data_len);
    assert(conn->request_len < 0 || conn->data_len >= conn->request_len);
    if (conn->request_len == 0 && conn->data_len == conn->buf_size) {
      send_http_error(conn, 413, "Request Too Large", "%s", "");
      return;
    } if (conn->request_len <= 0) {
      return;  // Remote end closed the connection
    }
    if (parse_http_request(conn->buf, conn->buf_size, ri) <= 0 ||
        !is_valid_uri(ri->uri)) {
      // Do not put garbage in the access log, just send it back to the client
      send_http_error(conn, 400, "Bad Request",
          "Cannot parse HTTP request: [%.*s]", conn->data_len, conn->buf);
      conn->must_close = 1;
    } else if (strcmp(ri->http_version, "1.0") &&
               strcmp(ri->http_version, "1.1")) {
      // Request seems valid, but HTTP version is strange
      send_http_error(conn, 505, "HTTP version not supported", "%s", "");
      log_access(conn);
    } else {
      // Request is valid, handle it
      if ((cl = get_header(ri, "Content-Length")) != NULL) {
        conn->content_len = strtoll(cl, NULL, 10);
      } else if (!mg_strcasecmp(ri->request_method, "POST") ||
                 !mg_strcasecmp(ri->request_method, "PUT")) {
        conn->content_len = -1;
      } else {
        conn->content_len = 0;
      }
      conn->birth_time = time(NULL);
      handle_request(conn);
      conn->request_info.ev_data = (void *) conn->status_code;
      call_user(conn, MG_REQUEST_COMPLETE);
      log_access(conn);
    }
    if (ri->remote_user != NULL) {
      free((void *) ri->remote_user);
    }

    // NOTE(lsm): order is important here. should_keep_alive() call
    // is using parsed request, which will be invalid after memmove's below.
    // Therefore, memorize should_keep_alive() result now for later use
    // in loop exit condition.
    keep_alive = should_keep_alive(conn);

    // Discard all buffered data for this request
    discard_len = conn->content_len >= 0 &&
      conn->request_len + conn->content_len < (int64_t) conn->data_len ?
      (int) (conn->request_len + conn->content_len) : conn->data_len;
    memmove(conn->buf, conn->buf + discard_len, conn->data_len - discard_len);
    conn->data_len -= discard_len;
    assert(conn->data_len >= 0);
    assert(conn->data_len <= conn->buf_size);

  } while (conn->ctx->stop_flag == 0 &&
           keep_alive_enabled &&
           conn->content_len >= 0 &&
           keep_alive);
}

// Worker threads take accepted socket from the queue
static int consume_socket(struct mg_context *ctx, struct socket *sp) {
  (void) mg_thread_mutex_lock(&ctx->mutex);
  DEBUG_TRACE(("going idle"));

  // If the queue is empty, wait. We're idle at this point.
  while (ctx->sq_head == ctx->sq_tail && ctx->stop_flag == 0) {
    mg_thread_cond_wait(&ctx->sq_full, &ctx->mutex);
  }

  // If we're stopping, sq_head may be equal to sq_tail.
  if (ctx->sq_head > ctx->sq_tail) {
    // Copy socket from the queue and increment tail
    *sp = ctx->queue[ctx->sq_tail % ARRAY_SIZE(ctx->queue)];
    ctx->sq_tail++;
    DEBUG_TRACE(("grabbed socket %d, going busy", sp->sock));

    // Wrap pointers if needed
    while (ctx->sq_tail > (int) ARRAY_SIZE(ctx->queue)) {
      ctx->sq_tail -= ARRAY_SIZE(ctx->queue);
      ctx->sq_head -= ARRAY_SIZE(ctx->queue);
    }
  }

  (void) mg_thread_cond_signal(&ctx->sq_empty);
  (void) mg_thread_mutex_unlock(&ctx->mutex);

  return !ctx->stop_flag;
}

static void worker_thread(struct mg_context *ctx) {
  struct mg_connection *conn;

  conn = (struct mg_connection *) calloc(1, sizeof(*conn) + MAX_REQUEST_SIZE);
  if (conn == NULL) {
    cry(fc(ctx), "%s", "Cannot create new connection struct, OOM");
  } else {
    conn->buf_size = MAX_REQUEST_SIZE;
    conn->buf = (char *) (conn + 1);

    // Call consume_socket() even when ctx->stop_flag > 0, to let it signal
    // sq_empty condvar to wake up the master waiting in produce_socket()
    while (consume_socket(ctx, &conn->client)) {
      conn->birth_time = time(NULL);
      conn->ctx = ctx;

      // Fill in IP, port info early so even if SSL setup below fails,
      // error handler would have the corresponding info.
      // Thanks to Johannes Winkelmann for the patch.
      // TODO(lsm): Fix IPv6 case
      conn->request_info.remote_port = ntohs(conn->client.rsa.sin.sin_port);
      memcpy(&conn->request_info.remote_ip,
             &conn->client.rsa.sin.sin_addr.s_addr, 4);
      conn->request_info.remote_ip = ntohl(conn->request_info.remote_ip);
      conn->request_info.is_ssl = conn->client.is_ssl;

      if (!conn->client.is_ssl ||
          (conn->client.is_ssl &&
           sslize(conn, conn->ctx->ssl_ctx, SSL_accept))) {
        process_new_connection(conn);
      }

      close_connection(conn);
    }
    free(conn);
  }

  // Signal master that we're done with connection and exiting
  (void) mg_thread_mutex_lock(&ctx->mutex);
  ctx->num_threads--;
  (void) mg_thread_cond_signal(&ctx->cond);
  assert(ctx->num_threads >= 0);
  (void) mg_thread_mutex_unlock(&ctx->mutex);

  DEBUG_TRACE(("exiting"));
}

// Master thread adds accepted socket to a queue
static void produce_socket(struct mg_context *ctx, const struct socket *sp) {
  (void) mg_thread_mutex_lock(&ctx->mutex);

  // If the queue is full, wait
  while (ctx->stop_flag == 0 &&
         ctx->sq_head - ctx->sq_tail >= (int) ARRAY_SIZE(ctx->queue)) {
    (void) mg_thread_cond_wait(&ctx->sq_empty, &ctx->mutex);
  }

  if (ctx->sq_head - ctx->sq_tail < (int) ARRAY_SIZE(ctx->queue)) {
    // Copy socket to the queue and increment head
    ctx->queue[ctx->sq_head % ARRAY_SIZE(ctx->queue)] = *sp;
    ctx->sq_head++;
    DEBUG_TRACE(("queued socket %d", sp->sock));
  }

  (void) mg_thread_cond_signal(&ctx->sq_full);
  (void) mg_thread_mutex_unlock(&ctx->mutex);
}

static void accept_new_connection(const struct socket *listener,
                                  struct mg_context *ctx) {
  struct socket accepted;
  char src_addr[20];
  socklen_t len;
  int allowed;

  len = sizeof(accepted.rsa);
  accepted.lsa = listener->lsa;
  accepted.sock = accept(listener->sock, &accepted.rsa.sa, &len);
  if (accepted.sock != INVALID_SOCKET) {
    allowed = check_acl(ctx, ntohl(* (uint32_t *) &accepted.rsa.sin.sin_addr));
    if (allowed) {
      // Put accepted socket structure into the queue
      DEBUG_TRACE(("accepted socket %d", accepted.sock));
      accepted.is_ssl = listener->is_ssl;
      produce_socket(ctx, &accepted);
    } else {
      mg_sockaddr_to_string(src_addr, sizeof(src_addr), &accepted.rsa);
      cry(fc(ctx), "%s: %s is not allowed to connect", __func__, src_addr);
      (void) closesocket(accepted.sock);
    }
  }
}

static void master_thread(struct mg_context *ctx) {
  fd_set read_set;
  struct timeval tv;
  struct socket *sp;
  int max_fd;

  // Increase priority of the master thread
#if defined(_WIN32)
  SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
#endif

#if defined(ISSUE_317)
  struct sched_param sched_param;
  sched_param.sched_priority = sched_get_priority_max(SCHED_RR);
  pthread_setschedparam(mg_thread_self(), SCHED_RR, &sched_param);
#endif

  while (ctx->stop_flag == 0) {
    FD_ZERO(&read_set);
    max_fd = -1;

    // Add listening sockets to the read set
    for (sp = ctx->listening_sockets; sp != NULL; sp = sp->next) {
      add_to_set(sp->sock, &read_set, &max_fd);
    }

    tv.tv_sec = 0;
    tv.tv_usec = 200 * 1000;

    if (select(max_fd + 1, &read_set, NULL, NULL, &tv) < 0) {
#ifdef _WIN32
      // On windows, if read_set and write_set are empty,
      // select() returns "Invalid parameter" error
      // (at least on my Windows XP Pro). So in this case, we sleep here.
      mg_sleep(1000);
#endif // _WIN32
    } else {
      for (sp = ctx->listening_sockets; sp != NULL; sp = sp->next) {
        if (ctx->stop_flag == 0 && FD_ISSET(sp->sock, &read_set)) {
          accept_new_connection(sp, ctx);
        }
      }
    }
  }
  DEBUG_TRACE(("stopping workers"));

  // Stop signal received: somebody called mg_stop. Quit.
  close_all_listening_sockets(ctx);

  // Wakeup workers that are waiting for connections to handle.
  mg_thread_cond_broadcast(&ctx->sq_full);

  // Wait until all threads finish
  (void) mg_thread_mutex_lock(&ctx->mutex);
  while (ctx->num_threads > 0) {
    (void) mg_thread_cond_wait(&ctx->cond, &ctx->mutex);
  }
  (void) mg_thread_mutex_unlock(&ctx->mutex);

  // All threads exited, no sync is needed. Destroy mutex and condvars
  (void) mg_thread_mutex_destroy(&ctx->mutex);
  (void) mg_thread_cond_destroy(&ctx->cond);
  (void) mg_thread_cond_destroy(&ctx->sq_empty);
  (void) mg_thread_cond_destroy(&ctx->sq_full);

#if !defined(NO_SSL)
  uninitialize_ssl(ctx);
#endif
  DEBUG_TRACE(("exiting"));

  // Signal mg_stop() that we're done.
  // WARNING: This must be the very last thing this
  // thread does, as ctx becomes invalid after this line.
  ctx->stop_flag = 2;
}

static void free_context(struct mg_context *ctx) {
  int i;

  // Deallocate config parameters
  for (i = 0; i < NUM_OPTIONS; i++) {
    if (ctx->config[i] != NULL)
      free(ctx->config[i]);
  }

  // Deallocate SSL context
  if (ctx->ssl_ctx != NULL) {
    SSL_CTX_free(ctx->ssl_ctx);
  }
  if (ctx->client_ssl_ctx != NULL) {
    SSL_CTX_free(ctx->client_ssl_ctx);
  }
#ifndef NO_SSL
  if (ssl_mutexes != NULL) {
    free(ssl_mutexes);
    ssl_mutexes = NULL;
  }
#endif // !NO_SSL

  // Deallocate context itself
  free(ctx);
}

void mg_stop(struct mg_context *ctx) {
  ctx->stop_flag = 1;

  // Wait until mg_fini() stops
  while (ctx->stop_flag != 2) {
    (void) mg_sleep(10);
  }
  free_context(ctx);

#if defined(_WIN32) && !defined(__SYMBIAN32__)
  (void) WSACleanup();
#endif // _WIN32
}

struct mg_context *mg_start(mg_callback_t user_callback, void *user_data,
                            const char **options) {
  struct mg_context *ctx;
  const char *name, *value, *default_value;
  int i;

#if defined(_WIN32) && !defined(__SYMBIAN32__)
  WSADATA data;
  WSAStartup(MAKEWORD(2,2), &data);
  InitializeCriticalSection(&global_log_file_lock);
#endif // _WIN32

  // Allocate context and initialize reasonable general case defaults.
  // TODO(lsm): do proper error handling here.
  if ((ctx = (struct mg_context *) calloc(1, sizeof(*ctx))) == NULL) {
    return NULL;
  }
  ctx->user_callback = user_callback;
  ctx->user_data = user_data;

  while (options && (name = *options++) != NULL) {
    if ((i = get_option_index(name)) == -1) {
      cry(fc(ctx), "Invalid option: %s", name);
      free_context(ctx);
      return NULL;
    } else if ((value = *options++) == NULL) {
      cry(fc(ctx), "%s: option value cannot be NULL", name);
      free_context(ctx);
      return NULL;
    }
    if (ctx->config[i] != NULL) {
      cry(fc(ctx), "warning: %s: duplicate option", name);
      free(ctx->config[i]);
    }
    ctx->config[i] = mg_strdup(value);
    DEBUG_TRACE(("[%s] -> [%s]", name, value));
  }

  // Set default value if needed
  for (i = 0; config_options[i * ENTRIES_PER_CONFIG_OPTION] != NULL; i++) {
    default_value = config_options[i * ENTRIES_PER_CONFIG_OPTION + 2];
    if (ctx->config[i] == NULL && default_value != NULL) {
      ctx->config[i] = mg_strdup(default_value);
      DEBUG_TRACE(("Setting default: [%s] -> [%s]",
                   config_options[i * ENTRIES_PER_CONFIG_OPTION + 1],
                   default_value));
    }
  }

  // NOTE(lsm): order is important here. SSL certificates must
  // be initialized before listening ports. UID must be set last.
  if (!set_gpass_option(ctx) ||
#if !defined(NO_SSL)
      !set_ssl_option(ctx) ||
#endif
      !set_ports_option(ctx) ||
#if !defined(_WIN32)
      !set_uid_option(ctx) ||
#endif
      !set_acl_option(ctx)) {
    free_context(ctx);
    return NULL;
  }

#if !defined(_WIN32) && !defined(__SYMBIAN32__)
  // Ignore SIGPIPE signal, so if browser cancels the request, it
  // won't kill the whole process.
  (void) signal(SIGPIPE, SIG_IGN);
  // Also ignoring SIGCHLD to let the OS to reap zombies properly.
  (void) signal(SIGCHLD, SIG_IGN);
#endif // !_WIN32

  (void) mg_thread_mutex_init(&ctx->mutex, NULL);
  (void) mg_thread_cond_init(&ctx->cond, NULL);
  (void) mg_thread_cond_init(&ctx->sq_empty, NULL);
  (void) mg_thread_cond_init(&ctx->sq_full, NULL);

  // Start master (listening) thread
  mg_start_thread((mg_thread_func_t) master_thread, ctx);

  // Start worker threads
  for (i = 0; i < atoi(ctx->config[NUM_THREADS]); i++) {
    if (mg_start_thread((mg_thread_func_t) worker_thread, ctx) != 0) {
      cry(fc(ctx), "Cannot start worker thread: %d", ERRNO);
    } else {
      ctx->num_threads++;
    }
  }

  return ctx;
}
