#if !defined(NO_CGI)

#if defined(_WIN32) && !defined(__SYMBIAN32__)
static pid_t mg_spawn_process(struct mg_connection *conn, const char *prog,
                           char *envblk, char *envp[], int fd_stdin,
                           int fd_stdout, const char *dir) {
  HANDLE me;
  char *p, *interp, full_interp[PATH_MAX], full_dir[PATH_MAX],
       cmdline[PATH_MAX], buf[PATH_MAX];
  struct file file;
  STARTUPINFOA si = { sizeof(si) };
  PROCESS_INFORMATION pi = { 0 };

  envp = NULL; // Unused

  // TODO(lsm): redirect CGI errors to the error log file
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;

  me = GetCurrentProcess();
  DuplicateHandle(me, (HANDLE) _get_osfhandle(fd_stdin), me,
                  &si.hStdInput, 0, TRUE, DUPLICATE_SAME_ACCESS);
  DuplicateHandle(me, (HANDLE) _get_osfhandle(fd_stdout), me,
                  &si.hStdOutput, 0, TRUE, DUPLICATE_SAME_ACCESS);

  // If CGI file is a script, try to read the interpreter line
  interp = conn->ctx->config[CGI_INTERPRETER];
  if (interp == NULL) {
    buf[0] = buf[1] = '\0';

    // Read the first line of the script into the buffer
    snprintf(cmdline, sizeof(cmdline), "%s%c%s", dir, '/', prog);
    if (mg_conn_fopen(conn, cmdline, "r", &file)) {
      p = (char *) file.membuf;
      mg_fgets(buf, sizeof(buf), &file, &p);
      mg_fclose(&file);
      buf[sizeof(buf) - 1] = '\0';
    }

    if (buf[0] == '#' && buf[1] == '!') {
      trim_trailing_whitespaces(buf + 2);
    } else {
      buf[2] = '\0';
    }
    interp = buf + 2;
  }

  if (interp[0] != '\0') {
    GetFullPathNameA(interp, sizeof(full_interp), full_interp, NULL);
    interp = full_interp;
  }
  GetFullPathNameA(dir, sizeof(full_dir), full_dir, NULL);

  mg_snprintf(conn, cmdline, sizeof(cmdline), "%s%s%s\\%s",
              interp, interp[0] == '\0' ? "" : " ", full_dir, prog);

  DEBUG_TRACE(("Running [%s]", cmdline));
  if (CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
        CREATE_NEW_PROCESS_GROUP, envblk, NULL, &si, &pi) == 0) {
    cry(conn, "%s: CreateProcess(%s): %d",
        __func__, cmdline, ERRNO);
    pi.hProcess = (pid_t) -1;
  }

  // Always close these to prevent handle leakage.
  (void) close(fd_stdin);
  (void) close(fd_stdout);

  (void) CloseHandle(si.hStdOutput);
  (void) CloseHandle(si.hStdInput);
  (void) CloseHandle(pi.hThread);

  return (pid_t) pi.hProcess;
}
#else
static pid_t spawn_process(struct mg_connection *conn, const char *prog,
                           char *envblk, char *envp[], int fd_stdin,
                           int fd_stdout, const char *dir) {
  pid_t pid;
  const char *interp;

  envblk = NULL; // Unused

  if ((pid = fork()) == -1) {
    // Parent
    send_http_error(conn, 500, http_500_error, "fork(): %s", strerror(ERRNO));
  } else if (pid == 0) {
    // Child
    if (chdir(dir) != 0) {
      cry(conn, "%s: chdir(%s): %s", __func__, dir, strerror(ERRNO));
    } else if (dup2(fd_stdin, 0) == -1) {
      cry(conn, "%s: dup2(%d, 0): %s", __func__, fd_stdin, strerror(ERRNO));
    } else if (dup2(fd_stdout, 1) == -1) {
      cry(conn, "%s: dup2(%d, 1): %s", __func__, fd_stdout, strerror(ERRNO));
    } else {
      (void) dup2(fd_stdout, 2);
      (void) close(fd_stdin);
      (void) close(fd_stdout);

      // After exec, all signal handlers are restored to their default values,
      // with one exception of SIGCHLD. According to POSIX.1-2001 and Linux's
      // implementation, SIGCHLD's handler will leave unchanged after exec
      // if it was set to be ignored. Restore it to default action.
      signal(SIGCHLD, SIG_DFL);

      interp = conn->ctx->config[CGI_INTERPRETER];
      if (interp == NULL) {
        (void) execle(prog, prog, NULL, envp);
        cry(conn, "%s: execle(%s): %s", __func__, prog, strerror(ERRNO));
      } else {
        (void) execle(interp, interp, prog, NULL, envp);
        cry(conn, "%s: execle(%s %s): %s", __func__, interp, prog,
            strerror(ERRNO));
      }
    }
    exit(EXIT_FAILURE);
  }

  // Parent. Close stdio descriptors
  (void) close(fd_stdin);
  (void) close(fd_stdout);

  return pid;
}
#endif

// This structure helps to create an environment for the spawned CGI program.
// Environment is an array of "VARIABLE=VALUE\0" ASCIIZ strings,
// last element must be NULL.
// However, on Windows there is a requirement that all these VARIABLE=VALUE\0
// strings must reside in a contiguous buffer. The end of the buffer is
// marked by two '\0' characters.
// We satisfy both worlds: we create an envp array (which is vars), all
// entries are actually pointers inside buf.
struct cgi_env_block {
  struct mg_connection *conn;
  char buf[CGI_ENVIRONMENT_SIZE]; // Environment buffer
  int len; // Space taken
  char *vars[MAX_CGI_ENVIR_VARS]; // char **envp
  int nvars; // Number of variables
};

static char *addenv(struct cgi_env_block *block,
                    PRINTF_FORMAT_STRING(const char *fmt), ...)
  PRINTF_ARGS(2, 3);

// Append VARIABLE=VALUE\0 string to the buffer, and add a respective
// pointer into the vars array.
static char *addenv(struct cgi_env_block *block, const char *fmt, ...) {
  int n, space;
  char *added;
  va_list ap;

  // Calculate how much space is left in the buffer
  space = sizeof(block->buf) - block->len - 2;
  assert(space >= 0);

  // Make a pointer to the free space int the buffer
  added = block->buf + block->len;

  // Copy VARIABLE=VALUE\0 string into the free space
  va_start(ap, fmt);
  n = mg_vsnprintf(block->conn, added, (size_t) space, fmt, ap);
  va_end(ap);

  // Make sure we do not overflow buffer and the envp array
  if (n > 0 && n + 1 < space &&
      block->nvars < (int) ARRAY_SIZE(block->vars) - 2) {
    // Append a pointer to the added string into the envp array
    block->vars[block->nvars++] = added;
    // Bump up used length counter. Include \0 terminator
    block->len += n + 1;
  } else {
    cry(block->conn, "%s: CGI env buffer truncated for [%s]", __func__, fmt);
  }

  return added;
}

static void prepare_cgi_environment(struct mg_connection *conn,
                                    const char *prog,
                                    struct cgi_env_block *blk) {
  const char *s, *slash;
  struct vec var_vec;
  char *p, src_addr[20];
  int  i;

  blk->len = blk->nvars = 0;
  blk->conn = conn;
  mg_sockaddr_to_string(src_addr, sizeof(src_addr), &conn->client.rsa);

  addenv(blk, "SERVER_NAME=%s", conn->ctx->config[AUTHENTICATION_DOMAIN]);
  addenv(blk, "SERVER_ROOT=%s", conn->ctx->config[DOCUMENT_ROOT]);
  addenv(blk, "DOCUMENT_ROOT=%s", conn->ctx->config[DOCUMENT_ROOT]);

  // Prepare the environment block
  addenv(blk, "%s", "GATEWAY_INTERFACE=CGI/1.1");
  addenv(blk, "%s", "SERVER_PROTOCOL=HTTP/1.1");
  addenv(blk, "%s", "REDIRECT_STATUS=200"); // For PHP

  // TODO(lsm): fix this for IPv6 case
  addenv(blk, "SERVER_PORT=%d", ntohs(conn->client.lsa.sin.sin_port));

  addenv(blk, "REQUEST_METHOD=%s", conn->request_info.request_method);
  addenv(blk, "REMOTE_ADDR=%s", src_addr);
  addenv(blk, "REMOTE_PORT=%d", conn->request_info.remote_port);
  addenv(blk, "REQUEST_URI=%s", conn->request_info.uri);

  // SCRIPT_NAME
  assert(conn->request_info.uri[0] == '/');
  slash = strrchr(conn->request_info.uri, '/');
  if ((s = strrchr(prog, '/')) == NULL)
    s = prog;
  addenv(blk, "SCRIPT_NAME=%.*s%s", (int) (slash - conn->request_info.uri),
         conn->request_info.uri, s);

  addenv(blk, "SCRIPT_FILENAME=%s", prog);
  addenv(blk, "PATH_TRANSLATED=%s", prog);
  addenv(blk, "HTTPS=%s", conn->ssl == NULL ? "off" : "on");

  if ((s = mg_get_header(conn, "Content-Type")) != NULL)
    addenv(blk, "CONTENT_TYPE=%s", s);

  if (conn->request_info.query_string != NULL)
    addenv(blk, "QUERY_STRING=%s", conn->request_info.query_string);

  if ((s = mg_get_header(conn, "Content-Length")) != NULL)
    addenv(blk, "CONTENT_LENGTH=%s", s);

  if ((s = getenv("PATH")) != NULL)
    addenv(blk, "PATH=%s", s);

  if (conn->path_info != NULL) {
    addenv(blk, "PATH_INFO=%s", conn->path_info);
  }

#if defined(_WIN32)
  if ((s = getenv("COMSPEC")) != NULL) {
    addenv(blk, "COMSPEC=%s", s);
  }
  if ((s = getenv("SYSTEMROOT")) != NULL) {
    addenv(blk, "SYSTEMROOT=%s", s);
  }
  if ((s = getenv("SystemDrive")) != NULL) {
    addenv(blk, "SystemDrive=%s", s);
  }
#else
  if ((s = getenv("LD_LIBRARY_PATH")) != NULL)
    addenv(blk, "LD_LIBRARY_PATH=%s", s);
#endif // _WIN32

  if ((s = getenv("PERLLIB")) != NULL)
    addenv(blk, "PERLLIB=%s", s);

  if (conn->request_info.remote_user != NULL) {
    addenv(blk, "REMOTE_USER=%s", conn->request_info.remote_user);
    addenv(blk, "%s", "AUTH_TYPE=Digest");
  }

  // Add all headers as HTTP_* variables
  for (i = 0; i < conn->request_info.num_headers; i++) {
    p = addenv(blk, "HTTP_%s=%s",
        conn->request_info.http_headers[i].name,
        conn->request_info.http_headers[i].value);

    // Convert variable name into uppercase, and change - to _
    for (; *p != '=' && *p != '\0'; p++) {
      if (*p == '-')
        *p = '_';
      *p = (char) toupper(* (unsigned char *) p);
    }
  }

  // Add user-specified variables
  s = conn->ctx->config[CGI_ENVIRONMENT];
  while ((s = mg_next_option(s, &var_vec, NULL)) != NULL) {
    addenv(blk, "%.*s", (int) var_vec.len, var_vec.ptr);
  }

  blk->vars[blk->nvars++] = NULL;
  blk->buf[blk->len++] = '\0';

  assert(blk->nvars < (int) ARRAY_SIZE(blk->vars));
  assert(blk->len > 0);
  assert(blk->len < (int) sizeof(blk->buf));
}

static void handle_cgi_request(struct mg_connection *conn, const char *prog) {
  int headers_len, data_len, i, fd_stdin[2], fd_stdout[2];
  const char *status, *status_text;
  char buf[16384], *pbuf, dir[PATH_MAX], *p;
  struct mg_request_info ri;
  struct cgi_env_block blk;
  FILE *in, *out;
  struct file fout = STRUCT_FILE_INITIALIZER;
  pid_t pid;

  prepare_cgi_environment(conn, prog, &blk);

  // CGI must be executed in its own directory. 'dir' must point to the
  // directory containing executable program, 'p' must point to the
  // executable program name relative to 'dir'.
  (void) mg_snprintf(conn, dir, sizeof(dir), "%s", prog);
  if ((p = strrchr(dir, '/')) != NULL) {
    *p++ = '\0';
  } else {
    dir[0] = '.', dir[1] = '\0';
    p = (char *) prog;
  }

  pid = (pid_t) -1;
  fd_stdin[0] = fd_stdin[1] = fd_stdout[0] = fd_stdout[1] = -1;
  in = out = NULL;

  if (pipe(fd_stdin) != 0 || pipe(fd_stdout) != 0) {
    send_http_error(conn, 500, http_500_error,
        "Cannot create CGI pipe: %s", strerror(ERRNO));
    goto done;
  }

  pid = spawn_process(conn, p, blk.buf, blk.vars, fd_stdin[0], fd_stdout[1],
                      dir);
  // spawn_process() must close those!
  // If we don't mark them as closed, close() attempt before
  // return from this function throws an exception on Windows.
  // Windows does not like when closed descriptor is closed again.
  fd_stdin[0] = fd_stdout[1] = -1;

  if (pid == (pid_t) -1) {
    send_http_error(conn, 500, http_500_error,
        "Cannot spawn CGI process [%s]: %s", prog, strerror(ERRNO));
    goto done;
  }

  if ((in = fdopen(fd_stdin[1], "wb")) == NULL ||
      (out = fdopen(fd_stdout[0], "rb")) == NULL) {
    send_http_error(conn, 500, http_500_error,
        "fopen: %s", strerror(ERRNO));
    goto done;
  }

  setbuf(in, NULL);
  setbuf(out, NULL);
  fout.fp = out;

  // Send POST data to the CGI process if needed
  if (!strcmp(conn->request_info.request_method, "POST") &&
      !forward_body_data(conn, in, INVALID_SOCKET, NULL)) {
    goto done;
  }

  // Close so child gets an EOF.
  fclose(in);
  in = NULL;
  fd_stdin[1] = -1;

  // Now read CGI reply into a buffer. We need to set correct
  // status code, thus we need to see all HTTP headers first.
  // Do not send anything back to client, until we buffer in all
  // HTTP headers.
  data_len = 0;
  headers_len = read_request(out, conn, buf, sizeof(buf), &data_len);
  if (headers_len <= 0) {
    send_http_error(conn, 500, http_500_error,
                    "CGI program sent malformed or too big (>%u bytes) "
                    "HTTP headers: [%.*s]",
                    (unsigned) sizeof(buf), data_len, buf);
    goto done;
  }
  pbuf = buf;
  buf[headers_len - 1] = '\0';
  parse_http_headers(&pbuf, &ri);

  // Make up and send the status line
  status_text = "OK";
  if ((status = get_header(&ri, "Status")) != NULL) {
    conn->status_code = atoi(status);
    status_text = status;
    while (isdigit(* (unsigned char *) status_text) || *status_text == ' ') {
      status_text++;
    }
  } else if (get_header(&ri, "Location") != NULL) {
    conn->status_code = 302;
  } else {
    conn->status_code = 200;
  }
  if (get_header(&ri, "Connection") != NULL &&
      !mg_strcasecmp(get_header(&ri, "Connection"), "keep-alive")) {
    conn->must_close = 1;
  }
  (void) mg_printf(conn, "HTTP/1.1 %d %s\r\n", conn->status_code,
                   status_text);

  // Send headers
  for (i = 0; i < ri.num_headers; i++) {
    mg_printf(conn, "%s: %s\r\n",
              ri.http_headers[i].name, ri.http_headers[i].value);
  }
  mg_write(conn, "\r\n", 2);

  // Send chunk of data that may have been read after the headers
  conn->num_bytes_sent += mg_write(conn, buf + headers_len,
                                   (size_t)(data_len - headers_len));

  // Read the rest of CGI output and send to the client
  send_file_data(conn, &fout, 0, INT64_MAX);

done:
  if (pid != (pid_t) -1) {
    kill(pid, SIGKILL);
  }
  if (fd_stdin[0] != -1) {
    close(fd_stdin[0]);
  }
  if (fd_stdout[1] != -1) {
    close(fd_stdout[1]);
  }

  if (in != NULL) {
    fclose(in);
  } else if (fd_stdin[1] != -1) {
    close(fd_stdin[1]);
  }

  if (out != NULL) {
    fclose(out);
  } else if (fd_stdout[0] != -1) {
    close(fd_stdout[0]);
  }
}
#endif // !NO_CGI

