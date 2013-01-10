#ifdef USE_LUA
#include <lua.h>
#include <lauxlib.h>

#ifdef _WIN32
static void *mmap(void *addr, int64_t len, int prot, int flags, int fd,
                  int offset) {
  HANDLE fh = (HANDLE) _get_osfhandle(fd);
  HANDLE mh = CreateFileMapping(fh, 0, PAGE_READONLY, 0, 0, 0);
  void *p = MapViewOfFile(mh, FILE_MAP_READ, 0, 0, (size_t) len);
  CloseHandle(fh);
  CloseHandle(mh);
  return p;
}
#define munmap(x, y)  UnmapViewOfFile(x)
#define MAP_FAILED NULL
#define MAP_PRIVATE 0
#define PROT_READ 0
#else
#include <sys/mman.h>
#endif

static void lsp(struct mg_connection *conn, const char *p, int64_t len,
                lua_State *L) {
  int i, j, pos = 0;

  for (i = 0; i < len; i++) {
    if (p[i] == '<' && p[i + 1] == '?') {
      for (j = i + 1; j < len ; j++) {
        if (p[j] == '?' && p[j + 1] == '>') {
          mg_write(conn, p + pos, i - pos);
          if (luaL_loadbuffer(L, p + (i + 2), j - (i + 2), "") == LUA_OK) {
            lua_pcall(L, 0, LUA_MULTRET, 0);
          }
          pos = j + 2;
          i = pos - 1;
          break;
        }
      }
    }
  }

  if (i > pos) {
    mg_write(conn, p + pos, i - pos);
  }
}

static int lsp_mg_print(lua_State *L) {
  int i, num_args;
  const char *str;
  size_t size;
  struct mg_connection *conn = lua_touserdata(L, lua_upvalueindex(1));

  num_args = lua_gettop(L);
  for (i = 1; i <= num_args; i++) {
    if (lua_isstring(L, i)) {
      str = lua_tolstring(L, i, &size);
      mg_write(conn, str, size);
    }
  }

  return 0;
}

static int lsp_mg_read(lua_State *L) {
  struct mg_connection *conn = lua_touserdata(L, lua_upvalueindex(1));
  char buf[1024];
  int len = mg_read(conn, buf, sizeof(buf));

  lua_settop(L, 0);
  lua_pushlstring(L, buf, len);

  return 1;
}

static void reg_string(struct lua_State *L, const char *name, const char *val) {
  lua_pushstring(L, name);
  lua_pushstring(L, val);
  lua_rawset(L, -3);
}

static void reg_int(struct lua_State *L, const char *name, int val) {
  lua_pushstring(L, name);
  lua_pushinteger(L, val);
  lua_rawset(L, -3);
}

static void prepare_lua_environment(struct mg_connection *conn, lua_State *L) {
  const struct mg_request_info *ri = mg_get_request_info(conn);
  extern void luaL_openlibs(lua_State *);
  int i;

  luaL_openlibs(L);

  // Register "print" function which calls mg_write()
  lua_pushlightuserdata(L, conn);
  lua_pushcclosure(L, lsp_mg_print, 1);
  lua_setglobal(L, "print");

  // Register mg_read()
  lua_pushlightuserdata(L, conn);
  lua_pushcclosure(L, lsp_mg_read, 1);
  lua_setglobal(L, "read");

  // Export request_info
  lua_newtable(L);
  reg_string(L, "request_method", ri->request_method);
  reg_string(L, "uri", ri->uri);
  reg_string(L, "http_version", ri->http_version);
  reg_string(L, "query_string", ri->query_string);
  reg_int(L, "remote_ip", ri->remote_ip);
  reg_int(L, "remote_port", ri->remote_port);
  reg_int(L, "num_headers", ri->num_headers);
  lua_pushstring(L, "http_headers");
  lua_newtable(L);
  for (i = 0; i < ri->num_headers; i++) {
    reg_string(L, ri->http_headers[i].name, ri->http_headers[i].value);
  }
  lua_rawset(L, -3);
  lua_setglobal(L, "request_info");
}

static void handle_lsp_request(struct mg_connection *conn, const char *path,
                               struct file *filep) {
  void *p = NULL;
  lua_State *L = NULL;

  if (!mg_conn_fopen(conn, path, "r", filep)) {
    send_http_error(conn, 404, "Not Found", "%s", "File not found");
  } else if (filep->membuf == NULL &&
             (p = mmap(NULL, filep->size, PROT_READ, MAP_PRIVATE,
                       fileno(filep->fp), 0)) == MAP_FAILED) {
    send_http_error(conn, 500, http_500_error, "%s", "x");
  } else if ((L = luaL_newstate()) == NULL) {
    send_http_error(conn, 500, http_500_error, "%s", "y");
  } else {
    mg_printf(conn, "%s", "HTTP/1.1 200 OK\r\n"
              "Content-Type: text/html\r\nConnection: close\r\n\r\n");
    prepare_lua_environment(conn, L);
    conn->request_info.ev_data = L;
    call_user(conn, MG_INIT_LUA);
    lsp(conn, filep->membuf == NULL ? p : filep->membuf, filep->size, L);
  }

  if (L) lua_close(L);
  if (p) munmap(p, filep->size);
  mg_fclose(filep);
}
#endif // USE_LUA

