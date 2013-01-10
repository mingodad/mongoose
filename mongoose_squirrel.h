#if defined(USE_SQUIRREL)
#include "squirrel.h"

void sq_printfunc(HSQUIRRELVM v,const SQChar *s,...)
{
  va_list vl;
	va_start(vl, s);
	vfprintf(stdout, s, vl);
	va_end(vl);
}

void sq_errorfunc(HSQUIRRELVM v,const SQChar *s,...)
{
	va_list vl;
	va_start(vl, s);
	vfprintf(stderr, s, vl);
	va_end(vl);
}

static void sqsp(struct mg_connection *conn, const char *p, int64_t len,
                HSQUIRRELVM v) {
  int i, j, pos = 0;

  for (i = 0; i < len; i++) {
    if (p[i] == '<' && p[i + 1] == '?') {
      for (j = i + 1; j < len ; j++) {
        if (p[j] == '?' && p[j + 1] == '>') {
          mg_write(conn, p + pos, i - pos);
          if (sq_compilebuffer(v, p + (i + 2), j - (i + 2), "sqsp", SQFalse) == SQ_OK) {
            sq_pushroottable(v);
            if(sq_call(v, 1, SQFalse, SQTrue) != SQ_OK){
                sq_errorfunc(v, "sq_call failed %d\n%s", __LINE__, sq_getlasterror_str(v));
            }
            sq_poptop(v); //remove function from stack
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

static int sqsp_mg_write(HSQUIRRELVM v) {
  int i, num_args;
  const char *str;
  size_t size;
  struct mg_connection *conn;
  sq_getuserpointer(v, -1, (SQUserPointer*)&conn);

  num_args = sq_gettop(v);
  for (i = 2; i < num_args; i++) { //last argument is the free variable
    sq_tostring(v, i);
    sq_getstring(v, -1, &str);
    size = sq_getsize(v, -1);
    mg_write(conn, str, size);
  }

  return 0;
}

static int sqsp_mg_read(HSQUIRRELVM v) {
  struct mg_connection *conn;
  sq_getuserpointer(v, -1, (void**)&conn);
  SQInteger param_len;
  if(sq_gettop(v) > 2) sq_getinteger(v, 2, &param_len);
  else param_len = 8192;
  SQChar *data = sq_getscratchpad(v,param_len);
  int len = mg_read(conn, data, param_len);
  sq_pushstring(v, data, len);

  return 1;
}

static void reg_string(HSQUIRRELVM v, const char *name, const char *val) {
  sq_pushstring(v, name, -1);
  if(val) sq_pushstring(v, val, -1);
  else sq_pushnull(v);
  sq_rawset(v, -3);
}

static void reg_int(HSQUIRRELVM v, const char *name, int val) {
  sq_pushstring(v, name, -1);
  sq_pushinteger(v, val);
  sq_rawset(v, -3);
}

static void prepare_sq_environment(struct mg_connection *conn, HSQUIRRELVM v) {
  const struct mg_request_info *ri = mg_get_request_info(conn);
  int i;

    sq_pushroottable(v);
    sqstd_register_bloblib(v);
    sqstd_register_iolib(v);
    sqstd_register_systemlib(v);
    sqstd_register_mathlib(v);
    sqstd_register_stringlib(v);

	sqstd_seterrorhandlers(v); //registers the default error handlers
	sq_setprintfunc(v, sq_printfunc, sq_errorfunc); //sets the print function

  // Register "write" function which calls mg_write()
	sq_pushstring(v,_SC("write"),-1);
	sq_pushuserpointer(v,conn);
	sq_newclosure(v,sqsp_mg_write,1);
	sq_setparamscheck(v,-2,NULL);
	sq_newslot(v,-3,SQFalse);

  // Register mg_read()
	sq_pushstring(v,_SC("read"),-1);
	sq_pushuserpointer(v,conn);
	sq_newclosure(v,sqsp_mg_read,1);
	sq_setparamscheck(v, -1,".i");
	sq_newslot(v,-3,SQFalse);

  // Export request_info
  sq_pushstring(v,_SC("request_info"),-1);
  sq_newtable(v);
  reg_string(v, "request_method", ri->request_method);
  reg_string(v, "uri", ri->uri);
  reg_string(v, "http_version", ri->http_version);
  reg_string(v, "query_string", ri->query_string);
  reg_int(v, "remote_ip", ri->remote_ip);
  reg_int(v, "remote_port", ri->remote_port);
  reg_int(v, "num_headers", ri->num_headers);
  sq_pushstring(v, "http_headers", -1);
  sq_newtable(v);
  for (i = 0; i < ri->num_headers; i++) {
    reg_string(v, ri->http_headers[i].name, ri->http_headers[i].value);
  }
  sq_rawset(v, -3);

  sq_newslot(v,-3,SQFalse); //request_info
  sq_poptop(v); //remove root table
}

static void handle_sqsp_request(struct mg_connection *conn, const char *path,
                               struct file *filep) {
  void *p = NULL;
  HSQUIRRELVM v = NULL;

  if (!mg_fopen(conn, path, "r", filep)) {
    send_http_error(conn, 404, "Not Found", "%s", "File not found");
  } else if (filep->membuf == NULL &&
             (p = mmap(NULL, filep->size, PROT_READ, MAP_PRIVATE,
                       fileno(filep->fp), 0)) == MAP_FAILED) {
    send_http_error(conn, 500, http_500_error, "%s", "x");
  } else if ((v = sq_open(1024)) == NULL) {
    send_http_error(conn, 500, http_500_error, "%s", "y");
  } else {
    mg_printf(conn, "%s", "HTTP/1.1 200 OK\r\n"
              "Content-Type: text/html\r\nConnection: close\r\n\r\n");
    prepare_sq_environment(conn, v);
    conn->request_info.ev_data = v;
    call_user(conn, MG_INIT_LUA);
    sqsp(conn, filep->membuf == NULL ? p : filep->membuf, filep->size, v);
  }

  if (v) sq_close(v);
  if (p) munmap(p, filep->size);
  mg_fclose(filep);
}

#endif

