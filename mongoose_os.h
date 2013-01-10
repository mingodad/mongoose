#ifndef MONGOOSE_OS_H
#define MONGOOSE_OS_H

#if defined(_WIN32)
#define _CRT_SECURE_NO_WARNINGS // Disable deprecation warning in VS2005
#else
#ifdef __linux__
#define _XOPEN_SOURCE 600     // For flockfile() on Linux
#endif
#define _LARGEFILE_SOURCE     // Enable 64-bit file offsets
#define __STDC_FORMAT_MACROS  // <inttypes.h> wants this for C++
#define __STDC_LIMIT_MACROS   // C++ wants that for INT64_MAX
#endif

#if defined (_MSC_VER)
// conditional expression is constant: introduced by FD_SET(..)
#pragma warning (disable : 4127)
// non-constant aggregate initializer: issued due to missing C99 support
#pragma warning (disable : 4204)
#endif

// Disable WIN32_LEAN_AND_MEAN.
// This makes windows.h always include winsock2.h
#ifdef WIN32_LEAN_AND_MEAN
#undef WIN32_LEAN_AND_MEAN
#endif

#ifndef _WIN32_WCE // Some ANSI #includes are not available on Windows CE
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#endif // !_WIN32_WCE

#include <time.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>

#if defined(_WIN32) && !defined(__SYMBIAN32__) // Windows specific
#define _WIN32_WINNT 0x0400 // To make it link in VS2005
#include <windows.h>

#ifndef PATH_MAX
#define PATH_MAX MAX_PATH
#endif

#ifndef _WIN32_WCE
#include <process.h>
#include <direct.h>
#include <io.h>
#else // _WIN32_WCE
#define NO_CGI // WinCE has no pipes

typedef long off_t;

#define errno   GetLastError()
#define strerror(x)  _ultoa(x, (char *) _alloca(sizeof(x) *3 ), 10)
#endif // _WIN32_WCE

#define MAKEUQUAD(lo, hi) ((uint64_t)(((uint32_t)(lo)) | \
      ((uint64_t)((uint32_t)(hi))) << 32))
#define RATE_DIFF 10000000 // 100 nsecs
#define EPOCH_DIFF MAKEUQUAD(0xd53e8000, 0x019db1de)
#define SYS2UNIX_TIME(lo, hi) \
  (time_t) ((MAKEUQUAD((lo), (hi)) - EPOCH_DIFF) / RATE_DIFF)

// Visual Studio 6 does not know __func__ or __FUNCTION__
// The rest of MS compilers use __FUNCTION__, not C99 __func__
// Also use _strtoui64 on modern M$ compilers
#if defined(_MSC_VER) && _MSC_VER < 1300
#define STRX(x) #x
#define STR(x) STRX(x)
#define __func__ "line " STR(__LINE__)
#define strtoull(x, y, z) strtoul(x, y, z)
#define strtoll(x, y, z) strtol(x, y, z)
#else
#define __func__  __FUNCTION__
#define strtoull(x, y, z) _strtoui64(x, y, z)
#define strtoll(x, y, z) _strtoi64(x, y, z)
#endif // _MSC_VER

#define ERRNO   GetLastError()
#define NO_SOCKLEN_T
#define O_NONBLOCK  0
#if !defined(EWOULDBLOCK)
#define EWOULDBLOCK  WSAEWOULDBLOCK
#endif // !EWOULDBLOCK
#define _POSIX_
#define INT64_FMT  "I64d"

#define WINCDECL __cdecl
#define SHUT_WR 1
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#define mg_sleep(x) Sleep(x)

#define pipe(x) _pipe(x, MG_BUF_LEN, _O_BINARY)
#define popen(x, y) _popen(x, y)
#define pclose(x) _pclose(x)
#define close(x) _close(x)
#define dlsym(x,y) GetProcAddress((HINSTANCE) (x), (y))
#define RTLD_LAZY  0
#define fseeko(x, y, z) _lseeki64(_fileno(x), (y), (z))
#define fdopen(x, y) _fdopen((x), (y))
#define write(x, y, z) _write((x), (y), (unsigned) z)
#define read(x, y, z) _read((x), (y), (unsigned) z)
#define flockfile(x) EnterCriticalSection(&global_log_file_lock)
#define funlockfile(x) LeaveCriticalSection(&global_log_file_lock)
#define sleep(x) Sleep((x) * 1000)

#if !defined(fileno)
#define fileno(x) _fileno(x)
#endif // !fileno MINGW #defines fileno

#define pid_t HANDLE // MINGW typedefs pid_t to int. Using #define here.

static void to_unicode(const char *path, wchar_t *wbuf, size_t wbuf_len);
struct file;
static char *mg_fgets(char *buf, size_t size, struct file *filep, char **p);

#if defined(HAVE_STDINT)
#include <stdint.h>
#else
typedef unsigned int  uint32_t;
typedef unsigned short  uint16_t;
typedef unsigned __int64 uint64_t;
typedef __int64   int64_t;
#define INT64_MAX  9223372036854775807
#endif // HAVE_STDINT

// POSIX dirent interface
struct dirent {
  char d_name[PATH_MAX];
};

typedef struct DIR {
  HANDLE   handle;
  WIN32_FIND_DATAW info;
  struct dirent  result;
} DIR;

// Mark required libraries
#pragma comment(lib, "Ws2_32.lib")

#else    // UNIX  specific
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <stdint.h>
#include <inttypes.h>
#include <netdb.h>

#include <pwd.h>
#include <unistd.h>
#include <dirent.h>
#ifndef O_BINARY
#define O_BINARY  0
#endif // O_BINARY
#define closesocket(a) close(a)
#define mg_sleep(x) usleep((x) * 1000)
#define ERRNO errno
#define INVALID_SOCKET (-1)
#define INT64_FMT PRId64
typedef int SOCKET;
#define WINCDECL

#endif // End of Windows and UNIX specific includes

// Darwin prior to 7.0 and Win32 do not have socklen_t
#ifdef NO_SOCKLEN_T
typedef int socklen_t;
#endif // NO_SOCKLEN_T
#define _DARWIN_UNLIMITED_SELECT

#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

#if !defined(SOMAXCONN)
#define SOMAXCONN 100
#endif

#if !defined(PATH_MAX)
#define PATH_MAX 4096
#endif

// Unified socket address. For IPv6 support, add IPv6 address structure
// in the union u.
union usa {
  struct sockaddr sa;
  struct sockaddr_in sin;
#if defined(USE_IPV6)
  struct sockaddr_in6 sin6;
#endif
};

// Describes a string (chunk of memory).
struct vec {
  const char *ptr;
  size_t len;
};

struct file {
  int is_directory;
  time_t modification_time;
  int64_t size;
  FILE *fp;
  const char *membuf;   // Non-NULL if file data is in memory
};
#define STRUCT_FILE_INITIALIZER {0, 0, 0, NULL, NULL}

// Describes listening socket, or socket which was accept()-ed by the master
// thread and queued for future handling by the worker thread.
struct socket {
  struct socket *next;  // Linkage
  SOCKET sock;          // Listening socket
  union usa lsa;        // Local socket address
  union usa rsa;        // Remote socket address
  int is_ssl;           // Is socket SSL-ed
};

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

void mg_fopen(const char *path, const char *mode, struct file *filep);
int mg_fgetc(struct file *filep, int offset);
void mg_fclose(struct file *filep);
int mg_rename(const char* oldname, const char* newname);
int mg_remove(const char *path);
int mg_mkdir(const char *path, int mode);
DIR * mg_opendir(const char *name);
struct dirent *mg_readdir(DIR *dir);
int mg_closedir(DIR *dir);
void mg_file_stat(const char *path, struct file *filep);
int mg_kill(pid_t pid, int sig_num);

int mg_set_non_blocking_mode(SOCKET sock);
void mg_set_close_on_exec(int fd);
void mg_sockaddr_to_string(char *buf, size_t len, const union usa *usa);

void mg_strlcpy(register char *dst, register const char *src, size_t n);
int mg_lowercase(const char *s);
int mg_strncasecmp(const char *s1, const char *s2, size_t len);
int mg_strcasecmp(const char *s1, const char *s2);
char * mg_strndup(const char *ptr, size_t len);
char * mg_strdup(const char *str);
void mg_trim_trailing_whitespaces(char *s);
void mg_remove_double_dots_and_double_slashes(char *s);
int mg_match_prefix(const char *pattern, int pattern_len, const char *str);
char *mg_skip_quoted(char **buf, const char *delimiters,
                         const char *whitespace, char quotechar);
const char *mg_next_option(const char *list, struct vec *val,
                               struct vec *eq_val);
int mg_get_request_len(const char *buf, int buflen);
void mg_url_encode(const char *src, char *dst, size_t dst_len);
int mg_url_decode(const char *src, int src_len, char *dst,
                      int dst_len, int is_form_url_encoded);
int mg_get_var(const char *data, size_t data_len, const char *name,
               char *dst, size_t dst_len);
time_t mg_parse_date_string(const char *datetime);
int mg_parse_net(const char *spec, uint32_t *net, uint32_t *mask);

#endif //MONGOOSE_OS_H
