#ifndef STRLIB_H_
#define STRLIB_H_

#include <stdarg.h>

struct strlib_buf {
    size_t buflen; // Total size of the buffer
    size_t len; // Length of the string not including the terminating \0
    size_t mark; // Right mark for strbuf_rstrip
    char *s; // Buffer
};
typedef struct strlib_buf strlib_buf_t;

extern void strlib_init(strlib_buf_t *sb);
extern void strlib_free(strlib_buf_t *sb);
extern void strlib_reset(strlib_buf_t *sb);
extern void strlib_setmark(strlib_buf_t *sb, size_t mark);
extern void strlib_grow(strlib_buf_t *sb, size_t n);
extern void strlib_push(strlib_buf_t *sb, char c);
extern void strlib_rstrip(strlib_buf_t *sb);
extern void strlib_append(strlib_buf_t *sb, const char *s, size_t len);
extern void strlib_appendbuf(strlib_buf_t *dest, strlib_buf_t *src);
extern __attribute__((format(printf,2,0))) void strlib_vappendf(
        strlib_buf_t *sb, const char *fmt, va_list ap);
extern __attribute__((format(printf,2,3))) void strlib_appendf(
        strlib_buf_t *sb, const char *fmt, ...);

#endif /* STRLIB_H_ */
