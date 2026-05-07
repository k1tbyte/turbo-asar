/**
 * @file js_scan.h
 * @brief Zero-allocation JSON scanner primitives.
 *
 * Header-only. All functions are static inline.
 *
 * Limitation: key comparison uses raw JSON bytes. Names containing JSON
 * escape sequences (e.g. a literal backslash in a filename) will not match.
 * This is extremely rare in practice on all platforms.
 */

#ifndef JS_SCAN_H
#define JS_SCAN_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/* Forward declaration needed for mutual recursion between skip helpers. */
static inline const char *js_skip_val(const char *p);

static inline const char *js_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

static inline const char *js_skip_str(const char *p)
{
    if (*p != '"') return p;
    for (++p; *p && *p != '"'; p++)
        if (*p == '\\' && p[1]) p++;
    return *p == '"' ? p + 1 : p;
}

static inline const char *js_skip_obj(const char *p)
{
    if (*p != '{') return p + 1;
    p++;
    p = js_ws(p);
    if (*p == '}') return p + 1;
    while (*p == '"') {
        p = js_skip_str(p);
        p = js_ws(p);
        if (*p == ':') p++;
        p = js_ws(p);
        p = js_skip_val(p);
        p = js_ws(p);
        if      (*p == ',') { p++; p = js_ws(p); }
        else if (*p == '}') return p + 1;
        else break;
    }
    return p;
}

static inline const char *js_skip_arr(const char *p)
{
    if (*p != '[') return p + 1;
    p++;
    p = js_ws(p);
    if (*p == ']') return p + 1;
    while (*p) {
        p = js_skip_val(p);
        p = js_ws(p);
        if      (*p == ',') { p++; p = js_ws(p); }
        else if (*p == ']') return p + 1;
        else break;
    }
    return p;
}

static inline const char *js_skip_val(const char *p)
{
    p = js_ws(p);
    if (*p == '{') return js_skip_obj(p);
    if (*p == '[') return js_skip_arr(p);
    if (*p == '"') return js_skip_str(p);
    if (*p == '-' || (*p >= '0' && *p <= '9')) {
        if (*p == '-') p++;
        while (*p >= '0' && *p <= '9') p++;
        if (*p == '.') { p++; while (*p >= '0' && *p <= '9') p++; }
        if (*p == 'e' || *p == 'E') {
            p++;
            if (*p == '+' || *p == '-') p++;
            while (*p >= '0' && *p <= '9') p++;
        }
        return p;
    }
    if (strncmp(p, "true",  4) == 0) return p + 4;
    if (strncmp(p, "false", 5) == 0) return p + 5;
    if (strncmp(p, "null",  4) == 0) return p + 4;
    return p + 1;
}

/* Return pointer to the value of `key` (klen bytes, no quotes) inside the
 * JSON object at p (must start with '{').  Returns NULL if not found. */
static inline const char *js_obj_get(const char *p, const char *key, size_t klen)
{
    if (!p || *p != '{') return NULL;
    p++;
    p = js_ws(p);
    if (*p == '}') return NULL;
    while (*p == '"') {
        const char *ks = p + 1;
        p = js_skip_str(p);
        size_t tklen = (size_t)((p - 1) - ks);
        p = js_ws(p);
        if (*p != ':') return NULL;
        p++;
        p = js_ws(p);
        if (tklen == klen && memcmp(ks, key, klen) == 0) return p;
        p = js_skip_val(p);
        p = js_ws(p);
        if      (*p == ',') { p++; p = js_ws(p); }
        else if (*p == '}') break;
    }
    return NULL;
}

/* Read a JSON string value (p at '"') into buf (NUL-terminated). */
static inline bool js_read_str(const char *p, char *buf, size_t bufsz)
{
    if (*p != '"' || bufsz == 0) return false;
    p++;
    size_t i = 0;
    while (*p && *p != '"') {
        if (i >= bufsz - 1) return false;
        if (*p == '\\') {
            p++;
            char c;
            switch (*p) {
                case '"':  c = '"';  break;
                case '\\': c = '\\'; break;
                case '/':  c = '/';  break;
                case 'n':  c = '\n'; break;
                case 'r':  c = '\r'; break;
                case 't':  c = '\t'; break;
                default:   c = *p;   break;
            }
            buf[i++] = c;
        } else {
            buf[i++] = *p;
        }
        p++;
    }
    buf[i] = '\0';
    return *p == '"';
}

/* Read unsigned decimal integer from JSON number at p. */
static inline uint64_t js_u64(const char *p)
{
    uint64_t v = 0;
    while (*p >= '0' && *p <= '9') v = v * 10 + (uint64_t)(*p++ - '0');
    return v;
}

#define JS_SCAN_NAV_MAX_DEPTH 32

#endif /* JS_SCAN_H */
