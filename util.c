/*
 * Some internal utility functions
 */

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#include "pgpr.h"
#include "pgpr_internal.h"

uint32_t pgprCurrentTime(void) {
    time_t t = time(NULL);
    return (uint32_t)t;
}

void *pgprMemdup(const void *ptr, size_t len)
{
    void *mem = ptr ? pgprMalloc(len) : NULL;
    if (mem && len)
	memcpy(mem, ptr, len);
    return mem;
}

char *pgprStrdup(const char *s)
{
    return s ? pgprMemdup(s, strlen(s) + 1) : NULL;
}

int pgprAsprintf(char **strp, const char *fmt, ...)
{
    int n;
    va_list ap;

    va_start(ap, fmt);
    n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n >= -1) {
	size_t nb = n + 1;
	*strp = pgprMalloc(nb);
	if (*strp) {
	    va_start(ap, fmt);
	    n = vsnprintf(*strp, nb, fmt, ap);
	    va_end(ap);
	}
    }
    return n;
}

#ifndef PGPR_RPM_INTREE

static void xoom(size_t num, size_t len)
{
    if (num)
	fprintf(stderr, "Out of memory allocating %zu*%zu bytes!\n", num, len);
    else if (len)
	fprintf(stderr, "Out of memory allocating %zu bytes!\n", len);
    else
	fprintf(stderr, "Out of memory!\n");
    abort();
}

void *pgprMalloc(size_t len)
{
    void *r = malloc(len ? len : 1);
    if (!r)
	xoom(0, len ? len : 1);
    return r;
}

void *pgprRealloc(void *old, size_t len)
{
    if (old == 0)
	old = malloc(len ? len : 1);
    else
	old = realloc(old, len ? len : 1);
    if (!old)
	xoom(0, len ? len : 1);
    return old;
}

void *pgprCalloc(size_t num, size_t len)
{
    void *r;
    if (num == 0 || len == 0)
	r = malloc(1);
    else
	r = calloc(num, len);
    if (!r)
	xoom(num, len ? len : 1);
    return r;
}

#endif
