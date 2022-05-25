#include <string.h>

char *strcat(char *restrict dest, const char *restrict src)
{
	strcpy(dest + strlen(dest), src);
	return dest;
}


#include "printf.h"

#include <stdio.h>
#include <stdarg.h>


#include <string.h>
#include <stdint.h>
#include <limits.h>

#define ALIGN (sizeof(size_t))
#define ONES ((size_t)-1/UCHAR_MAX)
#define HIGHS (ONES * (UCHAR_MAX/2+1))
#define HASZERO(x) ((x)-ONES & ~(x) & HIGHS)

char *__stpcpy(char *restrict d, const char *restrict s)
{
	size_t *wd;
	const size_t *ws;

	if ((uintptr_t)s % ALIGN == (uintptr_t)d % ALIGN) {
		for (; (uintptr_t)s % ALIGN; s++, d++)
			if (!(*d=*s)) return d;
		wd=(void *)d; ws=(const void *)s;
		for (; !HASZERO(*ws); *wd++ = *ws++);
		d=(void *)wd; s=(const void *)ws;
	}
	for (; (*d=*s); s++, d++);

	return d;
}

/* weak_alias(__stpcpy, stpcpy); */

char *__stpcpy(char *, const char *);

char *strcpy(char *restrict dest, const char *restrict src)
{
#if 1
	__stpcpy(dest, src);
	return dest;
#else
	const unsigned char *s = src;
	unsigned char *d = dest;
	while ((*d++ = *s++));
	return dest;
#endif
}


/* int vsprintf(char *restrict s, const char *restrict fmt, va_list ap) */
/* { */
/* 	return vsnprintf(s, INT_MAX, fmt, ap); */
/* } */
