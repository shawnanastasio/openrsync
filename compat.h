/*	$Id$ */
/*
 * Copyright (c) 2019 Shawn Anastasio <shawn@anastas.io>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * This file contains compatibility wrappers for functions not available
 * on non-OpenBSD systems.
 */

#ifndef COMPAT_H
#define COMPAT_H

/* Wrappers required on Linux systems */
#ifdef __linux__
#include <stddef.h>

#ifndef INFTIM
/* INFTIM is a non-portable macro for -1 */
#define INFTIM -1
#endif

/* Required for major()/minor() macros */
#include <sys/sysmacros.h>

/* Include TIMEVAL_TO_TIMESPEC's definition */
#include <bsd/sys/time.h>

/* libbsd's reallocarray(), etc. */
#include <bsd/stdlib.h>

/* libbsd's strlcpy(), etc. */
#include <bsd/string.h>

/* Implemented in linux.c */
void *
recallocarray(void *ptr, size_t oldnmemb, size_t nmemb, size_t size);

int
pledge(const char *promises, const char *execpromises);

int
unveil(const char *path, const char *permissions);

#endif /*__linux__*/

#endif /*!COMPAT_H*/
