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
 * Definitions for structures and functions in seccomp_broker.h.
 * Linux only.
 */

#ifndef SECCOMP_BROKER_H
#define SECCOMP_BROKER_H

#include <stdint.h>

struct syscall_info {
	int nr;
	uint64_t args[6];
};

/* A message sent to the broker from the client */
struct client_msg {
	uint8_t type;
#define CLIENT_MTYPE_SYSCALL 0 /* A forwarded syscall */

	union {
		struct syscall_info syscall;
	};
};

struct syscall_resp {
	uint8_t flags;
#define RESP_FLAG_ERR (1 << 0) /* The syscall was emulated but failed */
#define RESP_FLAG_FD  (1 << 1) /* A file descriptor was returned */

	/* The value in the result register */
	uint64_t result;
};

/* A message sent to the client from the broker */
struct broker_msg {
	uint8_t type;
#define BROKER_MTYPE_SYSCALL 0 /* The response for a forwarded syscall */

	union {
		struct syscall_resp syscall;
	};
};

ssize_t
broker_recv(int socfd, void *buf, size_t len, int *fd_out);

ssize_t
broker_send(int socfd, void *data, size_t len, int fd);

void
broker_entry(int socfd);

#endif /*!SECCOMP_BROKER_H*/
