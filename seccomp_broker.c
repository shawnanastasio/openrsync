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
 * seccomp-bpf broker process implementation (Linux only).
 *
 * Due to the limitations of seccomp-bpf, it's not possible to express
 * many rules directly in filters. Instead, the relevant syscalls must be
 * trapped and emulated.
 *
 * This approach uses a broker process that gets spawned /before/ the sandbox
 * is created and therefore has no restrictions placed on it. For syscalls
 * that can't be done in bpf, they are sent over an AF_UNIX socket pair to
 * the broker so that it can perform the syscall and send the result back.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <syscall.h>

#include <unistd.h>
#include <syscall.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "compat.h"
#include "seccomp_broker.h"

/*
 * Send a broker message
 * socfd - recipient
 * data  - (optional) content of message
 * len   - length of data
 * fd    - (optional) file descriptor to send (SCM_RIGHTS)
 *
 * return - bytes sent, or -1 on error
 */
ssize_t
broker_send(int socfd, void *data, size_t len, int fd)
{
	union {
		char cmsgbuf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} u;

	struct cmsghdr *cmsg;
	struct iovec iov = { .iov_base = data, .iov_len = len };
	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_flags = 0,
		.msg_control = (fd > 0) ? u.cmsgbuf : NULL,
		.msg_controllen = (fd > 0) ? CMSG_LEN(sizeof(int)) : 0,
	};

	/* Initialize the control message to hand off the fd */
	if (fd > 0) {
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		*(int *)CMSG_DATA(cmsg) = fd;
	}

	return sendmsg(socfd, &msg, 0);
}

ssize_t
broker_recv(int socfd, void *buf, size_t len, int *fd_out)
{
	ssize_t s;
	union {
		char cmsgbuf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} u;

	struct cmsghdr *cmsg;
	struct iovec iov = { .iov_base = buf, .iov_len = len };
	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_flags = 0,
		.msg_control = u.cmsgbuf,
		.msg_controllen = CMSG_LEN(sizeof(int))
	};

	if ((s = recvmsg(socfd, &msg, 0)) < 0)
		return s;

	if (fd_out) {
		cmsg = CMSG_FIRSTHDR(&msg);
		if (!cmsg || cmsg->cmsg_len != CMSG_LEN(sizeof(int)))
			return -1;

		*fd_out = *((int *)CMSG_DATA(cmsg));
	}

	return s;
}

static void
broker_abort(void)
{
	_exit(1);
}

void
emulate_syscall(int socfd, struct syscall_info *info)
{
	struct broker_msg bmsg = { .type = BROKER_MTYPE_SYSCALL };
	struct syscall_resp *resp = &bmsg.syscall;
	int respfd = -1;
	switch (info->nr) {
	case __NR_socket:
	{
		/* TODO: Check AF */
		int fd = socket(info->args[0], info->args[1], info->args[2]);
		if (fd < 0)
			goto out_errno;

		resp->flags = RESP_FLAG_FD;
		respfd = fd;
		goto out;
	}

	}

out_errno:
	fprintf(stderr, "broker: syscall failed: %m\n");
	resp->flags = RESP_FLAG_ERR;
	resp->result = errno;
out:
	if (broker_send(socfd, &bmsg, sizeof(struct broker_msg), respfd) < 0) {
		fprintf(stderr, "broker: Failed to send response!\n");
		broker_abort();
	}
}

void
broker_entry(int socfd)
{
	/* Broker event loop */
	for(;;) {
		struct client_msg msg;
		if (broker_recv(socfd, &msg, sizeof(struct client_msg), NULL) < 0) {
			fprintf(stderr, "broker: Failed to recieve client message!\n");
			broker_abort();
		}

		switch (msg.type) {
		case CLIENT_MTYPE_SYSCALL:
			emulate_syscall(socfd, &msg.syscall);
			break;

		default:
			fprintf(stderr, "broker: Unknown message type recieved!\n");
			broker_abort();
		}

	}
}


