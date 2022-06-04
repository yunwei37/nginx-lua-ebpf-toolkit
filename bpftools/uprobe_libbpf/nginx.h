/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __nginx_H
#define __nginx_H

#define TASK_COMM_LEN 16
#define HOST_LEN 80

struct event
{
	__u64 time;
	__u32 pid;
	char comm[TASK_COMM_LEN];
	char host[HOST_LEN];
};

#endif /* __nginx_H */
