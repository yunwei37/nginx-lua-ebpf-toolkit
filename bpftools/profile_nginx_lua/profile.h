/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef __PROFILE_H
#define __PROFILE_H

#define TASK_COMM_LEN 16
#define MAX_CPU_NR 128
#define MAX_ENTRIES 10240
#define HOST_LEN 80

struct key_t
{
	unsigned int pid;
	unsigned long long kernel_ip;
	int user_stack_id;
	int kern_stack_id;
	char name[TASK_COMM_LEN];
};

struct lua_stack_event
{
	unsigned int pid;
	int  user_stack_id;
	int  level;
	char name[HOST_LEN];
	void *L;
};

#endif /* __PROFILE_H */
