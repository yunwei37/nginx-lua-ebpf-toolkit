/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef __PROFILE_H
#define __PROFILE_H

#define TASK_COMM_LEN		16
#define MAX_CPU_NR		128
#define MAX_ENTRIES		10240
#define HOST_LEN 80

struct key_t {
	__u32 pid;
	__u64 kernel_ip;
	int user_stack_id;
	int kern_stack_id;
	char name[TASK_COMM_LEN];
};

struct nginx_event
{
	__u64 time;
	__u32 pid;
	char name[HOST_LEN];
	void *L;
};

struct lua_stack_func
{
	__u64 ip;
	__u8 deepth;
	char name[16][16];
};

#endif /* __PROFILE_H */
