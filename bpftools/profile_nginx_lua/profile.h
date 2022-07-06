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

// enum func_type {
// 	FUNC_TYPE_LUA,
// 	FUNC_TYPE_C,
// 	FUNC_TYPE_F,
// 	FUNC_TYPE_UNKNOWN,
// };

struct lua_stack_event
{
	unsigned int pid;
	int  user_stack_id;
	int  level;
	//enum func_type type;
	char name[HOST_LEN];
	//void *funcp;
	void *L;
};

#endif /* __PROFILE_H */
