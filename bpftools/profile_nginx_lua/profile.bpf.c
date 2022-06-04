/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2022 LG Electronics */
#include "lua_state.h"
#include "profile.h"
#include "maps.bpf.h"

const volatile bool kernel_stacks_only = false;
const volatile bool user_stacks_only = false;
const volatile bool include_idle = false;
const volatile pid_t targ_pid = -1;
const volatile pid_t targ_tid = -1;

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
} stackmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct key_t);
	__type(value, sizeof(u64));
	__uint(max_entries, MAX_ENTRIES);
} counts SEC(".maps");

#define MAX_ENTRIES	10240

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct nginx_event);
} starts_nginx SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events_nginx SEC(".maps");

/*
 * If PAGE_OFFSET macro is not available in vmlinux.h, determine ip whose MSB
 * (Most Significant Bit) is 1 as the kernel address.
 * TODO: use end address of user space to determine the address space of ip
 */
#if defined(__TARGET_ARCH_arm64) || defined(__TARGET_ARCH_x86)
#define BITS_PER_ADDR	(64)
#define MSB_SET_ULONG	(1UL << (BITS_PER_ADDR - 1))
static __always_inline
bool is_kernel_addr(u64 addr)
{
	return !!(addr & MSB_SET_ULONG);
}
#else
static __always_inline
bool is_kernel_addr(u64 addr)
{
	return false;
}
#endif /* __TARGET_ARCH_arm64 || __TARGET_ARCH_x86 */

static int fix_lua_stack(struct bpf_perf_event_data *ctx, __u32 tid)
{
	struct nginx_event *eventp;

	eventp = bpf_map_lookup_elem(&starts_nginx, &tid);
	if (!eventp)
		return 0;
	/* update time from timestamp to delta */
	eventp->time = bpf_ktime_get_ns() - eventp->time;
	bpf_perf_event_output(ctx, &events_nginx, BPF_F_CURRENT_CPU, eventp, sizeof(*eventp));

	lua_State *L = eventp->L;
	int size = 0;
	cTValue *ctv = lj_debug_frame(L, 1, &size);
	//bpf_map_delete_elem(&starts_nginx, &tid);
	return 0;
}


SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 pid = id >> 32;
	__u32 tid = id;
	__u64 *valp;
	static const __u64 zero;
	struct key_t key = {};

	if (!include_idle && tid == 0)
		return 0;

	if (targ_pid != -1 && targ_pid != pid)
		return 0;
	if (targ_tid != -1 && targ_tid != tid)
		return 0;

	key.pid = pid;
	bpf_get_current_comm(&key.name, sizeof(key.name));

	if (user_stacks_only)
		key.kern_stack_id = -1;
	else
		key.kern_stack_id = bpf_get_stackid(&ctx->regs, &stackmap, 0);

	if (kernel_stacks_only)
		key.user_stack_id = -1;
	else
		key.user_stack_id = bpf_get_stackid(&ctx->regs, &stackmap, BPF_F_USER_STACK);

	if (key.kern_stack_id >= 0) {
		// populate extras to fix the kernel stack
		__u64 ip = PT_REGS_IP(&ctx->regs);

		if (is_kernel_addr(ip)) {
		    key.kernel_ip = ip;
		}
	}

	valp = bpf_map_lookup_or_try_init(&counts, &key, &zero);
	if (valp)
		__sync_fetch_and_add(valp, 1);

	fix_lua_stack(ctx, tid);

	return 0;
}


static int probe_entry_lua(struct pt_regs *ctx)
{
	if (!PT_REGS_PARM1(ctx))
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct nginx_event event = {};

	if (targ_pid != -1 && targ_pid != pid)
		return 0;

	event.time = bpf_ktime_get_ns();
	event.pid = pid;
	//bpf_get_current_comm(&event.comm, sizeof(event.comm));
	//bpf_probe_read_user(&event.host, sizeof(event.host), (void *)PT_REGS_PARM4(ctx));
	event.L = (void *)PT_REGS_PARM1(ctx);
	bpf_map_update_elem(&starts_nginx, &tid, &event, BPF_ANY);
	//bpf_perf_event_output(ctx, &events_nginx, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

SEC("kprobe/handle_entry_lua")
int handle_entry_lua(struct pt_regs *ctx)
{
	return probe_entry_lua(ctx);
}


char LICENSE[] SEC("license") = "GPL";
