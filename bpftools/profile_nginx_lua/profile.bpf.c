/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2022 LG Electronics */
#include "lua_debug.h"
#include "profile.h"
#include "maps.bpf.h"

const volatile bool kernel_stacks_only = false;
const volatile bool user_stacks_only = false;
const volatile bool include_idle = false;
const volatile pid_t targ_pid = -1;
const volatile pid_t targ_tid = -1;

struct
{
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
} stackmap SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct key_t);
	__type(value, sizeof(u64));
	__uint(max_entries, MAX_ENTRIES);
} counts SEC(".maps");

#define MAX_ENTRIES 10240

// for collecting lua stack trace function name
// and pass the pointer of Lua_state to perf event
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct lua_stack_event);
} lua_events SEC(".maps");

// output the lua stack to user space because we cannot keep all of them in
// ebpf maps
struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} lua_event_output SEC(".maps");

/*
 * If PAGE_OFFSET macro is not available in vmlinux.h, determine ip whose MSB
 * (Most Significant Bit) is 1 as the kernel address.
 * TODO: use end address of user space to determine the address space of ip
 */
#if defined(__TARGET_ARCH_arm64) || defined(__TARGET_ARCH_x86)
#define BITS_PER_ADDR (64)
#define MSB_SET_ULONG (1UL << (BITS_PER_ADDR - 1))
static __always_inline bool is_kernel_addr(u64 addr)
{
	return !!(addr & MSB_SET_ULONG);
}
#else
static __always_inline bool is_kernel_addr(u64 addr)
{
	return false;
}
#endif /* __TARGET_ARCH_arm64 || __TARGET_ARCH_x86 */

static inline int lua_get_funcdata(struct bpf_perf_event_data *ctx, cTValue *frame, struct lua_stack_event *eventp, int level)
{
	if (!frame)
		return -1;
	GCfunc *fn = frame_func(frame);
	if (!fn)
		return -1;
	if (isluafunc(fn))
	{
		eventp->type = FUNC_TYPE_LUA;
		GCproto *pt = funcproto(fn);
		if (!pt)
			return -1;
		eventp->ffid = BPF_PROBE_READ_USER(pt, firstline);
		GCstr *name = proto_chunkname(pt); /* GCstr *name */
		const char *src = strdata(name);
		if (!src)
			return -1;
		bpf_probe_read_user_str(eventp->name, sizeof(eventp->name), src);
		bpf_printk("level= %d, fn_name=%s\n", level, eventp->name);
	}
	else if (iscfunc(fn))
	{
		eventp->type = FUNC_TYPE_C;
		eventp->funcp = BPF_PROBE_READ_USER(fn, c.f);
	}
	else if (isffunc(fn))
	{
		eventp->type = FUNC_TYPE_F;
		eventp->ffid = BPF_PROBE_READ_USER(fn, c.ffid);
	}
	eventp->level = level;
	bpf_perf_event_output(ctx, &lua_event_output, BPF_F_CURRENT_CPU, eventp, sizeof(*eventp));
	return 0;
}

static int fix_lua_stack(struct bpf_perf_event_data *ctx, __u32 tid, int stack_id)
{
	if (stack_id == 0)
	{
		return 0;
	}
	struct lua_stack_event *eventp;

	eventp = bpf_map_lookup_elem(&lua_events, &tid);
	if (!eventp)
		return 0;

	eventp->user_stack_id = stack_id;
	lua_State *L = eventp->L;
	if (!L)
		return 0;

	// start from the top of the stack and trace back
	// count the number of function calls founded
	int level = 1, count = 0;

	cTValue *frame, *nextframe, *bot = tvref(BPF_PROBE_READ_USER(L, stack)) + LJ_FR2;
	int i = 0;
	frame = nextframe = BPF_PROBE_READ_USER(L, base) - 1;
	/* Traverse frames backwards. */
	// for the ebpf verifier insns (limit 1000000), we need to limit the max loop times to 12
	for (; i < 12 && frame > bot; i++)
	{
		if (frame_gc(frame) == obj2gco(L))
		{
			level++; /* Skip dummy frames. See lj_err_optype_call(). */
		}
		if (level-- == 0)
		{
			level++;
			// *size = (nextframe - frame);
			/* Level found. */
			if (lua_get_funcdata(ctx, frame, eventp, count) != 0)
			{
				continue;
			}
			count++;
		}
		nextframe = frame;
		if (frame_islua(frame))
		{
			frame = frame_prevl(frame);
		}
		else
		{
			if (frame_isvarg(frame))
				level++; /* Skip vararg pseudo-frame. */
			frame = frame_prevd(frame);
		}
	}
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

	if (key.kern_stack_id >= 0)
	{
		// populate extras to fix the kernel stack
		__u64 ip = PT_REGS_IP(&ctx->regs);

		if (is_kernel_addr(ip))
		{
			key.kernel_ip = ip;
		}
	}

	valp = bpf_map_lookup_or_try_init(&counts, &key, &zero);
	if (valp)
		__sync_fetch_and_add(valp, 1);

	if (!valp || *valp <= 1)
	{
		// only get lua stack the first time
		fix_lua_stack(ctx, tid, key.user_stack_id);
	}
	return 0;
}

static int probe_entry_lua_cancel(struct pt_regs *ctx)
{
	if (!PT_REGS_PARM2(ctx))
		return 0;
	if (!PT_REGS_PARM4(ctx))
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	if (targ_pid != -1 && targ_pid != pid)
		return 0;
	bpf_map_delete_elem(&lua_events, &tid);
	return 0;
}

SEC("kprobe/handle_entry_lua_cancel")
int handle_entry_lua_cancel(struct pt_regs *ctx)
{
	return probe_entry_lua_cancel(ctx);
}

static int probe_entry_lua(struct pt_regs *ctx)
{
	if (!PT_REGS_PARM1(ctx))
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct lua_stack_event event = {};

	if (targ_pid != -1 && targ_pid != pid)
		return 0;

	event.pid = pid;
	event.L = (void *)PT_REGS_PARM1(ctx);
	bpf_map_update_elem(&lua_events, &tid, &event, BPF_ANY);
	return 0;
}

SEC("kprobe/handle_entry_lua")
int handle_entry_lua(struct pt_regs *ctx)
{
	return probe_entry_lua(ctx);
}

char LICENSE[] SEC("license") = "GPL";
