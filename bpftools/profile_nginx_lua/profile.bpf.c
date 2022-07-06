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

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct lua_stack_event);
} starts_nginx SEC(".maps");

struct
{
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

static int fix_lua_stack(struct bpf_perf_event_data *ctx, __u32 tid, int stack_id)
{
	if (stack_id == 0)
	{
		return 0;
	}
	struct lua_stack_event *eventp;

	eventp = bpf_map_lookup_elem(&starts_nginx, &tid);
	if (!eventp)
		return 0;

	/* update time from timestamp to delta */
	// eventp->time = bpf_ktime_get_ns() - eventp->time;
	// bpf_perf_event_output(ctx, &events_nginx, BPF_F_CURRENT_CPU, eventp, sizeof(*eventp));
	eventp->user_stack_id = stack_id;
	lua_State *L = eventp->L;
	if (!L)
		return 0;

	// cTValue *frame = NULL;
	// int size;
	// frame = BPF_PROBE_READ_USER(L, base);
	// bpf_printk("perf get lua_state %p", L);
	// bpf_printk("L->status %d", BPF_PROBE_READ_USER(L, status));
	// bpf_printk("L->base %p. is lua %d, is varg %d", frame, frame_islua(frame), frame_isvarg(frame));
	// bpf_printk("L->stack %p", tvref(BPF_PROBE_READ_USER(L, stack)));
	// bpf_printk("L->stacksize %x", BPF_PROBE_READ_USER(L, stacksize));
	// bpf_printk("L->top %p", BPF_PROBE_READ_USER(L, top));
	// bpf_printk("L max stack %p.", tvref(BPF_PROBE_READ_USER(L, maxstack)));
	// bpf_printk("prevd frame %p.", frame_prevd(frame));
	// bpf_printk("prevl frame %p.\n", frame_prevl(frame));
	int level = 1, count = 0;

	cTValue *frame, *nextframe, *bot = tvref(BPF_PROBE_READ_USER(L, stack)) + LJ_FR2;
	int i = 0;
	frame = nextframe = BPF_PROBE_READ_USER(L, base) - 1;
	// bpf_printk("lj_debug_frame start: frame=%p, nextframe=%p, bot=%p\n", frame, nextframe, bot);
	/* Traverse frames backwards. */
	for (; i < 10 && frame > bot; i++)
	{
		// bpf_printk("loop %d\n", i);
		// bpf_printk("lj_debug_frame loop: frame=%p, nextframe=%p, bot=%p\n", frame, nextframe, bot);
		if (frame_gc(frame) == obj2gco(L))
		{
			// bpf_printk("frame_gc == obj2gco. Skip dummy frames. See lj_meta_call.\n");
			level++; /* Skip dummy frames. See lj_err_optype_call(). */
		}
		if (level-- == 0)
		{
			// *size = (nextframe - frame);
			// bpf_printk("Level found, frame=%p, nextframe=%p, bot=%p\n", frame, nextframe, bot);
			// bpf_printk("size=%d, frame=%p\n", size, frame);
			// return frame; /* Level found. */
			if (!frame)
				continue;
			GCfunc *fn = frame_func(frame);
			if (!fn)
				continue;
			// eventp->type = FUNC_TYPE_LUA;
			GCproto *pt = funcproto(fn);
			if (!pt)
				continue;
			GCstr *name = proto_chunkname(pt); /* GCstr *name */
			const char *src = strdata(name);
			if (!src)
				continue;
			bpf_probe_read_user_str(eventp->name, sizeof(eventp->name), src);
			bpf_printk("level= %d, fn_name=%s\n", i, eventp->name);
			// if (iscfunc(fn))
			// {
			// 	eventp->type = FUNC_TYPE_C;
			// 	eventp->funcp = BPF_PROBE_READ_USER(fn, c.f);
			// }
			// else if (isffunc(fn))
			// {
			// 	eventp->type = FUNC_TYPE_F;
			// 	eventp->funcp = (void *)BPF_PROBE_READ_USER(fn, c.ffid);
			// }
			eventp->level = count;
			bpf_perf_event_output(ctx, &events_nginx, BPF_F_CURRENT_CPU, eventp, sizeof(*eventp));
			level++;
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
	// bpf_map_update_elem(&lua_stack_bt, &stack_id, &stack_func, BPF_ANY);
	// frame = lj_debug_frame(L, 1, &size);
	// //bpf_printk("size=%d\n", size);
	// //lua_getinfo(L, i_ci);
	// GCfunc *fn = frame_func(frame);
	// bpf_printk("GCfunc %p\n", fn);
	// GCproto *pt = funcproto(fn);
	// bpf_printk("GCproto %p\n", pt);
	// GCstr *name = proto_chunkname(pt); /* GCstr *name */
	// const char *src = strdata(name);
	// char* fn_name[16];
	// bpf_probe_read_user_str(fn_name, sizeof(fn_name), src);
	// bpf_printk("fn_name=%s\n", src);
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

	fix_lua_stack(ctx, tid, key.user_stack_id);

	return 0;
}

static int probe_entry_nginx(struct pt_regs *ctx)
{
	if (!PT_REGS_PARM2(ctx))
		return 0;
	if (!PT_REGS_PARM4(ctx))
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	// struct lua_stack_event event = {};

	if (targ_pid != -1 && targ_pid != pid)
		return 0;
	// event.time = bpf_ktime_get_ns();
	// event.pid = pid;
	bpf_map_delete_elem(&starts_nginx, &tid);
	// bpf_get_current_comm(&event.comm, sizeof(event.comm));
	// bpf_probe_read_user(&event.name, sizeof(event.name), (void *)PT_REGS_PARM4(ctx));
	// event.L = (void *)PT_REGS_PARM2(ctx);
	// bpf_map_update_elem(&starts_nginx, &tid, &event, BPF_ANY);
	// bpf_perf_event_output(ctx, &events_nginx, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

SEC("kprobe/handle_entry_lua_cancel")
int handle_entry_lua_cancel(struct pt_regs *ctx)
{
	return probe_entry_nginx(ctx);
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
	// event.time = bpf_ktime_get_ns();
	event.pid = pid;
	// bpf_get_current_comm(&event.comm, sizeof(event.comm));
	event.L = (void *)PT_REGS_PARM1(ctx);
	// bpf_printk("lua_state %p\n", event.L);
	bpf_map_update_elem(&starts_nginx, &tid, &event, BPF_ANY);
	return 0;
}

SEC("kprobe/handle_entry_lua")
int handle_entry_lua(struct pt_regs *ctx)
{
	return probe_entry_lua(ctx);
}

char LICENSE[] SEC("license") = "GPL";
