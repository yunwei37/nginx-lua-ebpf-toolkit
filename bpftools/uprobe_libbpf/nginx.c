/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * nginx  Show latency for getaddrinfo/gethostbyname[2] calls.
 *
 * Copyright (c) 2021 Hengqi Chen
 *
 * Based on nginx(8) from BCC by Brendan Gregg.
 * 24-Mar-2021   Hengqi Chen   Created this.
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "nginx.h"
#include "nginx.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

static pid_t target_pid = 0;
static const char *libc_path = NULL;
static bool verbose = false;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

static void handle_nginx_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[16];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	printf("%-8s %-7d %-16s %-10.3f %-s\n",
	       ts, e->pid, e->comm, (double)e->time/1000000, e->host);
}

static void handle_nginx_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

static int attach_uprobes(struct nginx_bpf *obj, struct bpf_link *links[])
{
	int err;
	char *nginx_path = "/usr/local/openresty/nginx/sbin/nginx";

	off_t func_off = get_elf_func_offset(nginx_path, "ngx_http_lua_cache_load_code");
	if (func_off < 0) {
		warn("could not find getaddrinfo in %s\n", nginx_path);
		return -1;
	}
	links[0] = bpf_program__attach_uprobe(obj->progs.handle_entry_lua, false,
					      target_pid ?: -1, nginx_path, func_off);
	if (!links[0]) {
		warn("failed to attach getaddrinfo: %d\n", -errno);
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	struct perf_buffer *pb = NULL;
	struct bpf_link *links[6] = {};
	struct nginx_bpf *obj;
	int i, err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = nginx_bpf__open_opts(&open_opts);
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = target_pid;

	err = nginx_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = attach_uprobes(obj, links);
	if (err)
		goto cleanup;

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events_nginx), PERF_BUFFER_PAGES,
			      handle_nginx_event, handle_nginx_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("%-8s %-7s %-16s %-10s %-s\n",
	       "TIME", "PID", "COMM", "LATms", "HOST");

	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warn("error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	for (i = 0; i < 2; i++)
		bpf_link__destroy(links[i]);
	nginx_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}