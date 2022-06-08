# Apache APISIX profile 工具

## 项目产出要求：

使用eBPF捕获和解析 `Apache APISIX` 中的 lua 调用堆栈信息，对其进行汇总并生成cpu火焰图：
- 利用eBPF同时捕获和解析C和Lua混合调用堆栈信息，对其进行总结，生成cpu火焰图。
- 支持获取在Docker中运行的 `Apache APISIX` 进程
- 支持获取 Apache APISIX Openresty luajit 32/luajit 64 模式

## 项目完成进度


- [X] 获取 docker 中运行的 APISIX 和 Openresty / nginx 进程 PID `2022/05`
- [X] 利用 ebpf/BCC 生成火焰图 `2022/05`
- [X] 利用 libbpf 生成 Openresty/nginx/lua 火焰图 `2022/06/04`
- [X] 在 libbpf 中利用 uprobe 获取 lua status 堆栈信息 `2022/06/08`
- [X] 在 profile 的同时获取 lua status stack trace 信息
- [ ] 把得到的函数信息在最后生成火焰图的时候和原先的 c 函数信息综合起来
- [ ] 整理工具

## probe nginx lua

see: bpftools/profile_nginx_lua/profile.bpf.c

to get stack frame of lua:

this is nearly the same sa `lj_debug_frame` func in `lj_debug.c` from luajit source code
```c
/* Get frame corresponding to a level. */
static cTValue * lj_debug_frame(lua_State *L, int level, int *size)
{
	cTValue *frame, *nextframe, *bot = tvref(BPF_PROBE_READ_USER(L, stack)) + LJ_FR2;

	int i = 0;
	frame = nextframe = BPF_PROBE_READ_USER(L, base) - 1;
	/* Traverse frames backwards. */
	for (; i < 10 && frame > bot; i++)
	{
		if (frame_gc(frame) == obj2gco(L))
		{
			level++; /* Skip dummy frames. See lj_err_optype_call(). */
		}
		if (level-- == 0)
		{
			*size = (nextframe - frame);
			bpf_printk("Level found, frame=%p, nextframe=%p, bot=%p\n", frame, nextframe, bot);
			return frame; /* Level found. */
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
	*size = level;
	return NULL; /* Level not found. */
}
```

to print function name of lua:
```c
	for (int i = 1; i < 15; ++i) {
		frame = lj_debug_frame(L, i, &size);
		if (!frame)
			continue;
		GCfunc *fn = frame_func(frame);
		if (!fn)
			continue;
		GCproto *pt = funcproto(fn);
		if (!pt)
			continue;
		GCstr *name = proto_chunkname(pt); /* GCstr *name */
		const char *src = strdata(name);
		if (!src)
			continue;
		char* fn_name[16];
		bpf_probe_read_user_str(fn_name, sizeof(fn_name), src);
		bpf_printk("level= %d, fn_name=%s\n", i, src);
	}
```

note the loop counter here is smaller because of ebpf verifier. Maybe we can optimize it in the future, it's a O(n^2) nested loop.

reference:

```c
LJ_FUNC void lj_debug_dumpstack(lua_State *L, SBuf *sb, const char *fmt,
				int depth);
```

in `lj_debug.h` and `lj_debug.c` from luajit source code: `openresty-1.21.4.1/build/LuaJIT-2.1-20220411/src/lj_debug.h`  

and:

- https://github.com/api7/stapxx/blob/master/tapset/luajit_gc64.sxx
- https://github.com/openresty/openresty-systemtap-toolkit/blob/master/ngx-sample-lua-bt

### to run:

for lua struct defination, see: `bpftools/profile_nginx_lua/lua_state.h`, it's copied from luajit headers.

we can determine the luajit 32/64 from:

bpftools/profile_nginx_lua/lua_state.h:9
```c
#define LJ_TARGET_GC64 1
```

Note currently this is hardcoded in `bpftools/profile_nginx_lua/profile.c`:

bpftools/profile_nginx_lua/profile.c:569
```c
char *nginx_path = "/usr/local/openresty/nginx/sbin/nginx";
char *lua_path = "/usr/local/openresty/luajit/lib/libluajit-5.1.so.2.1.0";
```

this is used for uprobe to find function offset.

the openresty used and tested is from `https://openresty.org/en/benchmark.html`

## run nginx prob

sudo /usr/bin/python /home/yunwei/coding/ebpf/nginx_uprobe.py

## openresty

basic benchmark：

- https://openresty.org/en/getting-started.html
- https://openresty.org/en/benchmark.html

```
cd ~/work
PATH=/usr/local/openresty/nginx/sbin:$PATH
export PATH
nginx -p `pwd`/ -c conf/nginx.conf
```

```
curl http://localhost:8080/
```

## ebpf for uprobe

- https://blog.csdn.net/github_36774378/article/details/112259337 聊聊风口上的 eBPF
- https://cloud.tencent.com/developer/article/1037840 openresty源码剖析——lua代码的加载
- http://www.javashuo.com/article/p-wqgnoodo-kn.html 经过lua栈了解lua与c的交互
- https://ty-chen.github.io/lua-vm-md/
