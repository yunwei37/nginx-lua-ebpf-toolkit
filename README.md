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
- [X] 在 libbpf 中利用 uprobe 获取 lua status 堆栈信息 `2022/06/04`
- [ ] 在 profile 的同时修复 lua status stack trace 信息
- [ ] 整理工具

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

## lua

```
function lua_getstack(L, level) {
    ci = \@cast(L, "lua_State", "$lua_path")->ci
    base_ci = \@cast(L, "lua_State", "$lua_path")->base_ci
    //printf("L=%x, ci=%x, base_ci=%x\\n", L, ci, base_ci)
    if (ci_offset == 0) {
        ci_offset = &\@cast(0, "CallInfo", "$lua_path")[1]
    }
    //printf("ci offset: %d\\n", ci_offset)
    for (; level > 0 && ci > base_ci; ci -= ci_offset) {
        level--;
        //tt = \@cast(ci, "CallInfo", "$lua_path")->func->tt
        //printf("ci tt: %d\\n", tt)
        if (f_isLua(ci)) { /* Lua function? */
            tailcalls = \@cast(ci, "CallInfo", "$lua_path")->tailcalls
            //printf("it is a lua func! tailcalls=%d\\n", tailcalls)
            level -= tailcalls;  /* skip lost tail calls */
        }
    }
    if (level == 0 && ci > base_ci) {  /* level found? */
        //printf("lua_getstack: ci=%x\\n", ci);
        //tt = \@cast(ci, "CallInfo", "$lua_path")->func->tt
        //printf("ci tt: %d\\n", tt)
        //ff = &\@cast(ci, "CallInfo", "$lua_path")->func->value->gc->cl
        //isC = \@cast(ci, "CallInfo", "$lua_path")->func->value->gc->cl->c->isC
        //printf("isC: %d, %d ff=%x\\n", isC, \@cast(ff, "Closure", "$lua_path")->c->isC, ff)
        //f = ci_func(ci)
        //printf("lua_getstack: ci=%x, f=%x, isLua=%d\\n", ci, f, f_isLua(ci));
        return ci - base_ci;
    }
    if (level < 0) {  /* level is of a lost tail call? */
        return 0;
    }
    return -1;
}

```

## ebpf for uprobe

- https://blog.csdn.net/github_36774378/article/details/112259337 聊聊风口上的 eBPF
- https://cloud.tencent.com/developer/article/1037840 openresty源码剖析——lua代码的加载
- http://www.javashuo.com/article/p-wqgnoodo-kn.html 经过lua栈了解lua与c的交互
- https://ty-chen.github.io/lua-vm-md/
