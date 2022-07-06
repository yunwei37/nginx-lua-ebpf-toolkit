#ifndef LUA_STACKS_HELPER_H
#define LUA_STACKS_HELPER_H

#define MAX_STACK_DEPTH 64

#include "profile.h"

#ifdef __cplusplus
extern "C"
{
#endif

    struct stack_backtrace
    {
        int level_size;
        struct lua_stack_event stack[MAX_STACK_DEPTH];
    };

    struct lua_stack_map;

    struct lua_stack_map *init_lua_stack_map(void);
    void free_lua_stack_map(struct lua_stack_map *map);
    int insert_lua_stack_map(struct lua_stack_map *map, const struct lua_stack_event *event);
    int get_lua_stack_backtrace(struct lua_stack_map *map, int user_stack_id, struct stack_backtrace *stack);

#ifdef __cplusplus
}
#endif

#endif