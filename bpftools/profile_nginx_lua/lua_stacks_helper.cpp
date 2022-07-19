#include "lua_stacks_helper.h"
#include <map>

struct lua_stack_map
{
    std::map<int, struct stack_backtrace> map;
};

struct lua_stack_map *init_lua_stack_map(void)
{
    struct lua_stack_map *map = new lua_stack_map;
    return map;
}

void free_lua_stack_map(struct lua_stack_map *map)
{
    delete map;
}

int insert_lua_stack_map(struct lua_stack_map *map, const struct lua_stack_event *e)
{
    if (!e)
    {
        return -1;
    }
    auto it = map->map.find(e->user_stack_id);
    if (it == map->map.end())
    {
        struct stack_backtrace stack = {0};
        stack.stack[e->level] = *e;
        stack.level_size = e->level + 1;
        map->map[e->user_stack_id] = stack; // insert
        return 0;
    }
    struct stack_backtrace *stack = &it->second;
    if (e->level >= MAX_STACK_DEPTH)
    {
        return -1;
    }
    if (e->level >= stack->level_size)
    {
        stack->level_size = e->level + 1;
    }
    stack->stack[e->level] = *e;
    return 0;
}

// return the level of stack in the map
int get_lua_stack_backtrace(struct lua_stack_map *map, int user_stack_id, struct stack_backtrace *stack)
{
    auto it = map->map.find(user_stack_id);
    if (it == map->map.end())
    {
        *stack = {0};
        return -1;
    }
    *stack = it->second;
    return stack? stack->level_size:0;
}