#ifndef LUA_DEBUG_H
#define LUA_DEBUG_H

#include "lua_state.h"

/*

static size_t lj_debug_frame(lua_State *L, int level)
{
  cTValue *frame, *nextframe, *bot = tvref(L->stack) + LJ_FR2;
  int size;

  int i = 0;
  bpf_probe_read_user(&nextframe, sizeof(nextframe), &L->base);
  bpf_probe_read_user(&frame, sizeof(nextframe), &L->base);
  for (;i <10 && frame > bot; i++)
  {
    if (frame_gc(frame) == obj2gco(L))
      level++;

    if (level-- == 0)
    {
      size = (int)(nextframe - frame);
      size_t i_ci = ((size << 16) + (frame - bot)) / sizeof(TValue);
      return i_ci;
    }
    nextframe = frame;
    if (frame_islua(frame))
    {
      frame = frame_prevl(frame);
    }
    else
    {
      if (frame_isvarg(frame))
        level++; 
      frame = frame_prevd(frame);
    }
  }
  return 0;
}

*/

#endif