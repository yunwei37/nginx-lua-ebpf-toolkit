#ifndef __LUA_STATE_H
#define __LUA_STATE_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define LJ_TARGET_GC64		1

/* 64 bit GC references. */
#if LJ_TARGET_GC64
#define LJ_GC64			1
#else
#define LJ_GC64			0
#endif

/* GCobj reference */
typedef struct GCRef {
#if LJ_GC64
  uint64_t gcptr64;	/* True 64 bit pointer. */
#else
  uint32_t gcptr32;	/* Pseudo 32 bit pointer. */
#endif
} GCRef;

/* 2-slot frame info. */
#if LJ_GC64
#define LJ_FR2			1
#else
#define LJ_FR2			0
#endif

/* Common GC header for all collectable objects. */
#define GCHeader	GCRef nextgc; uint8_t marked; uint8_t gct
/* This occupies 6 bytes, so use the next 2 bytes for non-32 bit fields. */

/* Memory reference */
typedef struct MRef {
#if LJ_GC64
  uint64_t ptr64;	/* True 64 bit pointer. */
#else
  uint32_t ptr32;	/* Pseudo 32 bit pointer. */
#endif
} MRef;

#define LJ_ALIGN(n)	__attribute__((aligned(n)))

#define LUA_NUMBER		double

/* type of numbers in Lua */
typedef LUA_NUMBER lua_Number;

#if LJ_ARCH_ENDIAN == LUAJIT_BE
#define LJ_LE			0
#define LJ_BE			1
#define LJ_ENDIAN_SELECT(le, be)	be
#define LJ_ENDIAN_LOHI(lo, hi)		hi lo
#else
#define LJ_LE			1
#define LJ_BE			0
#define LJ_ENDIAN_SELECT(le, be)	le
#define LJ_ENDIAN_LOHI(lo, hi)		lo hi
#endif

/* Tagged value. */
typedef LJ_ALIGN(8) union TValue {
  uint64_t u64;		/* 64 bit pattern overlaps number. */
  lua_Number n;		/* Number object overlaps split tag/value object. */
#if LJ_GC64
  GCRef gcr;		/* GCobj reference with tag. */
  int64_t it64;
  struct {
    LJ_ENDIAN_LOHI(
      int32_t i;	/* Integer value. */
    , uint32_t it;	/* Internal object tag. Must overlap MSW of number. */
    )
  };
#else
  struct {
    LJ_ENDIAN_LOHI(
      union {
	GCRef gcr;	/* GCobj reference (if any). */
	int32_t i;	/* Integer value. */
      };
    , uint32_t it;	/* Internal object tag. Must overlap MSW of number. */
    )
  };
#endif
#if LJ_FR2
  int64_t ftsz;		/* Frame type and size of previous frame, or PC. */
#else
  struct {
    LJ_ENDIAN_LOHI(
      GCRef func;	/* Function for next frame (or dummy L). */
    , FrameLink tp;	/* Link to previous frame. */
    )
  } fr;
#endif
  struct {
    LJ_ENDIAN_LOHI(
      uint32_t lo;	/* Lower 32 bits of number. */
    , uint32_t hi;	/* Upper 32 bits of number. */
    )
  } u32;
} TValue;

/* Memory and GC object sizes. */
typedef uint32_t MSize;
#if LJ_GC64
typedef uint64_t GCSize;
#else
typedef uint32_t GCSize;
#endif

/* Per-thread state object. */
struct lua_State {
  GCHeader;
  uint8_t dummy_ffid;	/* Fake FF_C for curr_funcisL() on dummy frames. */
  uint8_t status;	/* Thread status. */
  MRef glref;		/* Link to global state. */
  GCRef gclist;		/* GC chain. */
  TValue *base;		/* Base of currently executing function. */
  TValue *top;		/* First free slot in the stack. */
  MRef maxstack;	/* Last free slot in the stack. */
  MRef stack;		/* Stack base. */
  GCRef openupval;	/* List of open upvalues in the stack. */
  GCRef env;		/* Thread environment (table of globals). */
  void *cframe;		/* End of C stack frame chain. */
  MSize stacksize;	/* True stack size (incl. LJ_STACK_EXTRA). */
  void *exdata;	        /* user extra data pointer. added by OpenResty */
  void *exdata2;	/* the 2nd user extra data pointer. added by OpenResty */
#if LJ_TARGET_ARM
  uint32_t unused1;
  uint32_t unused2;
#endif
};



#endif