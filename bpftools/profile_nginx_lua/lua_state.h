#ifndef __LUA_STATE_H
#define __LUA_STATE_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define LJ_TARGET_GC64 1

/* 64 bit GC references. */
#if LJ_TARGET_GC64
#define LJ_GC64 1
#else
#define LJ_GC64 0
#endif

/* GCobj reference */
typedef struct GCRef
{
#if LJ_GC64
  uint64_t gcptr64; /* True 64 bit pointer. */
#else
  uint32_t gcptr32; /* Pseudo 32 bit pointer. */
#endif
} GCRef;

/* 2-slot frame info. */
#if LJ_GC64
#define LJ_FR2 1
#else
#define LJ_FR2 0
#endif


/* Optional defines. */
#ifndef LJ_FASTCALL
#define LJ_FASTCALL
#endif
#ifndef LJ_NORET
#define LJ_NORET
#endif
#ifndef LJ_NOAPI
#define LJ_NOAPI	extern
#endif
#ifndef LJ_LIKELY
#define LJ_LIKELY(x)	(x)
#define LJ_UNLIKELY(x)	(x)
#endif

/* Attributes for internal functions. */
#define LJ_DATA		LJ_NOAPI
#define LJ_DATADEF
#define LJ_ASMF		LJ_NOAPI
#define LJ_FUNCA	LJ_NOAPI
#if defined(ljamalg_c)
#define LJ_FUNC		static
#else
#define LJ_FUNC		LJ_NOAPI
#endif
#define LJ_FUNC_NORET	LJ_FUNC LJ_NORET
#define LJ_FUNCA_NORET	LJ_FUNCA LJ_NORET
#define LJ_ASMF_NORET	LJ_ASMF LJ_NORET

/* Internal assertions. */
#if defined(LUA_USE_ASSERT) || defined(LUA_USE_APICHECK)
#define lj_assert_check(g, c, ...) \
  ((c) ? (void)0 : \
   (lj_assert_fail((g), __FILE__, __LINE__, __func__, __VA_ARGS__), 0))
#define lj_checkapi(c, ...)	lj_assert_check(G(L), (c), __VA_ARGS__)
#else
#define lj_checkapi(c, ...)	((void)L)
#endif

#ifdef LUA_USE_ASSERT
#define lj_assertG_(g, c, ...)	lj_assert_check((g), (c), __VA_ARGS__)
#define lj_assertG(c, ...)	lj_assert_check(g, (c), __VA_ARGS__)
#define lj_assertL(c, ...)	lj_assert_check(G(L), (c), __VA_ARGS__)
#define lj_assertX(c, ...)	lj_assert_check(NULL, (c), __VA_ARGS__)
#define check_exp(c, e)		(lj_assertX((c), #c), (e))
#else
#define lj_assertG_(g, c, ...)	((void)0)
#define lj_assertG(c, ...)	((void)g)
#define lj_assertL(c, ...)	((void)L)
#define lj_assertX(c, ...)	((void)0)
#define check_exp(c, e)		(e)
#endif

/* Static assertions. */
#define LJ_ASSERT_NAME2(name, line)	name ## line
#define LJ_ASSERT_NAME(line)		LJ_ASSERT_NAME2(lj_assert_, line)
#ifdef __COUNTER__
#define LJ_STATIC_ASSERT(cond) \
  extern void LJ_ASSERT_NAME(__COUNTER__)(int STATIC_ASSERTION_FAILED[(cond)?1:-1])
#else
#define LJ_STATIC_ASSERT(cond) \
  extern void LJ_ASSERT_NAME(__LINE__)(int STATIC_ASSERTION_FAILED[(cond)?1:-1])
#endif

/* PRNG state. Need this here, details in lj_prng.h. */
typedef struct PRNGState {
  uint64_t u[4];
} PRNGState;

/* Common GC header for all collectable objects. */
#define GCHeader  \
  GCRef nextgc;   \
  uint8_t marked; \
  uint8_t gct
/* This occupies 6 bytes, so use the next 2 bytes for non-32 bit fields. */

/* Memory reference */
typedef struct MRef
{
#if LJ_GC64
  uint64_t ptr64; /* True 64 bit pointer. */
#else
  uint32_t ptr32;   /* Pseudo 32 bit pointer. */
#endif
} MRef;


#if LJ_GC64
#define mref(r, t)	((t *)(void *)(r).ptr64)
#define mrefu(r)	((r).ptr64)

#define setmref(r, p)	((r).ptr64 = (uint64_t)(void *)(p))
#define setmrefu(r, u)	((r).ptr64 = (uint64_t)(u))
#define setmrefr(r, v)	((r).ptr64 = (v).ptr64)
#else
#define mref(r, t)	((t *)(void *)(uintptr_t)(r).ptr32)
#define mrefu(r)	((r).ptr32)

#define setmref(r, p)	((r).ptr32 = (uint32_t)(uintptr_t)(void *)(p))
#define setmrefu(r, u)	((r).ptr32 = (uint32_t)(u))
#define setmrefr(r, v)	((r).ptr32 = (v).ptr32)
#endif

#define LJ_ALIGN(n) __attribute__((aligned(n)))

#define LUA_NUMBER double

/* type of numbers in Lua */
typedef LUA_NUMBER lua_Number;

#if LJ_ARCH_ENDIAN == LUAJIT_BE
#define LJ_LE 0
#define LJ_BE 1
#define LJ_ENDIAN_SELECT(le, be) be
#define LJ_ENDIAN_LOHI(lo, hi) hi lo
#else
#define LJ_LE 1
#define LJ_BE 0
#define LJ_ENDIAN_SELECT(le, be) le
#define LJ_ENDIAN_LOHI(lo, hi) lo hi
#endif

/* Frame link. */
typedef union {
  int32_t ftsz;		/* Frame type and size of previous frame. */
  MRef pcr;		/* Or PC for Lua frames. */
} FrameLink;


/* Tagged value. */
typedef LJ_ALIGN(8) union TValue
{
  uint64_t u64; /* 64 bit pattern overlaps number. */
  lua_Number n; /* Number object overlaps split tag/value object. */
#if LJ_GC64
  GCRef gcr; /* GCobj reference with tag. */
  int64_t it64;
  struct
  {
    LJ_ENDIAN_LOHI(
        int32_t i;     /* Integer value. */
        , uint32_t it; /* Internal object tag. Must overlap MSW of number. */
    )
  };
#else
  struct
  {
    LJ_ENDIAN_LOHI(
        union {
          GCRef gcr; /* GCobj reference (if any). */
          int32_t i; /* Integer value. */
        };
        , uint32_t it; /* Internal object tag. Must overlap MSW of number. */
    )
  };
#endif
#if LJ_FR2
  int64_t ftsz; /* Frame type and size of previous frame, or PC. */
#else
  struct
  {
    LJ_ENDIAN_LOHI(
        GCRef func;     /* Function for next frame (or dummy L). */
        , FrameLink tp; /* Link to previous frame. */
    )
  } fr;
#endif
  struct
  {
    LJ_ENDIAN_LOHI(
        uint32_t lo;   /* Lower 32 bits of number. */
        , uint32_t hi; /* Upper 32 bits of number. */
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
struct lua_State
{
  GCHeader;
  uint8_t dummy_ffid; /* Fake FF_C for curr_funcisL() on dummy frames. */
  uint8_t status;     /* Thread status. */
  MRef glref;         /* Link to global state. */
  GCRef gclist;       /* GC chain. */
  TValue *base;       /* Base of currently executing function. */
  TValue *top;        /* First free slot in the stack. */
  MRef maxstack;      /* Last free slot in the stack. */
  MRef stack;         /* Stack base. */
  GCRef openupval;    /* List of open upvalues in the stack. */
  GCRef env;          /* Thread environment (table of globals). */
  void *cframe;       /* End of C stack frame chain. */
  MSize stacksize;    /* True stack size (incl. LJ_STACK_EXTRA). */
  void *exdata;       /* user extra data pointer. added by OpenResty */
  void *exdata2;      /* the 2nd user extra data pointer. added by OpenResty */
#if LJ_TARGET_ARM
  uint32_t unused1;
  uint32_t unused2;
#endif
};

typedef struct lua_State lua_State;

typedef int (*lua_CFunction) (lua_State *L);

typedef const TValue cTValue;
/* Internal object tags.
**
** Format for 32 bit GC references (!LJ_GC64):
**
** Internal tags overlap the MSW of a number object (must be a double).
** Interpreted as a double these are special NaNs. The FPU only generates
** one type of NaN (0xfff8_0000_0000_0000). So MSWs > 0xfff80000 are available
** for use as internal tags. Small negative numbers are used to shorten the
** encoding of type comparisons (reg/mem against sign-ext. 8 bit immediate).
**
**                  ---MSW---.---LSW---
** primitive types |  itype  |         |
** lightuserdata   |  itype  |  void * |  (32 bit platforms)
** lightuserdata   |ffff|seg|    ofs   |  (64 bit platforms)
** GC objects      |  itype  |  GCRef  |
** int (LJ_DUALNUM)|  itype  |   int   |
** number           -------double------
**
** Format for 64 bit GC references (LJ_GC64):
**
** The upper 13 bits must be 1 (0xfff8...) for a special NaN. The next
** 4 bits hold the internal tag. The lowest 47 bits either hold a pointer,
** a zero-extended 32 bit integer or all bits set to 1 for primitive types.
**
**                     ------MSW------.------LSW------
** primitive types    |1..1|itype|1..................1|
** GC objects         |1..1|itype|-------GCRef--------|
** lightuserdata      |1..1|itype|seg|------ofs-------|
** int (LJ_DUALNUM)   |1..1|itype|0..0|-----int-------|
** number              ------------double-------------
**
** ORDER LJ_T
** Primitive types nil/false/true must be first, lightuserdata next.
** GC objects are at the end, table/userdata must be lowest.
** Also check lj_ir.h for similar ordering constraints.
*/
#define LJ_TNIL			(~0u)
#define LJ_TFALSE		(~1u)
#define LJ_TTRUE		(~2u)
#define LJ_TLIGHTUD		(~3u)
#define LJ_TSTR			(~4u)
#define LJ_TUPVAL		(~5u)
#define LJ_TTHREAD		(~6u)
#define LJ_TPROTO		(~7u)
#define LJ_TFUNC		(~8u)
#define LJ_TTRACE		(~9u)
#define LJ_TCDATA		(~10u)
#define LJ_TTAB			(~11u)
#define LJ_TUDATA		(~12u)
/* This is just the canonical number type used in some places. */
#define LJ_TNUMX		(~13u)

/* Integers have itype == LJ_TISNUM doubles have itype < LJ_TISNUM */
#if LJ_64 && !LJ_GC64
#define LJ_TISNUM		0xfffeffffu
#else
#define LJ_TISNUM		LJ_TNUMX
#endif
#define LJ_TISTRUECOND		LJ_TFALSE
#define LJ_TISPRI		LJ_TTRUE
#define LJ_TISGCV		(LJ_TSTR+1)
#define LJ_TISTABUD		LJ_TTAB

/* Type marker for slot holding a traversal index. Must be lightuserdata. */
#define LJ_KEYINDEX		0xfffe7fffu

#if LJ_GC64
#define LJ_GCVMASK		(((uint64_t)1 << 47) - 1)
#endif

#if LJ_64
/* To stay within 47 bits, lightuserdata is segmented. */
#define LJ_LIGHTUD_BITS_SEG	8
#define LJ_LIGHTUD_BITS_LO	(47 - LJ_LIGHTUD_BITS_SEG)
#endif

/* -- Common type definitions --------------------------------------------- */

/* Types for handling bytecodes. Need this here, details in lj_bc.h. */
typedef uint32_t BCIns;  /* Bytecode instruction. */
typedef uint32_t BCPos;  /* Bytecode position. */
typedef uint32_t BCReg;  /* Bytecode register. */
typedef int32_t BCLine;  /* Bytecode line number. */

/* Internal assembler functions. Never call these directly from C. */
typedef void (*ASMFunction)(void);

/* Resizable string buffer. Need this here, details in lj_buf.h. */
#define SBufHeader	char *w, *e, *b; MRef L
typedef struct SBuf {
  SBufHeader;
} SBuf;


/* Operand ranges and related constants. */
#define BCMAX_A		0xff
#define BCMAX_B		0xff
#define BCMAX_C		0xff
#define BCMAX_D		0xffff
#define BCBIAS_J	0x8000
#define NO_REG		BCMAX_A
#define NO_JMP		(~(BCPos)0)

/* Macros to get instruction fields. */
#define bc_op(i)	((BCOp)((i)&0xff))
#define bc_a(i)		((BCReg)(((i)>>8)&0xff))
#define bc_b(i)		((BCReg)((i)>>24))
#define bc_c(i)		((BCReg)(((i)>>16)&0xff))
#define bc_d(i)		((BCReg)((i)>>16))
#define bc_j(i)		((ptrdiff_t)bc_d(i)-BCBIAS_J)

/* Macros to set instruction fields. */
#define setbc_byte(p, x, ofs) \
  ((uint8_t *)(p))[LJ_ENDIAN_SELECT(ofs, 3-ofs)] = (uint8_t)(x)
#define setbc_op(p, x)	setbc_byte(p, (x), 0)
#define setbc_a(p, x)	setbc_byte(p, (x), 1)
#define setbc_b(p, x)	setbc_byte(p, (x), 3)
#define setbc_c(p, x)	setbc_byte(p, (x), 2)
#define setbc_d(p, x) \
  ((uint16_t *)(p))[LJ_ENDIAN_SELECT(1, 0)] = (uint16_t)(x)
#define setbc_j(p, x)	setbc_d(p, (BCPos)((int32_t)(x)+BCBIAS_J))

/* Macros to compose instructions. */
#define BCINS_ABC(o, a, b, c) \
  (((BCIns)(o))|((BCIns)(a)<<8)|((BCIns)(b)<<24)|((BCIns)(c)<<16))
#define BCINS_AD(o, a, d) \
  (((BCIns)(o))|((BCIns)(a)<<8)|((BCIns)(d)<<16))
#define BCINS_AJ(o, a, j)	BCINS_AD(o, a, (BCPos)((int32_t)(j)+BCBIAS_J))

#if LJ_GC64
#define gcref(r) ((GCobj *)(r).gcptr64)
#define gcrefp(r, t) ((t *)(void *)(r).gcptr64)
#define gcrefu(r) ((r).gcptr64)
#define gcrefeq(r1, r2) ((r1).gcptr64 == (r2).gcptr64)

#define setgcref(r, gc) ((r).gcptr64 = (uint64_t) & (gc)->gch)
#define setgcreft(r, gc, it) \
  (r).gcptr64 = (uint64_t) & (gc)->gch | (((uint64_t)(it)) << 47)
#define setgcrefp(r, p) ((r).gcptr64 = (uint64_t)(p))
#define setgcrefnull(r) ((r).gcptr64 = 0)
#define setgcrefr(r, v) ((r).gcptr64 = (v).gcptr64)
#else
#define gcref(r) ((GCobj *)(uintptr_t)(r).gcptr32)
#define gcrefp(r, t) ((t *)(void *)(uintptr_t)(r).gcptr32)
#define gcrefu(r) ((r).gcptr32)
#define gcrefeq(r1, r2) ((r1).gcptr32 == (r2).gcptr32)

#define setgcref(r, gc) ((r).gcptr32 = (uint32_t)(uintptr_t) & (gc)->gch)
#define setgcrefp(r, p) ((r).gcptr32 = (uint32_t)(uintptr_t)(p))
#define setgcrefnull(r) ((r).gcptr32 = 0)
#define setgcrefr(r, v) ((r).gcptr32 = (v).gcptr32)
#endif

#define tvref(r) (mref(r, TValue))

/* -- String object ------------------------------------------------------- */

typedef uint32_t StrHash;	/* String hash value. */
typedef uint32_t StrID;		/* String ID. */

/* String object header. String payload follows. */
typedef struct GCstr {
  GCHeader;
  uint8_t reserved;	/* Used by lexer for fast lookup of reserved words. */
  uint8_t hashalg;	/* Hash algorithm. */
  StrID sid;		/* Interned string ID. */
  StrHash hash;		/* Hash of string. */
  MSize len;		/* Size of string. */
} GCstr;

#define strref(r)	(&gcref((r))->str)
#define strdata(s)	((const char *)((s)+1))
#define strdatawr(s)	((char *)((s)+1))
/* -- Userdata object ----------------------------------------------------- */

/* Userdata object. Payload follows. */
typedef struct GCudata {
  GCHeader;
  uint8_t udtype;	/* Userdata type. */
  uint8_t unused2;
  GCRef env;		/* Should be at same offset in GCfunc. */
  MSize len;		/* Size of payload. */
  GCRef metatable;	/* Must be at same offset in GCtab. */
  uint32_t align1;	/* To force 8 byte alignment of the payload. */
} GCudata;

/* Userdata types. */
enum {
  UDTYPE_USERDATA,	/* Regular userdata. */
  UDTYPE_IO_FILE,	/* I/O library FILE. */
  UDTYPE_FFI_CLIB,	/* FFI C library namespace. */
  UDTYPE_BUFFER,	/* String buffer. */
  UDTYPE__MAX
};

#define uddata(u)	((void *)((u)+1))
#define sizeudata(u)	(sizeof(struct GCudata)+(u)->len)

/* -- C data object ------------------------------------------------------- */

/* C data object. Payload follows. */
typedef struct GCcdata {
  GCHeader;
  uint16_t ctypeid;	/* C type ID. */
} GCcdata;

/* Prepended to variable-sized or realigned C data objects. */
typedef struct GCcdataVar {
  uint16_t offset;	/* Offset to allocated memory (relative to GCcdata). */
  uint16_t extra;	/* Extra space allocated (incl. GCcdata + GCcdatav). */
  MSize len;		/* Size of payload. */
} GCcdataVar;

#define cdataptr(cd)	((void *)((cd)+1))
#define cdataisv(cd)	((cd)->marked & 0x80)
#define cdatav(cd)	((GCcdataVar *)((char *)(cd) - sizeof(GCcdataVar)))
#define cdatavlen(cd)	check_exp(cdataisv(cd), cdatav(cd)->len)
#define sizecdatav(cd)	(cdatavlen(cd) + cdatav(cd)->extra)
#define memcdatav(cd)	((void *)((char *)(cd) - cdatav(cd)->offset))

/* -- Prototype object ---------------------------------------------------- */

#define SCALE_NUM_GCO	((int32_t)sizeof(lua_Number)/sizeof(GCRef))
#define round_nkgc(n)	(((n) + SCALE_NUM_GCO-1) & ~(SCALE_NUM_GCO-1))

typedef struct GCproto {
  GCHeader;
  uint8_t numparams;	/* Number of parameters. */
  uint8_t framesize;	/* Fixed frame size. */
  MSize sizebc;		/* Number of bytecode instructions. */
#if LJ_GC64
  uint32_t unused_gc64;
#endif
  GCRef gclist;
  MRef k;		/* Split constant array (points to the middle). */
  MRef uv;		/* Upvalue list. local slot|0x8000 or parent uv idx. */
  MSize sizekgc;	/* Number of collectable constants. */
  MSize sizekn;		/* Number of lua_Number constants. */
  MSize sizept;		/* Total size including colocated arrays. */
  uint8_t sizeuv;	/* Number of upvalues. */
  uint8_t flags;	/* Miscellaneous flags (see below). */
  uint16_t trace;	/* Anchor for chain of root traces. */
  /* ------ The following fields are for debugging/tracebacks only ------ */
  GCRef chunkname;	/* Name of the chunk this function was defined in. */
  BCLine firstline;	/* First line of the function definition. */
  BCLine numline;	/* Number of lines for the function definition. */
  MRef lineinfo;	/* Compressed map from bytecode ins. to source line. */
  MRef uvinfo;		/* Upvalue names. */
  MRef varinfo;		/* Names and compressed extents of local variables. */
} GCproto;

/* Flags for prototype. */
#define PROTO_CHILD		0x01	/* Has child prototypes. */
#define PROTO_VARARG		0x02	/* Vararg function. */
#define PROTO_FFI		0x04	/* Uses BC_KCDATA for FFI datatypes. */
#define PROTO_NOJIT		0x08	/* JIT disabled for this function. */
#define PROTO_ILOOP		0x10	/* Patched bytecode with ILOOP etc. */
/* Only used during parsing. */
#define PROTO_HAS_RETURN	0x20	/* Already emitted a return. */
#define PROTO_FIXUP_RETURN	0x40	/* Need to fixup emitted returns. */
/* Top bits used for counting created closures. */
#define PROTO_CLCOUNT		0x20	/* Base of saturating 3 bit counter. */
#define PROTO_CLC_BITS		3
#define PROTO_CLC_POLY		(3*PROTO_CLCOUNT)  /* Polymorphic threshold. */

#define PROTO_UV_LOCAL		0x8000	/* Upvalue for local slot. */
#define PROTO_UV_IMMUTABLE	0x4000	/* Immutable upvalue. */

#define proto_kgc(pt, idx) \
  check_exp((uintptr_t)(intptr_t)(idx) >= (uintptr_t)-(intptr_t)(pt)->sizekgc, \
	    gcref(mref((pt)->k, GCRef)[(idx)]))
#define proto_knumtv(pt, idx) \
  check_exp((uintptr_t)(idx) < (pt)->sizekn, &mref((pt)->k, TValue)[(idx)])
#define proto_bc(pt)		((BCIns *)((char *)(pt) + sizeof(GCproto)))
#define proto_bcpos(pt, pc)	((BCPos)((pc) - proto_bc(pt)))
#define proto_uv(pt)		(mref((pt)->uv, uint16_t))

#define proto_chunkname(pt)	(strref(BPF_PROBE_READ_USER(pt, chunkname)))

#define proto_chunknamestr(pt)	(strdata(proto_chunkname((pt))))
#define proto_lineinfo(pt)	(mref((pt)->lineinfo, const void))
#define proto_uvinfo(pt)	(mref((pt)->uvinfo, const uint8_t))
#define proto_varinfo(pt)	(mref((pt)->varinfo, const uint8_t))

/* -- Upvalue object ------------------------------------------------------ */

typedef struct GCupval {
  GCHeader;
  uint8_t closed;	/* Set if closed (i.e. uv->v == &uv->u.value). */
  uint8_t immutable;	/* Immutable value. */
  union {
    TValue tv;		/* If closed: the value itself. */
    struct {		/* If open: double linked list, anchored at thread. */
      GCRef prev;
      GCRef next;
    };
  };
  MRef v;		/* Points to stack slot (open) or above (closed). */
  uint32_t dhash;	/* Disambiguation hash: dh1 != dh2 => cannot alias. */
} GCupval;

#define uvprev(uv_)	(&gcref((uv_)->prev)->uv)
#define uvnext(uv_)	(&gcref((uv_)->next)->uv)
#define uvval(uv_)	(mref((uv_)->v, TValue))

/* GC header for generic access to common fields of GC objects. */
typedef struct GChead {
  GCHeader;
  uint8_t unused1;
  uint8_t unused2;
  GCRef env;
  GCRef gclist;
  GCRef metatable;
} GChead;


/* -- Function object (closures) ------------------------------------------ */

/* Common header for functions. env should be at same offset in GCudata. */
#define GCfuncHeader \
  GCHeader; uint8_t ffid; uint8_t nupvalues; \
  GCRef env; GCRef gclist; MRef pc

typedef struct GCfuncC {
  GCfuncHeader;
  lua_CFunction f;	/* C function to be called. */
  TValue upvalue[1];	/* Array of upvalues (TValue). */
} GCfuncC;

typedef struct GCfuncL {
  GCfuncHeader;
  GCRef uvptr[1];	/* Array of _pointers_ to upvalue objects (GCupval). */
} GCfuncL;

typedef union GCfunc {
  GCfuncC c;
  GCfuncL l;
} GCfunc;

#define FF_LUA		0
#define FF_C		1
#define isluafunc(fn)	((fn)->c.ffid == FF_LUA)
#define iscfunc(fn)	((fn)->c.ffid == FF_C)
#define isffunc(fn)	((fn)->c.ffid > FF_C)
#define funcproto(fn) \
  check_exp(isluafunc(fn), (GCproto *)(mref(BPF_PROBE_READ_USER((fn),l.pc), char)-sizeof(GCproto)))
#define sizeCfunc(n)	(sizeof(GCfuncC)-sizeof(TValue)+sizeof(TValue)*(n))
#define sizeLfunc(n)	(sizeof(GCfuncL)-sizeof(GCRef)+sizeof(GCRef)*(n))

typedef struct GCtab {
  GCHeader;
  uint8_t nomm;		/* Negative cache for fast metamethods. */
  char colo;		/* Array colocation. */
  MRef array;		/* Array part. */
  GCRef gclist;
  GCRef metatable;	/* Must be at same offset in GCudata. */
  MRef node;		/* Hash part. */
  uint32_t asize;	/* Size of array part (keys [0, asize-1]). */
  uint32_t hmask;	/* Hash part mask (size of hash part - 1). */
#if LJ_GC64
  MRef freetop;		/* Top of free elements. */
#endif
} GCtab;

#define sizetabcolo(n)	((n)*sizeof(TValue) + sizeof(GCtab))
#define tabref(r)	(&gcref((r))->tab)
#define noderef(r)	(mref((r), Node))
#define nextnode(n)	(mref((n)->next, Node))
#if LJ_GC64
#define getfreetop(t, n)	(noderef((t)->freetop))
#define setfreetop(t, n, v)	(setmref((t)->freetop, (v)))
#else
#define getfreetop(t, n)	(noderef((n)->freetop))
#define setfreetop(t, n, v)	(setmref((n)->freetop, (v)))
#endif

typedef union GCobj {
  GChead gch;
  GCstr str;
  GCupval uv;
  lua_State th;
  GCproto pt;
  GCfunc fn;
  GCcdata cd;
  GCtab tab;
  GCudata ud;
} GCobj;

/* Macros to convert a GCobj pointer into a specific value. */
#define gco2str(o)	check_exp((o)->gch.gct == ~LJ_TSTR, &(o)->str)
#define gco2uv(o)	check_exp((o)->gch.gct == ~LJ_TUPVAL, &(o)->uv)
#define gco2th(o)	check_exp((o)->gch.gct == ~LJ_TTHREAD, &(o)->th)
#define gco2pt(o)	check_exp((o)->gch.gct == ~LJ_TPROTO, &(o)->pt)
#define gco2func(o)	check_exp((o)->gch.gct == ~LJ_TFUNC, &(o)->fn)
#define gco2cd(o)	check_exp((o)->gch.gct == ~LJ_TCDATA, &(o)->cd)
#define gco2tab(o)	check_exp((o)->gch.gct == ~LJ_TTAB, &(o)->tab)
#define gco2ud(o)	check_exp((o)->gch.gct == ~LJ_TUDATA, &(o)->ud)

/* Macro to convert any collectable object into a GCobj pointer. */
#define obj2gco(v)	((GCobj *)(v))

#if LJ_GC64
//#define gcval(o) ((GCobj *)(gcrefu((o)->gcr) & LJ_GCVMASK))
#define gcval(o) ((GCobj *)(gcrefu(BPF_PROBE_READ_USER(o, gcr)) & LJ_GCVMASK))

// static __always_inline GCobj * gcval(cTValue *frame) {
// 	GCRef gcr;
// 	bpf_probe_read_user(&gcr, sizeof(gcr), &frame->gcr);
// 	return (GCobj*)(gcr.gcptr64 & LJ_GCVMASK);
// }

#else
#define gcval(o) (gcref((o)->gcr))
#endif

/* -- Lua stack frame ----------------------------------------------------- */

/* Frame type markers in LSB of PC (4-byte aligned) or delta (8-byte aligned:
**
**    PC  00  Lua frame
** delta 001  C frame
** delta 010  Continuation frame
** delta 011  Lua vararg frame
** delta 101  cpcall() frame
** delta 110  ff pcall() frame
** delta 111  ff pcall() frame with active hook
*/
enum
{
  FRAME_LUA,
  FRAME_C,
  FRAME_CONT,
  FRAME_VARG,
  FRAME_LUAP,
  FRAME_CP,
  FRAME_PCALL,
  FRAME_PCALLH
};
#define FRAME_TYPE 3
#define FRAME_P 4
#define FRAME_TYPEP (FRAME_TYPE | FRAME_P)

/* Macros to access and modify Lua frames. */
#if LJ_FR2
/* Two-slot frame info, required for 64 bit PC/GCRef:
**
**                   base-2  base-1      |  base  base+1 ...
**                  [func   PC/delta/ft] | [slots ...]
**                  ^-- frame            | ^-- base   ^-- top
**
** Continuation frames:
**
**   base-4  base-3  base-2  base-1      |  base  base+1 ...
**  [cont      PC ] [func   PC/delta/ft] | [slots ...]
**                  ^-- frame            | ^-- base   ^-- top
*/
#define frame_gc(f) (gcval((f)-1))
#define frame_ftsz(f) ((ptrdiff_t)BPF_PROBE_READ_USER(frame, ftsz))

#define frame_pc(f) ((const BCIns *)frame_ftsz(f))
#define setframe_ftsz(f, sz) ((f)->ftsz = (sz))
#define setframe_pc(f, pc) ((f)->ftsz = (int64_t)(intptr_t)(pc))
#else
/* One-slot frame info, sufficient for 32 bit PC/GCRef:
**
**              base-1              |  base  base+1 ...
**              lo     hi           |
**             [func | PC/delta/ft] | [slots ...]
**             ^-- frame            | ^-- base   ^-- top
**
** Continuation frames:
**
**  base-2      base-1              |  base  base+1 ...
**  lo     hi   lo     hi           |
** [cont | PC] [func | PC/delta/ft] | [slots ...]
**             ^-- frame            | ^-- base   ^-- top
*/
#define frame_gc(f) (gcref((f)->fr.func))
#define frame_ftsz(f) ((ptrdiff_t)BPF_PROBE_READ_USER(f, fr.tp.ftsz))

#define frame_pc(f) (mref((f)->fr.tp.pcr, const BCIns))
#define setframe_gc(f, p, tp) (setgcref((f)->fr.func, (p)), UNUSED(tp))
#define setframe_ftsz(f, sz) ((f)->fr.tp.ftsz = (int32_t)(sz))
#define setframe_pc(f, pc) (setmref((f)->fr.tp.pcr, (pc)))
#endif

#define frame_type(f) (frame_ftsz(f) & FRAME_TYPE)
#define frame_typep(f) (frame_ftsz(f) & FRAME_TYPEP)
#define frame_islua(f) (frame_type(f) == FRAME_LUA)
#define frame_isc(f) (frame_type(f) == FRAME_C)
#define frame_iscont(f) (frame_typep(f) == FRAME_CONT)
#define frame_isvarg(f) (frame_typep(f) == FRAME_VARG)
#define frame_ispcall(f) ((frame_ftsz(f) & 6) == FRAME_PCALL)
#define frame_func(f) (&frame_gc(f)->fn)


// static __always_inline GCfunc frame_func(GCobj* obj) {
// 	GCfunc fn;
// 	bpf_probe_read_user(&fn, sizeof(fn), &obj->fn);
// 	return fn;
// }

#define frame_delta(f) (frame_ftsz(f) >> 3)
#define frame_sized(f) (frame_ftsz(f) & ~FRAME_TYPEP)

enum
{
  LJ_CONT_TAILCALL,
  LJ_CONT_FFI_CALLBACK
}; /* Special continuations. */

#define frame_iscont_fficb(f) \
  (LJ_HASFFI && frame_contv(f) == LJ_CONT_FFI_CALLBACK)

static __always_inline BCIns frame_pc_prev(const BCIns *bcins) {
  const BCIns bcins_prev;
  bpf_probe_read_user((void*)&bcins_prev, sizeof(bcins_prev), bcins - 1);
  return bcins_prev;
}

#define frame_prevl(f) ((f) - (1 + LJ_FR2 + bc_a(frame_pc_prev(frame_pc(f)))))
#define frame_prevd(f) ((TValue *)((char *)(f)-frame_sized(f)))
#define frame_prev(f) (frame_islua(f) ? frame_prevl(f) : frame_prevd(f))

/* -- State objects ------------------------------------------------------- */

/* VM states. */
enum {
  LJ_VMST_INTERP,	/* Interpreter. */
  LJ_VMST_C,		/* C function. */
  LJ_VMST_GC,		/* Garbage collector. */
  LJ_VMST_EXIT,		/* Trace exit handler. */
  LJ_VMST_RECORD,	/* Trace recorder. */
  LJ_VMST_OPT,		/* Optimizer. */
  LJ_VMST_ASM,		/* Assembler. */
  LJ_VMST__MAX
};

#define setvmstate(g, st)	((g)->vmstate = ~LJ_VMST_##st)

/* Metamethods. ORDER MM */
#ifdef LJ_HASFFI
#define MMDEF_FFI(_) _(new)
#else
#define MMDEF_FFI(_)
#endif

#if LJ_52 || LJ_HASFFI
#define MMDEF_PAIRS(_) _(pairs) _(ipairs)
#else
#define MMDEF_PAIRS(_)
#define MM_pairs	255
#define MM_ipairs	255
#endif

#define MMDEF(_) \
  _(index) _(newindex) _(gc) _(mode) _(eq) _(len) \
  /* Only the above (fast) metamethods are negative cached (max. 8). */ \
  _(lt) _(le) _(concat) _(call) \
  /* The following must be in ORDER ARITH. */ \
  _(add) _(sub) _(mul) _(div) _(mod) _(pow) _(unm) \
  /* The following are used in the standard libraries. */ \
  _(metatable) _(tostring) MMDEF_FFI(_) MMDEF_PAIRS(_)

typedef enum {
#define MMENUM(name)	MM_##name,
MMDEF(MMENUM)
#undef MMENUM
  MM__MAX,
  MM____ = MM__MAX,
  MM_FAST = MM_len
} MMS;

/* GC root IDs. */
typedef enum {
  GCROOT_MMNAME,	/* Metamethod names. */
  GCROOT_MMNAME_LAST = GCROOT_MMNAME + MM__MAX-1,
  GCROOT_BASEMT,	/* Metatables for base types. */
  GCROOT_BASEMT_NUM = GCROOT_BASEMT + ~LJ_TNUMX,
  GCROOT_IO_INPUT,	/* Userdata for default I/O input file. */
  GCROOT_IO_OUTPUT,	/* Userdata for default I/O output file. */
  GCROOT_MAX
} GCRootID;

#define basemt_it(g, it)	((g)->gcroot[GCROOT_BASEMT+~(it)])
#define basemt_obj(g, o)	((g)->gcroot[GCROOT_BASEMT+itypemap(o)])
#define mmname_str(g, mm)	(strref((g)->gcroot[GCROOT_MMNAME+(mm)]))

/* Garbage collector state. */
typedef struct GCState {
  GCSize total;		/* Memory currently allocated. */
  GCSize threshold;	/* Memory threshold. */
  uint8_t currentwhite;	/* Current white color. */
  uint8_t state;	/* GC state. */
  uint8_t nocdatafin;	/* No cdata finalizer called. */
#if LJ_64
  uint8_t lightudnum;	/* Number of lightuserdata segments - 1. */
#else
  uint8_t unused1;
#endif
  MSize sweepstr;	/* Sweep position in string table. */
  GCRef root;		/* List of all collectable objects. */
  MRef sweep;		/* Sweep position in root list. */
  GCRef gray;		/* List of gray objects. */
  GCRef grayagain;	/* List of objects for atomic traversal. */
  GCRef weak;		/* List of weak tables (to be cleared). */
  GCRef mmudata;	/* List of userdata (to be finalized). */
  GCSize debt;		/* Debt (how much GC is behind schedule). */
  GCSize estimate;	/* Estimate of memory actually in use. */
  MSize stepmul;	/* Incremental GC step granularity. */
  MSize pause;		/* Pause between successive GC cycles. */
#if LJ_64
  MRef lightudseg;	/* Upper bits of lightuserdata segments. */
#endif
} GCState;

#define mainthread(g)	(&gcref(g->mainthref)->th)
#define niltv(L) \
  check_exp(tvisnil(&G(L)->nilnode.val), &G(L)->nilnode.val)
#define niltvg(g) \
  check_exp(tvisnil(&(g)->nilnode.val), &(g)->nilnode.val)

/* Hook management. Hook event masks are defined in lua.h. */
#define HOOK_EVENTMASK		0x0f
#define HOOK_ACTIVE		0x10
#define HOOK_ACTIVE_SHIFT	4
#define HOOK_VMEVENT		0x20
#define HOOK_GC			0x40
#define HOOK_PROFILE		0x80
#define hook_active(g)		((g)->hookmask & HOOK_ACTIVE)
#define hook_enter(g)		((g)->hookmask |= HOOK_ACTIVE)
#define hook_entergc(g) \
  ((g)->hookmask = ((g)->hookmask | (HOOK_ACTIVE|HOOK_GC)) & ~HOOK_PROFILE)
#define hook_vmevent(g)		((g)->hookmask |= (HOOK_ACTIVE|HOOK_VMEVENT))
#define hook_leave(g)		((g)->hookmask &= ~HOOK_ACTIVE)
#define hook_save(g)		((g)->hookmask & ~HOOK_EVENTMASK)
#define hook_restore(g, h) \
  ((g)->hookmask = ((g)->hookmask & HOOK_EVENTMASK) | (h))


/* thread status */
#define LUA_OK		0
#define LUA_YIELD	1
#define LUA_ERRRUN	2
#define LUA_ERRSYNTAX	3
#define LUA_ERRMEM	4
#define LUA_ERRERR	5

#endif
