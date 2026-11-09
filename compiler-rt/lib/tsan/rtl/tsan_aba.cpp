//===-- tsan_aba.cpp ------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of ThreadSanitizer (TSan), a race detector.
//
// Out-of-line state for ABA detection: the allocation epoch counter, the
// per-thread load cache, and the side table holding identities for pool slots
// annotated with __tsan_aba_pool_alloc/__tsan_aba_pool_free.
//
//===----------------------------------------------------------------------===//
#include "tsan_rtl_aba.h"

#include "tsan_rtl.h"
#include "tsan_report.h"
#include "sanitizer_common/sanitizer_stackdepot.h"
#include "sanitizer_common/sanitizer_symbolizer.h"

extern "C" void __sanitizer_print_stack_trace();
namespace __tsan {

// Monotonic allocation identity; 0 is reserved for dead/untracked memory.
atomic_uint64_t g_aba_epoch = {1};

__attribute__((tls_model("initial-exec")))
THREADLOCAL AbaCache aba_cache;

__attribute__((tls_model("initial-exec")))
THREADLOCAL u64 aba_report_count;

// Pool slot side table. Open addressing with a fixed probe window; removal
// zeroes the slot rather than leaving a tombstone. Lookups must therefore scan
// the whole window and never stop early, or a removal could hide a live entry
// behind it -- the resulting miss returns epoch 0, which the CAS check reads as
// an identity change and reports falsely. Overflowing the window drops the
// insert instead, costing only a missed detection.

// 1Mi entries (24MB of BSS, faulted in only where touched): a program that
// annotates every node of long-lived queues re-stamps rather than removes, so
// live entries accumulate up to the number of nodes ever annotated.
static const uptr kPoolSize = 1 << 20;
static const uptr kPoolMask = kPoolSize - 1;
static const uptr kPoolHashShift = 64 - 20;
static const uptr kPoolProbe = 8;

struct PoolSlot {
  atomic_uintptr_t addr;  // 0 == empty
  atomic_uint64_t epoch;
  atomic_uint64_t host;   // epoch of the heap block holding the slot, or 0
};

u64 AbaHeapHostEpoch(uptr p);  // tsan_mman.cpp

// An entry is stale when the heap block that held its slot was freed (and
// maybe reallocated): the annotations for it can never be removed now.
// Checked only when an insert finds its probe window full.
static inline bool PoolSlotStale(PoolSlot *s, uptr addr) {
  u64 host = atomic_load(&s->host, memory_order_relaxed);
  return host != 0 && AbaHeapHostEpoch(addr) != host;
}

static PoolSlot g_pool_map[kPoolSize];
static atomic_uint64_t g_aba_pool_dropped;

// Stays 0 until the first annotation, so unannotated programs pay one relaxed
// load per lookup instead of walking the probe window.
static atomic_uint32_t g_pool_used;

static inline uptr PoolHash(uptr p) {
  // Fibonacci hashing; the high product bits mix in the low address bits that
  // distinguish adjacent slots.
  return (uptr)(((u64)p * 0x9E3779B97F4A7C15ull) >> kPoolHashShift) & kPoolMask;
}

static void PoolInsert(uptr p, u64 epoch) {
  uptr h = PoolHash(p);
  u64 host = AbaHeapHostEpoch(p);
  // Re-stamp an existing entry for p first; claiming an earlier hole would
  // leave a stale duplicate that resurfaces after the next remove.
  for (uptr i = 0; i < kPoolProbe; i++) {
    PoolSlot *s = &g_pool_map[(h + i) & kPoolMask];
    if (atomic_load(&s->addr, memory_order_acquire) == p) {
      atomic_store(&s->host, host, memory_order_relaxed);
      atomic_store(&s->epoch, epoch, memory_order_release);
      return;
    }
  }
  for (int pass = 0; pass < 2; pass++) {
    for (uptr i = 0; i < kPoolProbe; i++) {
      PoolSlot *s = &g_pool_map[(h + i) & kPoolMask];
      uptr cur = atomic_load(&s->addr, memory_order_acquire);
      // Pass 1 reclaims entries whose slab was freed: without this, slots of
      // destroyed pools fill the window and later inserts are dropped.
      if (cur != 0 && cur != p && !(pass == 1 && PoolSlotStale(s, cur)))
        continue;  // taken by another address
      // On a lost race cur holds the winner's address; if it claimed p too,
      // the slot is still ours to stamp.
      uptr want = cur;
      if (cur != p &&
          !atomic_compare_exchange_strong(&s->addr, &cur, p,
                                          memory_order_acq_rel) &&
          cur != p)
        continue;
      (void)want;
      atomic_store(&s->host, host, memory_order_relaxed);
      atomic_store(&s->epoch, epoch, memory_order_release);
      return;
    }
  }
  atomic_fetch_add(&g_aba_pool_dropped, 1, memory_order_relaxed);
}

static void PoolRemove(uptr p) {
  uptr h = PoolHash(p);
  for (uptr i = 0; i < kPoolProbe; i++) {
    PoolSlot *s = &g_pool_map[(h + i) & kPoolMask];
    if (atomic_load(&s->addr, memory_order_acquire) != p)
      continue;
    atomic_store(&s->epoch, 0, memory_order_relaxed);
    atomic_store(&s->addr, 0, memory_order_release);
    return;
  }
}

static u64 PoolLookup(uptr p) {
  uptr h = PoolHash(p);
  for (uptr i = 0; i < kPoolProbe; i++) {
    PoolSlot *s = &g_pool_map[(h + i) & kPoolMask];
    if (atomic_load(&s->addr, memory_order_acquire) == p)
      // Not validated against the host block here (hot path): a stale entry
      // only returns a constant epoch, which can hide ABA but never report it.
      return atomic_load(&s->epoch, memory_order_acquire);
  }
  return 0;
}

atomic_uint64_t g_aba_push_suppressed;
atomic_uint64_t g_aba_freed_suppressed;
bool AbaReportFreed() {
  static int v = -1;
  if (v < 0) v = GetEnv("TSAN_ABA_REPORT_FREED") ? 1 : 0;
  return v;
}
atomic_uint64_t g_aba_benign[3];

atomic_uint64_t g_aba_loads, g_aba_loads_tracked, g_aba_cas_checked, g_aba_reports;

void AbaPrintPc(const char *what, uptr pc, uptr cas_pc) {
  if (!pc) return;
  SymbolizedStack *s = Symbolizer::GetOrInit()->SymbolizePC(pc);
  for (SymbolizedStack *f = s; f; f = f->next)
    Printf("  %s: %s %s:%d\n", what, f->info.function ? f->info.function : "?",
           f->info.file ? f->info.file : "?", f->info.line);
  if (s) s->ClearAll();
  Printf("  CAS stack (TSan shadow stack):\n");
  ThreadState *thr = cur_thread();
  VarSizeStackTrace trace;
  ObtainCurrentStack(thr, cas_pc, &trace);
  PrintStack(SymbolizeStackId(StackDepotPut(trace)));
}

void AbaPrintStats() {
  Printf("ABA stats: ptr-sized loads=%llu tracked=%llu cas-checked=%llu "
         "reports=%llu suppressed=%llu (mark=%llu push=%llu consistent=%llu) freed-token=%llu "
         "loc-checked=%llu loc-reports=%llu pool-dropped=%llu\n",
         (unsigned long long)atomic_load(&g_aba_loads, memory_order_relaxed),
         (unsigned long long)atomic_load(&g_aba_loads_tracked, memory_order_relaxed),
         (unsigned long long)atomic_load(&g_aba_cas_checked, memory_order_relaxed),
         (unsigned long long)atomic_load(&g_aba_reports, memory_order_relaxed),
         (unsigned long long)atomic_load(&g_aba_push_suppressed, memory_order_relaxed),
         (unsigned long long)atomic_load(&g_aba_benign[0], memory_order_relaxed),
         (unsigned long long)atomic_load(&g_aba_benign[1], memory_order_relaxed),
         (unsigned long long)atomic_load(&g_aba_benign[2], memory_order_relaxed),
         (unsigned long long)atomic_load(&g_aba_freed_suppressed, memory_order_relaxed),
         (unsigned long long)atomic_load(&g_aba_loc_checked, memory_order_relaxed),
         (unsigned long long)atomic_load(&g_aba_loc_reports, memory_order_relaxed),
         (unsigned long long)atomic_load(&g_aba_pool_dropped, memory_order_relaxed));
}

// Heap block containing p (p may point up to 128 bytes past the block start,
// e.g. past an allocator header or into an intrusive link field).
static MBlock *AbaEnclosingBlock(uptr p, uptr *start) {
  if (p < HeapMemBeg() || p >= HeapMemEnd())
    return nullptr;
  for (uptr back = 0; back <= 128; back += kMetaShadowCell) {
    uptr q = RoundDownTo(p, kMetaShadowCell) - back;
    if (MBlock *b = ctx->metamap.GetBlock(q)) {
      if (q + b->siz > p) {
        *start = q;
        return b;
      }
      return nullptr;  // p lies past the end of the nearest block
    }
  }
  return nullptr;
}

static uptr AbaObjectWords(uptr p) {
  if (!IsAppMem(p))
    return 0;
  uptr start;
  if (MBlock *b = AbaEnclosingBlock(p, &start))
    return Min<uptr>(start + b->siz - p, 128) / sizeof(uptr);
  if (atomic_load(&g_pool_used, memory_order_relaxed) && PoolLookup(p))
    return 1;  // slot size unknown: only the first word is known to be ours
  return 0;
}

static bool AbaObjectHolds(uptr obj, uptr value) {
  uptr words = AbaObjectWords(obj);
  const uptr *w = (const uptr *)obj;
  for (uptr i = 0; i < words; i++)
    if (w[i] == value)
      return true;
  return false;
}



// Multi-node push: desired is the first node of a private chain whose last
// node links to expected (first->...->last->next == expected). Follow each
// pointer-valued word offset of desired along the chain.
static bool AbaChainReaches(uptr desired, uptr expected) {
  uptr words = AbaObjectWords(desired);
  for (uptr off = 0; off < words; off++) {
    uptr cur = ((const uptr *)desired)[off];
    for (int hop = 0; hop < 4096 && cur; hop++) {
      if (cur == expected)
        return true;
      if (AbaObjectWords(cur) <= off || GetPointerEpoch(cur) == 0)
        break;
      cur = ((const uptr *)cur)[off];
    }
  }
  return false;
}

void AbaDebugObject(const char *what, uptr p) {
  uptr words = AbaObjectWords(p);
  Printf("  %s %p: words=%zu epoch=%llu heapblock=%d", what, (void *)p, words,
         (unsigned long long)GetPointerEpoch(p),
         IsAppMem(p) && ctx->metamap.GetBlock(p) ? 1 : 0);
  for (uptr i = 0; i < words && i < 4; i++)
    Printf(" [%zu]=%p", i, ((void **)p)[i]);
  Printf("\n");
}

void AbaSnapshot(uptr value, uptr *snap) {
  uptr words = Min<uptr>(AbaObjectWords(value), kAbaSnapWords);
  for (uptr i = 0; i < kAbaSnapWords; i++)
    snap[i] = i < words ? ((const uptr *)value)[i] : 0;
}

bool AbaDesiredLinksTo(uptr desired, uptr expected, bool pop_like) {
  // (1) Mark/flag CAS: writes back the same object with different mark bits
  // (low alignment bits or unused top bits). Old contents are never used.
  const uptr kAddrBits = 0x00007ffffffffff8ull;
  if (((desired ^ expected) & kAddrBits) == 0) {
    atomic_fetch_add(&g_aba_benign[0], 1, memory_order_relaxed);
    return true;
  }
  // (2) Push: the new object already links to the expected one
  // (n->next == expected). Only the old head's address is used.
  if (expected && !pop_like && (AbaObjectHolds(desired, expected) ||
                   AbaChainReaches(desired, expected))) {
    atomic_fetch_add(&g_aba_benign[1], 1, memory_order_relaxed);
    return true;
  }
  // (3) Consistent pop: the object now at `expected` (the new incarnation)
  // links to `desired`, so the update matches the current structure.
  // NULL is excluded: any zero word would match it.
  if (desired && GetPointerEpoch(expected) != 0 && AbaObjectHolds(expected, desired)) {
    atomic_fetch_add(&g_aba_benign[2], 1, memory_order_relaxed);
    return true;
  }
  return false;
}

u64 GetPointerEpoch(uptr p) {
  // Every pointer-sized atomic value lands here, including integers and
  // tagged pointers. GetBlock computes a meta address from p without a range
  // check, so a value outside application memory would fault.
  if (!IsAppMem(p))
    return 0;
  // Annotated slots first: a slot at the start of a malloc'd slab shares its
  // address with the slab's own heap block.
  if (atomic_load(&g_pool_used, memory_order_relaxed))
    if (u64 e = PoolLookup(p))
      return e;
  if (MBlock *b = ctx->metamap.GetBlock(p))
    return b->alloc_epoch;
  // Interior pointer (intrusive link field, allocator header): use the
  // enclosing block's identity.
  uptr start;
  if (MBlock *b = AbaEnclosingBlock(p, &start))
    return b->alloc_epoch;
  return 0;
}

atomic_uint64_t g_aba_loc_checked, g_aba_loc_reports;

int g_aba_plain = -1;

void AbaPlainLoadSlow(uptr addr, uptr pc) {
  if (g_aba_plain < 0) {
    const char *e = GetEnv("TSAN_ABA_PLAIN");
    g_aba_plain = (e && e[0] == '1') ? 1 : 0;
    if (!g_aba_plain)
      return;
  }
  if ((addr & (sizeof(uptr) - 1)) || !IsAppMem(addr))
    return;
  AbaRecordLoad(addr, *(volatile uptr *)addr, pc);
}

bool AbaLocationEnabled() {
  static int v = -1;
  if (v < 0) {
    const char *e = GetEnv("TSAN_ABA_LOCATION");
    v = (e && e[0] == '0') ? 0 : 1;  // on by default
  }
  return v;
}

u64 AbaLocationEpoch(uptr addr) {
  if (!IsAppMem(addr))
    return 0;
  // An annotated slot holding the atomic: the nearest slot start at or below
  // addr, up to 64 bytes back (an intrusive link field inside the slot).
  if (atomic_load(&g_pool_used, memory_order_relaxed))
    for (uptr back = 0; back <= 64 && back <= addr; back += sizeof(uptr))
      if (u64 e = PoolLookup(addr - back))
        return e;
  // Globals and stacks have no identity; skip the meta-map walk for them.
  if (addr < HeapMemBeg() || addr >= HeapMemEnd())
    return 0;
  if (MBlock *b = ctx->metamap.GetBlock(addr))
    return b->alloc_epoch;
  uptr start;
  if (MBlock *b = AbaEnclosingBlock(addr, &start))
    return b->alloc_epoch;
  return 0;
}

void AbaReportLocation(uptr addr, uptr expected, uptr desired, u64 then,
                       u64 now, uptr load_pc, uptr cas_pc) {
  Printf(
      "==================\n"
      "WARNING: ThreadSanitizer: ABA detected (location identity change)\n"
      "  Confidence: HIGH -- the object holding the atomic was recycled "
      "between the load and the CAS\n"
      "  Atomic variable at:        %p\n"
      "  Holder epoch at load:      %llu\n"
      "  Holder epoch at CAS:       %llu\n"
      "  expected=%p desired=%p tid=%d\n"
      "==================\n",
      (void *)addr, (unsigned long long)then, (unsigned long long)now,
      (void *)expected, (void *)desired, (int)GetTid());
  AbaPrintPc("note recorded at", load_pc, cas_pc);
  aba_report_count++;
  atomic_fetch_add(&g_aba_reports, 1, memory_order_relaxed);
  atomic_fetch_add(&g_aba_loc_reports, 1, memory_order_relaxed);
}

}  // namespace __tsan

using namespace __tsan;

extern "C" {

SANITIZER_INTERFACE_ATTRIBUTE
void __tsan_aba_pool_alloc(void *addr) {
  atomic_store(&g_pool_used, 1, memory_order_relaxed);
  u64 epoch = atomic_fetch_add(&g_aba_epoch, 1, memory_order_relaxed);
  PoolInsert((uptr)addr, epoch);
}

SANITIZER_INTERFACE_ATTRIBUTE
void __tsan_aba_pool_free(void *addr) { PoolRemove((uptr)addr); }
SANITIZER_INTERFACE_ATTRIBUTE
unsigned long long __tsan_aba_report_count(void) { return aba_report_count; }
}  // extern "C"

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
unsigned long long __tsan_aba_push_suppressed_count(void) {
  return atomic_load(&g_aba_push_suppressed, memory_order_relaxed);
}
