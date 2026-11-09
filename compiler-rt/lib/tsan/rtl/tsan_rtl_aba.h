//===-- tsan_rtl_aba.h ------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of ThreadSanitizer (TSan), a race detector.
//
// ABA detection. Every tracked object carries a monotonic allocation epoch.
// A successful CAS checks that the epoch under the expected pointer still
// matches the one recorded at the load that produced it.
//
//===----------------------------------------------------------------------===//
#ifndef TSAN_RTL_ABA_H
#define TSAN_RTL_ABA_H

#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_common.h"
#include "tsan_defs.h"

namespace __tsan {

#if SANITIZER_GO

// Go has its own allocator and no annotation API; the detector is C/C++ only.
static inline void AbaRecordLoad(uptr addr, uptr value, uptr pc = 0) {}
static inline void AbaForget(uptr addr) {}
static inline void AbaCheckCas(uptr addr, uptr expected, uptr desired, uptr pc = 0) {}

#else

// Monotonic allocation identity; 0 is reserved for dead or untracked memory.
extern atomic_uint64_t g_aba_epoch;

// Epoch of the object starting at p, or 0 if p starts no tracked object.
// Resolves heap blocks first, then annotated pool slots.
u64 GetPointerEpoch(uptr p);

// EXPERIMENT (location ABA): identity of the heap block or annotated pool slot
// that holds the atomic variable at addr, or 0 for globals, stacks, untracked
// memory. A CAS on a field of an object that was recycled after the load is
// ABA on the location itself (Michael-Scott enqueue: CAS(&tail->next, END, n)
// on a tail node that was popped and re-linked elsewhere), even when the value
// compared is a NULL/end token the value check cannot track.
u64 AbaLocationEpoch(uptr addr);
bool AbaLocationEnabled();
extern atomic_uint64_t g_aba_loc_checked, g_aba_loc_reports;
void AbaReportLocation(uptr addr, uptr expected, uptr desired, u64 then, u64 now,
                       uptr load_pc, uptr cas_pc);

// EXPERIMENT: true if the object at `desired` holds the pointer `expected` in
// one of its words -- the signature of a push-style CAS (n->next == expected),
// which only uses the old object's address and so tolerates ABA.
// pop_like: desired was read out of the expected object at load time (it is
// one of the words snapshotted then), so this is a pop and the push filter,
// which would match a stale link left inside a recycled desired, must not apply.
bool AbaDesiredLinksTo(uptr desired, uptr expected, bool pop_like = false);
// Snapshot the first kAbaSnapWords words of the object at value (tracked only).
static const uptr kAbaSnapWords = 2;
void AbaSnapshot(uptr value, uptr *snap);
void AbaPrintPc(const char *what, uptr pc, uptr cas_pc);
void AbaDebugObject(const char *what, uptr p);
extern atomic_uint64_t g_aba_push_suppressed;
// EXPERIMENT: CASes whose expected object is not allocated at CAS time
// (a dangling token, e.g. an exchange emulated with a CAS loop).
extern atomic_uint64_t g_aba_freed_suppressed;
bool AbaReportFreed();
// EXPERIMENT: coverage counters, printed at exit with TSAN_OPTIONS=verbosity=1
extern atomic_uint64_t g_aba_loads, g_aba_loads_tracked, g_aba_cas_checked, g_aba_reports;
void AbaPrintStats();

// Per-thread cache: 16 sets x 4 ways, keyed by the atomic variable's address.
static const uptr kAbaSets = 16;
static const uptr kAbaWays = 4;

struct AbaEntry {
  uptr addr;        // atomic variable address (key); 0 == empty
  uptr loaded_ptr;  // pointer value observed at load
  u64  epoch;       // its alloc epoch at load time (0: value untracked)
  u64  loc_epoch;   // identity of the object holding the atomic (0: none)
  uptr snap[kAbaSnapWords];  // first words of the loaded object at load time
  u32  lru;         // last-touch tick, for eviction
  uptr pc;          // EXPERIMENT: caller pc of the recording op
};

struct AbaCache {
  AbaEntry sets[kAbaSets][kAbaWays];
  u32 tick;
};

// Defined out of line: a static definition here would give each including
// translation unit its own copy, splitting the record path from the check path.
__attribute__((tls_model("initial-exec")))
extern THREADLOCAL AbaCache aba_cache;

// Per-thread count of ABA reports; lets tests attribute a report to one CAS.
__attribute__((tls_model("initial-exec")))
extern THREADLOCAL u64 aba_report_count;

static inline uptr AbaSetIndex(uptr addr) {
  // Multiplicative hash: (addr >> 3) & 15 put cache-line-aligned nodes into
  // only 2 of the 16 sets.
  return (uptr)(((u64)addr * 0x9E3779B97F4A7C15ull) >> 60) & (kAbaSets - 1);
}

// Record a loaded pointer's epoch and the identity of the atomic's holder.
// Notes with neither (untracked value in untracked memory) are dropped.
static inline void AbaRecordLoad(uptr addr, uptr value, uptr pc = 0) {
  atomic_fetch_add(&g_aba_loads, 1, memory_order_relaxed);
  u64 epoch = GetPointerEpoch(value);
  u64 loc = AbaLocationEnabled() ? AbaLocationEpoch(addr) : 0;
  if (epoch == 0 && loc == 0) {
    // The thread now knows the atomic holds an untracked value: an older note
    // for it is stale and must not be checked against a later CAS.
    AbaEntry *set = aba_cache.sets[AbaSetIndex(addr)];
    for (uptr i = 0; i < kAbaWays; i++)
      if (set[i].addr == addr)
        set[i].addr = 0;
    return;
  }
  atomic_fetch_add(&g_aba_loads_tracked, 1, memory_order_relaxed);
  AbaEntry *set = aba_cache.sets[AbaSetIndex(addr)];
  AbaEntry *slot = &set[0];
  for (uptr i = 0; i < kAbaWays; i++) {
    if (set[i].addr == addr || set[i].addr == 0) {  // hit or empty slot
      slot = &set[i];
      break;
    }
    if (set[i].lru < slot->lru)  // else track the LRU victim
      slot = &set[i];
  }
  slot->addr = addr;
  slot->loaded_ptr = value;
  slot->epoch = epoch;
  slot->loc_epoch = loc;
  if (epoch)
    AbaSnapshot(value, slot->snap);
  else
    for (uptr i = 0; i < kAbaSnapWords; i++) slot->snap[i] = 0;
  slot->lru = ++aba_cache.tick;
  slot->pc = pc;
}

// EXPERIMENT (plain loads): with TSAN_ABA_PLAIN=1, 8-byte plain/volatile reads
// also record notes, so a CAS whose expected value or holder was read without
// an atomic load (C code with volatile, `tail->next` field reads, __sync CAS)
// is checked too. Off by default: one predictable branch per 8-byte read.
extern int g_aba_plain;  // -1 unknown, 0 off, 1 on
void AbaPlainLoadSlow(uptr addr, uptr pc);
static ALWAYS_INLINE void AbaPlainLoad(uptr addr, uptr pc) {
  if (UNLIKELY(g_aba_plain != 0))
    AbaPlainLoadSlow(addr, pc);
}

// The atomic was changed in a way we don't model (fetch-op): drop the note.
static inline void AbaForget(uptr addr) {
  AbaEntry *set = aba_cache.sets[AbaSetIndex(addr)];
  for (uptr i = 0; i < kAbaWays; i++)
    if (set[i].addr == addr)
      set[i].addr = 0;
}

// On a successful CAS, fire if expected's epoch changed since the load.
static inline void AbaCheckCas(uptr addr, uptr expected, uptr desired, uptr pc = 0) {
  AbaEntry *set = aba_cache.sets[AbaSetIndex(addr)];
  AbaEntry *e = nullptr;
  for (uptr i = 0; i < kAbaWays; i++) {
    if (set[i].addr == addr) {
      e = &set[i];
      break;
    }
  }
  if (!e || e->loaded_ptr != expected)
    return;
  if (e->loc_epoch) {
    atomic_fetch_add(&g_aba_loc_checked, 1, memory_order_relaxed);
    u64 loc_now = AbaLocationEpoch(addr);
    // loc_now == 0: the holder was freed -- a use-after-free, not ours to
    // report (ASan's job), and too easily a benign teardown race.
    if (loc_now != 0 && loc_now != e->loc_epoch) {
      AbaReportLocation(addr, expected, desired, e->loc_epoch, loc_now, e->pc, pc);
      e->addr = 0;
      return;
    }
  }
  if (e->epoch == 0)
    return;  // value untracked: only the location could be checked
  atomic_fetch_add(&g_aba_cas_checked, 1, memory_order_relaxed);
  u64 now = GetPointerEpoch(expected);
  bool pop_like = false;
  for (uptr i = 0; i < kAbaSnapWords; i++)
    if (desired && e->snap[i] == desired)
      pop_like = true;
  if (now != e->epoch && AbaDesiredLinksTo(desired, expected, pop_like)) {
    atomic_fetch_add(&g_aba_push_suppressed, 1, memory_order_relaxed);
    e->addr = 0;
    return;
  }
  if (now != e->epoch && now == 0 && !AbaReportFreed()) {
    // The location holds the address of a block that is not allocated now:
    // nothing came back as "A", the value is only a stale token (hazard slot,
    // exchange emulated with a CAS loop). Not identity reuse.
    atomic_fetch_add(&g_aba_freed_suppressed, 1, memory_order_relaxed);
    e->addr = 0;
    return;
  }
  if (now != e->epoch) {
    Printf(
        "==================\n"
        "WARNING: ThreadSanitizer: ABA detected (heap object identity "
        "change)\n"
        "  Confidence: %s -- object at %p %s\n"
        "  Atomic variable at:        %p\n"
        "  Allocation epoch at load:  %llu\n"
        "  Allocation epoch at CAS:   %llu\n"
        "==================\n",
        now ? "HIGH" : "LOW", (void *)expected,
        now ? "was freed and reallocated" : "is freed (dangling value)",
        (void *)addr, (unsigned long long)e->epoch,
        (unsigned long long)now);
    Printf("  desired=%p  expected-word0-now=%p  tid=%d\n", (void *)desired,
           now ? *(void **)expected : nullptr, (int)GetTid());
    AbaDebugObject("desired", desired);
    AbaDebugObject("expected", expected);
    AbaPrintPc("note recorded at", e->pc, pc);
    aba_report_count++;
    atomic_fetch_add(&g_aba_reports, 1, memory_order_relaxed);
    e->addr = 0;  // consume; don't re-report this slot
  }
}

#endif  // SANITIZER_GO

}  // namespace __tsan

#endif  // TSAN_RTL_ABA_H
