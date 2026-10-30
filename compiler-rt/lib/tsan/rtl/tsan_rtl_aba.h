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

// EXPERIMENT: true if the object at `desired` holds the pointer `expected` in
// one of its words -- the signature of a push-style CAS (n->next == expected),
// which only uses the old object's address and so tolerates ABA.
bool AbaDesiredLinksTo(uptr desired, uptr expected);
void AbaPrintPc(const char *what, uptr pc, uptr cas_pc);
extern atomic_uint64_t g_aba_push_suppressed;
// EXPERIMENT: coverage counters, printed at exit with TSAN_OPTIONS=verbosity=1
extern atomic_uint64_t g_aba_loads, g_aba_loads_tracked, g_aba_cas_checked, g_aba_reports;
void AbaPrintStats();

// Per-thread cache: 16 sets x 4 ways, keyed by the atomic variable's address.
static const uptr kAbaSets = 16;
static const uptr kAbaWays = 4;

struct AbaEntry {
  uptr addr;        // atomic variable address (key); 0 == empty
  uptr loaded_ptr;  // pointer value observed at load
  u64  epoch;       // its alloc epoch at load time
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

// Record a loaded pointer's epoch. Untracked values (epoch 0) are ignored.
static inline void AbaRecordLoad(uptr addr, uptr value, uptr pc = 0) {
  atomic_fetch_add(&g_aba_loads, 1, memory_order_relaxed);
  u64 epoch = GetPointerEpoch(value);
  if (epoch == 0) {
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
  slot->lru = ++aba_cache.tick;
  slot->pc = pc;
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
  atomic_fetch_add(&g_aba_cas_checked, 1, memory_order_relaxed);
  u64 now = GetPointerEpoch(expected);
  if (now != e->epoch && AbaDesiredLinksTo(desired, expected)) {
    atomic_fetch_add(&g_aba_push_suppressed, 1, memory_order_relaxed);
    e->addr = 0;
    return;
  }
  if (now != e->epoch) {
    Printf(
        "==================\n"
        "WARNING: ThreadSanitizer: ABA detected (heap object identity "
        "change)\n"
        "  Confidence: HIGH -- object at %p was freed and reallocated\n"
        "  Atomic variable at:        %p\n"
        "  Allocation epoch at load:  %llu\n"
        "  Allocation epoch at CAS:   %llu\n"
        "==================\n",
        (void *)expected, (void *)addr, (unsigned long long)e->epoch,
        (unsigned long long)now);
    Printf("  desired=%p  expected-word0-now=%p  tid=%d\n", (void *)desired,
           now ? *(void **)expected : nullptr, (int)GetTid());
    AbaPrintPc("note recorded at", e->pc, pc);
    aba_report_count++;
    atomic_fetch_add(&g_aba_reports, 1, memory_order_relaxed);
    e->addr = 0;  // consume; don't re-report this slot
  }
}

#endif  // SANITIZER_GO

}  // namespace __tsan

#endif  // TSAN_RTL_ABA_H
