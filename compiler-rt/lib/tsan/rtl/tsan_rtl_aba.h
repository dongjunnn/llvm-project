#ifndef TSAN_RTL_ABA_H
#define TSAN_RTL_ABA_H

#include "sanitizer_common/sanitizer_common.h"
#include "tsan_defs.h"
#include "tsan_mman.h"

namespace __tsan {

// Per-thread cache: 16 sets x 4 ways, keyed by the atomic variable's address.
static const uptr kAbaSets = 16;
static const uptr kAbaWays = 4;

struct AbaEntry {
  uptr addr;        // atomic variable address (key); 0 == empty
  uptr loaded_ptr;  // pointer value observed at load
  u8   epoch;       // its alloc epoch at load time
  u32  lru;         // last-touch tick, for eviction
};

struct AbaCache {
  AbaEntry sets[kAbaSets][kAbaWays];
  u32 tick;
};

__attribute__((tls_model("initial-exec")))
static THREADLOCAL AbaCache aba_cache;

static inline uptr AbaSetIndex(uptr addr) {
  return (addr >> 3) & (kAbaSets - 1);  // atomics are >= pointer-aligned
}

// Record a loaded pointer's epoch. Non-heap values (epoch 0) are ignored.
static inline void AbaRecordLoad(uptr addr, uptr value) {
  u8 epoch = GetAllocEpoch(value);
  if (epoch == 0)
    return;
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
}

// On a successful CAS, fire if `expected`'s current epoch differs from the one
// recorded at load time -- i.e. the object was freed and reallocated.
static inline void AbaCheckCas(uptr addr, uptr expected) {
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
  u8 now = GetAllocEpoch(expected);
  if (now != e->epoch) {
    Printf(
        "==================\n"
        "WARNING: ThreadSanitizer: ABA detected (heap object identity "
        "change)\n"
        "  Confidence: HIGH -- object at %p was freed and reallocated\n"
        "  Atomic variable at:        %p\n"
        "  Allocation epoch at load:  %u\n"
        "  Allocation epoch at CAS:   %u\n"
        "==================\n",
        (void *)expected, (void *)addr, (unsigned)e->epoch, (unsigned)now);
    e->addr = 0;  // consume; don't re-report this slot
  }
}

}  // namespace __tsan

#endif  // TSAN_RTL_ABA_H
