// RUN: %clang_tsan -O1 %s -o %t && %run %t 2>&1 | FileCheck %s
//
// TN: pool value cycles A->B->A but slot A is never returned to the pool (a
// hazard pointer keeps it live), so its identity never changes. Mirrors
// aba_hazard_pointer.c, but through pool annotation on two static slots
// instead of malloc/free.
#include <stdatomic.h>
#include <stdio.h>
#include <sanitizer/tsan_interface.h>

static int slotA[1], slotB[1];

int main(void) {
  __tsan_aba_pool_alloc(slotA);
  __tsan_aba_pool_alloc(slotB);   // both stay live for the whole run
  _Atomic(int *) ptr = slotA;

  int *expected = atomic_load(&ptr);
  atomic_store(&ptr, slotB);
  atomic_store(&ptr, slotA);      // A->B->A; A was never returned to the pool

  atomic_compare_exchange_strong(&ptr, &expected, slotB);

  fprintf(stderr, "done\n");
  return 0;
}
// CHECK-NOT: ABA detected
// CHECK: done
