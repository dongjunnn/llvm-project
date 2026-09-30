// RUN: %clang_tsan -O1 %s -o %t && %run %t 2>&1 | FileCheck %s
//
// TN: pointer-sized atomics holding values that are not application addresses
// (a timestamp, a counter-in-high-bits tagged pointer) reach the ABA hooks
// like any pointer. The detector must skip them: no report and no crash from
// looking up metadata for a non-address.
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define PACK(p, tag) (((uint64_t)(tag) << 48) | (uint64_t)(uintptr_t)(p))

int main(void) {
  _Atomic uint64_t last_seen;
  atomic_store(&last_seen, 0x17f7895997198000ull);  // ns timestamp
  uint64_t t = atomic_load(&last_seen);
  atomic_compare_exchange_strong(&last_seen, &t, t + 1);

  int *A = malloc(sizeof(int));
  _Atomic uint64_t top;
  atomic_store(&top, PACK(A, 1));
  uint64_t e = atomic_load(&top);
  atomic_compare_exchange_strong(&top, &e, PACK(A, 2));

  fprintf(stderr, "done\n");
  return 0;
}
// CHECK-NOT: ABA detected
// CHECK: done
