// RUN: %clang_tsan -O1 %s -o %t && %run %t 2>&1 | FileCheck %s
//
// TN: object stays live between load and CAS (deferred reclamation), so its
// alloc-identity is unchanged and the detector must not fire.
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
  int *A = malloc(sizeof(int));
  _Atomic(int *) ptr = A;

  int *expected = atomic_load(&ptr);
  int *B = malloc(sizeof(int));  // A not freed -> cannot reuse A's slot
  (void)B;
  atomic_compare_exchange_strong(&ptr, &expected, malloc(sizeof(int)));

  fprintf(stderr, "done\n");
  return 0;
}
// CHECK-NOT: ABA detected
// CHECK: done
