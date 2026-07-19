// RUN: %clang_tsan -O1 %s -o %t && %run %t 2>&1 | FileCheck %s
//
// TN: value cycles A->B->A but A is never freed (a hazard pointer keeps it
// live), so its alloc-identity is unchanged. Layer A keys on identity, not
// value, and must stay silent -- the benign case a value-counter would flag.
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
  int *A = malloc(sizeof(int));
  int *B = malloc(sizeof(int));  // both stay live for the whole run
  _Atomic(int *) ptr = A;

  int *expected = atomic_load(&ptr);
  atomic_store(&ptr, B);
  atomic_store(&ptr, A);  // A->B->A; A was never freed

  atomic_compare_exchange_strong(&ptr, &expected, malloc(sizeof(int)));

  fprintf(stderr, "done\n");
  return 0;
}
// CHECK-NOT: ABA detected
// CHECK: done
