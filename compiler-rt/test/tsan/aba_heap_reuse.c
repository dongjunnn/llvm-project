// RUN: %clang_tsan -O1 %s -o %t && %run %t 2>&1 | FileCheck %s
//
// TP: heap-reuse ABA. A pointer is loaded, its object freed, and the address
// reused by a new allocation; a CAS against the old value then succeeds even
// though the object identity changed. Single-threaded and deterministic.
#include <assert.h>
#include <stdatomic.h>
#include <stdlib.h>

int main(void) {
  int *A = malloc(sizeof(int));
  _Atomic(int *) ptr = A;

  int *expected = atomic_load(&ptr);
  free(A);
  int *B = malloc(sizeof(int));  // reuses A's address with a fresh epoch
  assert(B == A);                // ABA precondition; INCONCLUSIVE if it fails
  atomic_store(&ptr, B);

  atomic_compare_exchange_strong(&ptr, &expected, malloc(sizeof(int)));
  return 0;
}
// CHECK: WARNING: ThreadSanitizer: ABA detected
