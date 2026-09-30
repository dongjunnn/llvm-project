// RUN: %clang_tsan -O1 %s -o %t && %run %t 2>&1 | FileCheck %s
//
// TN: a thread peeks at an atomic, later frees that object, and publishes a
// new allocation that lands at the same address with its own store. Its CAS
// expects the object it just stored, so no identity changed behind its back.
// The store must refresh the thread's cached epoch; otherwise the entry from
// the earlier peek is checked against the new object and reported falsely.
#include <assert.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
  _Atomic(int *) slot;
  atomic_store(&slot, malloc(sizeof(int)));

  int *cur = atomic_load(&slot);  // peek: cached epoch of the old object
  atomic_store(&slot, NULL);
  free(cur);
  int *n = malloc(sizeof(int));   // reuses cur's address with a fresh epoch
  assert(n == cur);               // precondition; INCONCLUSIVE if it fails
  atomic_store(&slot, n);         // own store: this thread knows slot == n

  atomic_compare_exchange_strong(&slot, &n, NULL);

  fprintf(stderr, "done\n");
  return 0;
}
// CHECK-NOT: ABA detected
// CHECK: done
