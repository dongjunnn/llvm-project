// RUN: %clang_tsan -O1 %s -o %t && %run %t 2>&1 | FileCheck %s
//
// TP: heap-reuse ABA. A pointer is loaded, its object freed, and the address
// reused by a new allocation; a CAS against the old value then succeeds even
// though the object identity changed. The free/realloc/store runs on a second
// thread: a thread's own store refreshes its cached epoch, so doing it on the
// loading thread would not be ABA. Semaphores make the interleaving
// deterministic.
#include <assert.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdlib.h>

static _Atomic(int *) ptr;
static sem_t to_t2, to_t1;

static void *t2(void *arg) {
  (void)arg;
  sem_wait(&to_t2);
  int *A = atomic_load(&ptr);
  free(A);
  int *B = malloc(sizeof(int));  // reuses A's address with a fresh epoch
  assert(B == A);                // ABA precondition; INCONCLUSIVE if it fails
  atomic_store(&ptr, B);
  sem_post(&to_t1);
  return NULL;
}

int main(void) {
  sem_init(&to_t2, 0, 0);
  sem_init(&to_t1, 0, 0);
  atomic_store(&ptr, malloc(sizeof(int)));

  pthread_t th;
  pthread_create(&th, NULL, t2, NULL);

  int *expected = atomic_load(&ptr);
  sem_post(&to_t2);
  sem_wait(&to_t1);              // T2 frees A and stores B at its address

  atomic_compare_exchange_strong(&ptr, &expected, malloc(sizeof(int)));
  pthread_join(th, NULL);
  return 0;
}
// CHECK: WARNING: ThreadSanitizer: ABA detected
