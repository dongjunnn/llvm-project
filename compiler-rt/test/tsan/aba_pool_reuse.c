// RUN: %clang_tsan -O1 %s -o %t && %run %t 2>&1 | FileCheck %s
//
// TP: pool-slot-reuse ABA. A pointer to an annotated pool slot is loaded,
// the slot is returned to the pool and immediately handed out again, and a
// CAS against the old value succeeds even though the slot's identity
// changed underneath it. Mirrors aba_heap_reuse.c, but through
// __tsan_aba_pool_alloc/free on a static slot instead of malloc/free, so
// the address never touches TSan's own allocator (GetBlock must find
// nothing here -- this is a clean test of the pool table in isolation).
// The recycle and store run on a second thread, as in aba_heap_reuse.c.
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <sanitizer/tsan_interface.h>

static int slot[1];
static _Atomic(int *) ptr;
static sem_t to_t2, to_t1;

static void *t2(void *arg) {
  (void)arg;
  sem_wait(&to_t2);
  __tsan_aba_pool_free(slot);    // return it to the pool
  __tsan_aba_pool_alloc(slot);   // reused immediately: same address, epoch N+1
  atomic_store(&ptr, slot);
  sem_post(&to_t1);
  return NULL;
}

int main(void) {
  sem_init(&to_t2, 0, 0);
  sem_init(&to_t1, 0, 0);
  __tsan_aba_pool_alloc(slot);   // hand out the slot: epoch N
  atomic_store(&ptr, slot);

  pthread_t th;
  pthread_create(&th, NULL, t2, NULL);

  int *expected = atomic_load(&ptr);
  sem_post(&to_t2);
  sem_wait(&to_t1);              // T2 recycles the slot

  atomic_compare_exchange_strong(&ptr, &expected, slot);
  pthread_join(th, NULL);
  return 0;
}
// CHECK: WARNING: ThreadSanitizer: ABA detected
