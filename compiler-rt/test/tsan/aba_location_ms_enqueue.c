// RUN: %clang_tsan -O1 %s -o %t && %run %t 2>&1 | FileCheck %s
// RUN: %clang_tsan -O1 -DRECYCLE=0 %s -o %t-tn && %run %t-tn 2>&1 | FileCheck %s --check-prefix=SILENT
// RUN: %clang_tsan -O1 -DPOOL=1 %s -o %t-pool && %run %t-pool 2>&1 | FileCheck %s
// RUN: %clang_tsan -O1 %s -o %t && env TSAN_ABA_LOCATION=0 %run %t 2>&1 | FileCheck %s --check-prefix=SILENT
//
// TP: location ABA (Michael-Scott enqueue). T1 reads tail->next == NULL and
// is preempted before CAS(&tail->next, NULL, n). Meanwhile the tail node is
// recycled: freed and reallocated at the same address (heap), or popped and
// re-linked into another list (annotated pool, as in libHttpClient's
// LocklessQueue, PR #1053). The expected value NULL carries no identity, so
// the value check is blind; the identity of the object *holding* the atomic
// changed, and the CAS links n into a node that is no longer the tail it saw.
// RECYCLE=0 is the true negative: same interleaving, no recycling.
#include <assert.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sanitizer/tsan_interface.h>
#ifndef RECYCLE
#define RECYCLE 1
#endif
#ifndef POOL
#define POOL 0
#endif

struct node { _Atomic(struct node *) next; long v; };
static struct node slab[4];
static struct node *tail_node;
static sem_t to_t2, to_t1;

static void *t2(void *arg) {
  (void)arg;
  sem_wait(&to_t2);
  if (RECYCLE) {
    struct node *A = tail_node;
    if (POOL) {
      __tsan_aba_pool_alloc(A);  // re-linked into another list: new stint
    } else {
      volatile uintptr_t a = (uintptr_t)A;  // opaque: clang folds malloc() == p
      free(A);
      struct node *B = malloc(sizeof(struct node));  // same address, new epoch
      assert((uintptr_t)B == a);  // ABA precondition; INCONCLUSIVE if it fails
    }
    atomic_store(&A->next, NULL);  // fresh end marker
  }
  sem_post(&to_t1);
  return NULL;
}

int main(void) {
  sem_init(&to_t2, 0, 0);
  sem_init(&to_t1, 0, 0);
  if (POOL) {
    tail_node = &slab[0];
    __tsan_aba_pool_alloc(tail_node);
  } else {
    tail_node = malloc(sizeof(struct node));
  }
  atomic_store(&tail_node->next, NULL);

  pthread_t th;
  pthread_create(&th, NULL, t2, NULL);

  struct node *t = tail_node;
  struct node *next = atomic_load(&t->next);  // NULL: this is the tail
  sem_post(&to_t2);
  sem_wait(&to_t1);  // T2 recycles the tail node

  struct node *n = POOL ? &slab[1] : malloc(sizeof(struct node));
  atomic_compare_exchange_strong(&t->next, &next, n);
  pthread_join(th, NULL);
  fprintf(stderr, "done\n");
  return 0;
}
// CHECK: WARNING: ThreadSanitizer: ABA detected (location identity change)
// SILENT-NOT: ABA detected
// SILENT: done
