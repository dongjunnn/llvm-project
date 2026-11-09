// RUN: %clang_tsan -O1 -DFIELD_OFF=8 %s -o %t-near && %run %t-near 2>&1 | FileCheck %s
// RUN: %clang_tsan -O1 -DFIELD_OFF=1024 %s -o %t-deep && %run %t-deep 2>&1 | FileCheck %s
// RUN: %clang_tsan -O1 -DFIELD_OFF=1024 %s -o %t-off && env TSAN_ABA_LOCATION=0 %run %t-off 2>&1 | FileCheck %s --check-prefix=OFF
//
// Location ABA with the atomic deep inside its holder: a node with a large
// payload before its `next` link, as in a Michael-Scott queue node. T1 loads
// node->next (NULL); T2 frees the node and the allocator hands the same
// address back as a new node whose next is NULL again; T1's CAS(NULL -> x)
// succeeds on the recycled node. The holder is found by the allocator's
// interior-pointer lookup, so the field offset does not matter.
#include <assert.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

struct node {
  char payload[FIELD_OFF];
  _Atomic(struct node *) next;
};

static struct node *volatile shared;
static sem_t to_t2, to_t1;

static void *t2(void *arg) {
  (void)arg;
  sem_wait(&to_t2);
  struct node *old = shared;
  free(old);
  struct node *n = malloc(sizeof(struct node));  // same address, fresh block
  assert(n == old);
  atomic_store(&n->next, NULL);
  shared = n;
  sem_post(&to_t1);
  return NULL;
}

int main(void) {
  sem_init(&to_t2, 0, 0);
  sem_init(&to_t1, 0, 0);
  struct node *n = malloc(sizeof(struct node));
  atomic_store(&n->next, NULL);
  shared = n;
  pthread_t th;
  pthread_create(&th, NULL, t2, NULL);

  struct node *expected = atomic_load(&n->next);   // NULL, holder epoch noted
  sem_post(&to_t2);
  sem_wait(&to_t1);
  struct node *x = malloc(sizeof(struct node));
  int ok = atomic_compare_exchange_strong(&n->next, &expected, x);
  assert(ok);
  pthread_join(th, NULL);
  fprintf(stderr, "done\n");
  return 0;
}
// CHECK: WARNING: ThreadSanitizer: ABA detected (location identity change)
// CHECK: done
// OFF-NOT: ABA detected
// OFF: done
