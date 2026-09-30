// RUN: %clang_tsan -O1 %s -o %t && %run %t 2>&1 | FileCheck %s
//
// TP: ABA on a CAS retry. In a Treiber pop, a failed compare_exchange copies
// the current head into `old`, and the retry uses that value without another
// atomic_load. Here the value handed back by the failed CAS (node C) is
// popped, freed and reallocated by another thread before the retry, so the
// retry CAS succeeds against a different object at the same address.
// Semaphores force the interleaving, so the test is deterministic.
#include <assert.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct Node { struct Node *next; } Node;

static _Atomic(Node *) head;
static Node *X, *A;
static sem_t to_t2, to_t1;

static void *t2(void *arg) {
  (void)arg;
  sem_wait(&to_t2);
  Node *C = malloc(sizeof(Node));   // push C: head = C -> A -> X
  C->next = A;
  atomic_store(&head, C);
  sem_post(&to_t1);

  sem_wait(&to_t2);
  atomic_store(&head, X);           // pop C and A
  free(C);
  Node *C2 = malloc(sizeof(Node));  // reuses C's address with a fresh epoch
  assert(C2 == C);                  // ABA precondition; INCONCLUSIVE if it fails
  C2->next = X;
  atomic_store(&head, C2);          // push C2: head = C2 -> X
  sem_post(&to_t1);
  return NULL;
}

int main(void) {
  sem_init(&to_t2, 0, 0);
  sem_init(&to_t1, 0, 0);
  X = malloc(sizeof(Node));
  X->next = NULL;
  A = malloc(sizeof(Node));
  A->next = X;
  atomic_store(&head, A);

  pthread_t th;
  pthread_create(&th, NULL, t2, NULL);

  Node *old = atomic_load(&head);   // old = A
  Node *next = old->next;
  sem_post(&to_t2);
  sem_wait(&to_t1);                 // T2 pushes C

  int ok = atomic_compare_exchange_strong(&head, &old, next);
  assert(!ok);                      // fails; old = C, never atomic_load'ed
  next = old->next;                 // next = A
  sem_post(&to_t2);
  sem_wait(&to_t1);                 // T2 frees C and pushes C2 at its address

  ok = atomic_compare_exchange_strong(&head, &old, next);
  assert(ok);                       // retry succeeds against C2

  pthread_join(th, NULL);
  fprintf(stderr, "done\n");
  return 0;
}
// CHECK: WARNING: ThreadSanitizer: ABA detected
// CHECK: done
