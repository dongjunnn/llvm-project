// RUN: %clang_tsan -O1 %s -o %t && %run %t 2>&1 | FileCheck %s --check-prefix=SILENT
// RUN: %clang_tsan -O1 %s -o %t && env TSAN_ABA_REPORT_FREED=1 %run %t 2>&1 | FileCheck %s --check-prefix=FREED
//
// FP guard: an exchange emulated with a CAS loop on a slot whose old value is a
// dangling pointer (a hazard-pointer slot still naming a node that has been
// freed and not reused, as in ConcurrencyKit's ck_pr_fas_ptr). The expected
// object is not allocated at CAS time, so nothing came back as "A": silent by
// default, reported at LOW confidence with TSAN_ABA_REPORT_FREED=1.
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

static _Atomic(void *) slot;
static sem_t to_t2, to_t1;
static void *keep;

static void *t2(void *arg) {
  (void)arg;
  sem_wait(&to_t2);
  free(atomic_load(&slot));      // the node the slot names is freed...
  keep = malloc(4096);           // ...and its address is not handed out again
  sem_post(&to_t1);
  return NULL;
}

int main(void) {
  sem_init(&to_t2, 0, 0);
  sem_init(&to_t1, 0, 0);
  atomic_store(&slot, malloc(64));
  pthread_t th;
  pthread_create(&th, NULL, t2, NULL);

  void *old = atomic_load(&slot);
  sem_post(&to_t2);
  sem_wait(&to_t1);
  void *mine = malloc(64);
  while (!atomic_compare_exchange_weak(&slot, &old, mine)) {
  }                              // exchange via CAS loop
  pthread_join(th, NULL);
  free(mine);
  free(keep);
  fprintf(stderr, "done\n");
  return 0;
}
// SILENT-NOT: ABA detected
// SILENT: done
// FREED: ABA detected
// FREED: Confidence: LOW
// FREED: done
