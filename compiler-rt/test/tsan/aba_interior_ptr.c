// RUN: %clang_tsan -O1 -DOFFSET=0 %s -o %t-control && %run %t-control 2>&1 | FileCheck %s --check-prefix=CONTROL
// RUN: %clang_tsan -O1 -DOFFSET=16 %s -o %t-interior && %run %t-interior 2>&1 | FileCheck %s --check-prefix=CONTROL
// RUN: %clang_tsan -O1 -DOFFSET=200 -DBLOCK=256 %s -o %t-far && %run %t-far 2>&1 | FileCheck %s --check-prefix=CONTROL
// RUN: %clang_tsan -O1 -DOFFSET=4000 -DBLOCK=4096 %s -o %t-deep && %run %t-deep 2>&1 | FileCheck %s --check-prefix=CONTROL
//
// Interior pointers. The atomic holds a pointer into the middle of a heap
// block, as intrusive lists do when the link field is not the first member.
// The epoch lookup asks the allocator for the chunk containing the pointer
// (GetBlockBegin), so a pointer at any offset into the block resolves to the
// enclosing block: OFFSET=0, 16, 200 and 4000 must all report.
#include <assert.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef BLOCK
#define BLOCK 64
#endif

static _Atomic(char *) ptr;
static sem_t to_t2, to_t1;

static void *t2(void *arg) {
  (void)arg;
  sem_wait(&to_t2);
  char *blk = atomic_load(&ptr) - OFFSET;
  free(blk);
  char *nb = malloc(BLOCK);      // reuses blk's address with a fresh epoch
  assert(nb == blk);             // ABA precondition
  atomic_store(&ptr, nb + OFFSET);
  sem_post(&to_t1);
  return NULL;
}

int main(void) {
  sem_init(&to_t2, 0, 0);
  sem_init(&to_t1, 0, 0);
  char *blk = malloc(BLOCK);
  atomic_store(&ptr, blk + OFFSET);

  pthread_t th;
  pthread_create(&th, NULL, t2, NULL);

  char *expected = atomic_load(&ptr);
  sem_post(&to_t2);
  sem_wait(&to_t1);

  int ok = atomic_compare_exchange_strong(&ptr, &expected, NULL);
  assert(ok);
  pthread_join(th, NULL);
  fprintf(stderr, "done\n");
  return 0;
}
// CONTROL: WARNING: ThreadSanitizer: ABA detected
// CONTROL: done
