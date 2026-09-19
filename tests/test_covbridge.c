#include "../covbridge.h"

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

void covbridgeTestWorkload(const uint8_t *data, size_t size);

static _Atomic int holdLastClose;
static _Atomic int lastCloseReached;
static _Atomic int releaseLastClose;

void cb_test_last_connection_closed(uint64_t run_id) {
  (void)run_id;
  if (!atomic_load_explicit(&holdLastClose, memory_order_acquire)) {
    return;
  }
  atomic_store_explicit(&lastCloseReached, 1, memory_order_release);
  while (!atomic_load_explicit(&releaseLastClose, memory_order_acquire)) {
    sched_yield();
  }
}

typedef struct {
  uint64_t run;
  int result;
  int error;
} closeAttempt;

static void *closeLastConnection(void *parameter) {
  closeAttempt *attempt = parameter;
  attempt->result = cb_connection_end(attempt->run);
  attempt->error = errno;
  return NULL;
}

static void waitForChild(pid_t child) {
  int status;
  assert(waitpid(child, &status, 0) == child);
  assert(WIFEXITED(status));
  assert(WEXITSTATUS(status) == 0);
}

int main(void) {
  const uint8_t input[] = {'A', 'B', 'C'};
  const uint8_t baselineInput[] = {'Z'};
  cb_snapshot baseline = {0};
  cb_snapshot snapshot = {0};
  uint64_t baselineRun;
  uint64_t firstRun;
  uint64_t isolationRun;
  uint64_t staleRun;
  uint64_t recoveredRun;
  uint64_t raceRun;
  uint64_t total = 0;
  uint32_t index;
  int runs[2];
  pid_t child;
  pthread_t closer;
  closeAttempt attempt;

  assert(cb_slots() > 0);
  assert(cb_init(UINT64_C(0x4150465a74657374)) == 0);
  assert(cb_claim_controller(0) == 0);
  assert(cb_begin(&firstRun) == 0);

  child = fork();
  assert(child >= 0);
  if (child == 0) {
    uint64_t run = cb_connection_begin();
    assert(run == firstRun);
    covbridgeTestWorkload(input, sizeof(input));
    cb_thread_pause();
    covbridgeTestWorkload(input, sizeof(input));
    cb_thread_resume(run);
    covbridgeTestWorkload(input, sizeof(input));
    assert(cb_connection_end(run) == 0);
    _exit(0);
  }
  waitForChild(child);
  assert(cb_wait_snapshot(firstRun, &snapshot, 1000) == 0);
  for (index = 0; index < snapshot.nslots; index++) {
    total += snapshot.counts[index];
  }
  assert(total > 0);
  assert(cb_libfuzzer_import(&snapshot, 0) == 0);

  assert(pipe(runs) == 0);
  child = fork();
  assert(child >= 0);
  if (child == 0) {
    uint64_t run;
    close(runs[0]);
    assert(cb_claim_controller(0) == 0);
    assert(cb_begin(&run) == 0);
    assert(cb_connection_begin() == run);
    assert(write(runs[1], &run, sizeof(run)) == (ssize_t)sizeof(run));
    close(runs[1]);
    _exit(0); /* Simulate a controller dying before connection cleanup. */
  }
  close(runs[1]);
  assert(read(runs[0], &staleRun, sizeof(staleRun)) ==
         (ssize_t)sizeof(staleRun));
  close(runs[0]);
  waitForChild(child);

  assert(cb_claim_controller(10) == 0);
  assert(cb_begin(&recoveredRun) == 0);
  assert(recoveredRun > staleRun);
  assert(cb_connection_end(staleRun) == -1);
  assert(errno == ESTALE);
  assert(cb_cancel(recoveredRun) == 0);

  /* Record the exact feedback for run B before exercising the boundary. */
  assert(cb_begin(&baselineRun) == 0);
  assert(cb_connection_begin() == baselineRun);
  covbridgeTestWorkload(baselineInput, sizeof(baselineInput));
  assert(cb_connection_end(baselineRun) == 0);
  assert(cb_wait_snapshot(baselineRun, &baseline, 1000) == 0);

  /* Hold the last close after its gate transition but before it publishes
     completion. Admission must already be closed throughout this interval.
     The main thread deliberately retains run A in thread-local state. */
  assert(cb_begin(&raceRun) == 0);
  assert(cb_connection_begin() == raceRun);
  covbridgeTestWorkload(input, sizeof(input));
  atomic_store_explicit(&lastCloseReached, 0, memory_order_relaxed);
  atomic_store_explicit(&releaseLastClose, 0, memory_order_relaxed);
  atomic_store_explicit(&holdLastClose, 1, memory_order_release);
  attempt.run = raceRun;
  attempt.result = -1;
  attempt.error = 0;
  assert(pthread_create(&closer, NULL, closeLastConnection, &attempt) == 0);
  while (!atomic_load_explicit(&lastCloseReached, memory_order_acquire)) {
    sched_yield();
  }
  assert(cb_connection_begin() == 0);
  atomic_store_explicit(&releaseLastClose, 1, memory_order_release);
  assert(pthread_join(closer, NULL) == 0);
  assert(attempt.result == 0);
  atomic_store_explicit(&holdLastClose, 0, memory_order_release);
  assert(cb_wait_snapshot(raceRun, &snapshot, 1000) == 0);

  /* Run B starts with zeroed counters. Work attempted with the retained run A
     tag must not alter B before a proper B connection contributes feedback. */
  assert(cb_begin(&isolationRun) == 0);
  covbridgeTestWorkload(input, sizeof(input));
  assert(cb_connection_begin() == isolationRun);
  covbridgeTestWorkload(baselineInput, sizeof(baselineInput));
  assert(cb_connection_end(isolationRun) == 0);
  assert(cb_wait_snapshot(isolationRun, &snapshot, 1000) == 0);
  assert(snapshot.layout_id == baseline.layout_id);
  assert(snapshot.mode == baseline.mode);
  assert(snapshot.nslots == baseline.nslots);
  for (index = 0; index < snapshot.nslots; index++) {
    assert(snapshot.counts[index] == baseline.counts[index]);
  }

  cb_snapshot_free(&baseline);
  cb_snapshot_free(&snapshot);
  puts("PASS covbridge shared feedback, run isolation, atomic boundary, "
       "and recovery");
  return 0;
}
