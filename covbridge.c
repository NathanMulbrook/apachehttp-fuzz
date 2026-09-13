/* SPDX-License-Identifier: MIT
 * Adapted from covbridge 0.1's guard and libFuzzer backends for Apache httpd.
 * This file must be compiled without SanitizerCoverage instrumentation.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "covbridge.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#if defined(__clang__)
#pragma clang attribute push(__attribute__((no_sanitize("coverage"))), apply_to = function)
#endif

_Static_assert(CB_MAX_EDGES % 64 == 0,
               "counter capacity must be a multiple of 64");
_Static_assert(__atomic_always_lock_free(sizeof(uint64_t), 0),
               "guard backend requires lock-free 64-bit atomics");
_Static_assert(__atomic_always_lock_free(sizeof(uint32_t), 0),
               "guard backend requires lock-free 32-bit atomics");

#define CB_GATE_ACTIVE_BITS 20u
#define CB_GATE_ACTIVE_MASK ((UINT64_C(1) << CB_GATE_ACTIVE_BITS) - 1)
#define CB_GATE_RUN_BITS 42u
#define CB_GATE_RUN_MASK ((UINT64_C(1) << CB_GATE_RUN_BITS) - 1)
#define CB_GATE_FINALIZING (UINT64_C(1) << 62)
#define CB_GATE_ENABLED (UINT64_C(1) << 63)

_Static_assert(CB_GATE_ACTIVE_BITS + CB_GATE_RUN_BITS + 2u == 64u,
               "gate fields must fill one 64-bit atomic");

typedef struct {
  uint64_t layout_id;
  _Atomic uint64_t run_id;
  _Atomic uint64_t completed_run;
  _Atomic uint64_t controller_pid;
  _Atomic uint64_t gate;
  _Atomic uint32_t overflow;
  _Atomic uint64_t counts[];
} shared_map;

static shared_map *map;
static uint32_t nslots;
static _Thread_local uint64_t thread_run;

static int64_t monotonicMilliseconds(void);

static uint64_t gateForRun(uint64_t run_id) {
  return run_id << CB_GATE_ACTIVE_BITS;
}

static uint64_t gateRun(uint64_t gate) {
  return (gate >> CB_GATE_ACTIVE_BITS) & CB_GATE_RUN_MASK;
}

static uint64_t gateActive(uint64_t gate) {
  return gate & CB_GATE_ACTIVE_MASK;
}

static int gateAllowsRun(uint64_t gate, uint64_t run_id) {
  return (gate & CB_GATE_ENABLED) != 0 && gateRun(gate) == run_id;
}

#if defined(CB_TESTING)
extern void cb_test_last_connection_closed(uint64_t run_id);
#endif

__attribute__((section("__libfuzzer_extra_counters"), used, aligned(64)))
static uint8_t extra[CB_MAX_EDGES];

static void badRegistration(void) {
  static const char message[] =
      "covbridge: too many edges or instrumented code loaded after cb_init\n";
  (void)write(STDERR_FILENO, message, sizeof(message) - 1);
  _exit(125);
}

void __wrap___sanitizer_cov_trace_pc_guard_init(uint32_t *start,
                                                uint32_t *end) {
  uint32_t *guard;
  size_t count;

  if (start == end || *start) {
    return;
  }
  count = (size_t)(end - start);
  if (map != NULL || count > CB_MAX_EDGES - nslots) {
    badRegistration();
  }
  for (guard = start; guard < end; guard++) {
    *guard = ++nslots;
  }
}

void __wrap___sanitizer_cov_trace_pc_guard(uint32_t *guard) {
  uint64_t gate;
  uint64_t old;
  uint64_t run = thread_run;

  if (map == NULL || guard == NULL || *guard == 0 || run == 0) {
    return;
  }
  gate = atomic_load_explicit(&map->gate, memory_order_acquire);
  if (!gateAllowsRun(gate, run)) {
    return;
  }
  old = atomic_fetch_add_explicit(&map->counts[*guard - 1], 1,
                                  memory_order_relaxed);
  if (old == UINT64_MAX) {
    atomic_store_explicit(&map->overflow, 1, memory_order_relaxed);
  }
}

uint32_t cb_slots(void) { return nslots; }

int cb_init(uint64_t layout_id) {
  shared_map *new_map;
  size_t bytes;
  uint32_t index;

  if (map != NULL) {
    errno = EALREADY;
    return -1;
  }
  if (layout_id == 0 || nslots == 0) {
    errno = EINVAL;
    return -1;
  }
  bytes = sizeof(*new_map) + (size_t)nslots * sizeof(new_map->counts[0]);
  new_map = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (new_map == MAP_FAILED) {
    return -1;
  }
  new_map->layout_id = layout_id;
  atomic_init(&new_map->run_id, 0);
  atomic_init(&new_map->completed_run, 0);
  atomic_init(&new_map->controller_pid, 0);
  atomic_init(&new_map->gate, 0);
  atomic_init(&new_map->overflow, 0);
  for (index = 0; index < nslots; index++) {
    atomic_init(&new_map->counts[index], 0);
  }
  map = new_map;
  return 0;
}

int cb_claim_controller(int stale_timeout_ms) {
  uint64_t process = (uint64_t)getpid();
  uint64_t gate;
  uint64_t old_run;
  uint64_t replacement_run;
  int64_t deadline;
  struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};

  if (map == NULL || stale_timeout_ms < 0) {
    errno = EINVAL;
    return -1;
  }
  deadline = monotonicMilliseconds();
  if (deadline == -1) {
    return -1;
  }
  deadline += stale_timeout_ms;
  old_run = atomic_load_explicit(&map->run_id, memory_order_acquire);
  /* A takeover consumes one epoch and cb_begin consumes the next. */
  if (old_run >= CB_GATE_RUN_MASK ||
      (old_run != 0 && old_run >= CB_GATE_RUN_MASK - 1)) {
    errno = EOVERFLOW;
    return -1;
  }

  /* Close admission before waiting. Existing connections can finish, but a
     busy listener cannot keep adding work while a replacement takes over. */
  gate = atomic_load_explicit(&map->gate, memory_order_acquire);
  while ((gate & CB_GATE_ENABLED) != 0 &&
         !atomic_compare_exchange_weak_explicit(
             &map->gate, &gate, gate & ~CB_GATE_ENABLED,
             memory_order_acq_rel, memory_order_acquire)) {
  }
  while (gateActive(atomic_load_explicit(&map->gate,
                                        memory_order_acquire)) != 0) {
    int64_t now = monotonicMilliseconds();
    if (now == -1) {
      return -1;
    }
    if (now >= deadline) {
      break;
    }
    nanosleep(&pause, NULL);
  }

  /* The caller holds a process-owned file lock. If the old controller died,
     an unfinished connection may never run its pool cleanup. Invalidate that
     old run before clearing its stale accounting. */
  replacement_run = old_run == 0 ? 0 : old_run + 1;
  atomic_store_explicit(&map->run_id, replacement_run, memory_order_release);
  atomic_store_explicit(&map->gate, gateForRun(replacement_run),
                        memory_order_release);
  atomic_store_explicit(&map->completed_run, 0, memory_order_relaxed);
  atomic_store_explicit(&map->controller_pid, process, memory_order_release);
  return 0;
}

int cb_begin(uint64_t *run_id) {
  uint64_t current_run;
  uint64_t process = (uint64_t)getpid();
  uint64_t run;
  uint32_t index;

  if (map == NULL || run_id == NULL ||
      atomic_load_explicit(&map->controller_pid, memory_order_acquire) !=
          process) {
    errno = EPERM;
    return -1;
  }
  current_run = atomic_load_explicit(&map->run_id, memory_order_acquire);
  if (atomic_load_explicit(&map->gate, memory_order_acquire) !=
      gateForRun(current_run)) {
    errno = EBUSY;
    return -1;
  }
  run = current_run;
  if (run >= CB_GATE_RUN_MASK) {
    errno = EOVERFLOW;
    return -1;
  }
  run++;
  for (index = 0; index < nslots; index++) {
    atomic_store_explicit(&map->counts[index], 0, memory_order_relaxed);
  }
  atomic_store_explicit(&map->overflow, 0, memory_order_relaxed);
  atomic_store_explicit(&map->completed_run, 0, memory_order_relaxed);
  atomic_store_explicit(&map->run_id, run, memory_order_release);
  atomic_store_explicit(&map->gate, gateForRun(run) | CB_GATE_ENABLED,
                        memory_order_release);
  *run_id = run;
  return 0;
}

int cb_cancel(uint64_t run_id) {
  uint64_t gate;

  if (map == NULL || run_id == 0 ||
      atomic_load_explicit(&map->controller_pid, memory_order_acquire) !=
          (uint64_t)getpid() ||
      atomic_load_explicit(&map->run_id, memory_order_relaxed) != run_id) {
    errno = EINVAL;
    return -1;
  }
  gate = atomic_load_explicit(&map->gate, memory_order_acquire);
  for (;;) {
    if (gateRun(gate) != run_id) {
      errno = ESTALE;
      return -1;
    }
    if ((gate & CB_GATE_FINALIZING) != 0) {
      struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
      nanosleep(&pause, NULL);
      gate = atomic_load_explicit(&map->gate, memory_order_acquire);
      continue;
    }
    if ((gate & CB_GATE_ENABLED) == 0 ||
        atomic_compare_exchange_weak_explicit(
            &map->gate, &gate, gate & ~CB_GATE_ENABLED,
            memory_order_acq_rel, memory_order_acquire)) {
      break;
    }
  }
  atomic_store_explicit(&map->completed_run, 0, memory_order_release);
  if (gateActive(gate) != 0) {
    errno = EBUSY;
    return -1;
  }
  return 0;
}

uint64_t cb_connection_begin(void) {
  uint64_t gate;
  uint64_t run;

  if (map == NULL) {
    return 0;
  }
  gate = atomic_load_explicit(&map->gate, memory_order_acquire);
  for (;;) {
    if ((gate & CB_GATE_ENABLED) == 0 ||
        gateActive(gate) == CB_GATE_ACTIVE_MASK) {
      if (gateActive(gate) == CB_GATE_ACTIVE_MASK) {
        errno = EOVERFLOW;
      }
      return 0;
    }
    run = gateRun(gate);
    if (run == 0 ||
        atomic_load_explicit(&map->run_id, memory_order_acquire) != run) {
      return 0;
    }
    if (atomic_compare_exchange_weak_explicit(
            &map->gate, &gate, gate + 1, memory_order_acq_rel,
            memory_order_acquire)) {
      break;
    }
  }
  thread_run = run;
  return run;
}

void cb_thread_pause(void) { thread_run = 0; }

void cb_thread_resume(uint64_t run_id) {
  if (map != NULL && run_id != 0) {
    uint64_t gate = atomic_load_explicit(&map->gate, memory_order_acquire);
    if (gateAllowsRun(gate, run_id)) {
      thread_run = run_id;
    }
  }
}

int cb_connection_end(uint64_t run_id) {
  uint64_t active;
  uint64_t desired;
  uint64_t gate;

  thread_run = 0;
  if (map == NULL || run_id == 0) {
    errno = EINVAL;
    return -1;
  }
  for (;;) {
    if (atomic_load_explicit(&map->run_id, memory_order_acquire) != run_id) {
      errno = ESTALE;
      return -1;
    }
    gate = atomic_load_explicit(&map->gate, memory_order_acquire);
    if (gateRun(gate) != run_id) {
      errno = ESTALE;
      return -1;
    }
    active = gateActive(gate);
    if (active == 0) {
      errno = EINVAL;
      return -1;
    }
    desired = gate - 1;
    if (active == 1 && (gate & CB_GATE_ENABLED) != 0) {
      desired = gateForRun(run_id) | CB_GATE_FINALIZING;
    }
    if (atomic_compare_exchange_weak_explicit(
            &map->gate, &gate, desired, memory_order_acq_rel,
            memory_order_acquire)) {
      break;
    }
  }
  if (active == 1 && (gate & CB_GATE_ENABLED) != 0) {
#if defined(CB_TESTING)
    cb_test_last_connection_closed(run_id);
#endif
    if (atomic_load_explicit(&map->run_id, memory_order_acquire) != run_id) {
      errno = ESTALE;
      return -1;
    }
    atomic_store_explicit(&map->completed_run, run_id, memory_order_release);
    gate = gateForRun(run_id) | CB_GATE_FINALIZING;
    desired = gateForRun(run_id);
    if (!atomic_compare_exchange_strong_explicit(
            &map->gate, &gate, desired, memory_order_release,
            memory_order_acquire)) {
      errno = ESTALE;
      return -1;
    }
  }
  return 0;
}

static int64_t monotonicMilliseconds(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
    return -1;
  }
  return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int reserveSnapshot(cb_snapshot *snapshot, uint32_t slots) {
  uint64_t *counts;

  if (snapshot->capacity >= slots) {
    snapshot->nslots = slots;
    return 0;
  }
  counts = realloc(snapshot->counts, (size_t)slots * sizeof(*counts));
  if (counts == NULL) {
    return -1;
  }
  snapshot->counts = counts;
  snapshot->capacity = slots;
  snapshot->nslots = slots;
  return 0;
}

int cb_wait_snapshot(uint64_t run_id, cb_snapshot *snapshot, int timeout_ms) {
  int64_t deadline;
  uint64_t idle_gate = gateForRun(run_id);
  uint32_t index;
  struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};

  if (map == NULL || snapshot == NULL || run_id == 0 || timeout_ms <= 0 ||
      atomic_load_explicit(&map->controller_pid, memory_order_acquire) !=
          (uint64_t)getpid()) {
    errno = EINVAL;
    return -1;
  }
  deadline = monotonicMilliseconds();
  if (deadline == -1) {
    return -1;
  }
  deadline += timeout_ms;
  while (atomic_load_explicit(&map->completed_run, memory_order_acquire) !=
             run_id ||
         atomic_load_explicit(&map->gate, memory_order_acquire) != idle_gate) {
    int64_t now = monotonicMilliseconds();
    if (now == -1) {
      return -1;
    }
    if (now >= deadline) {
      errno = ETIMEDOUT;
      return -1;
    }
    nanosleep(&pause, NULL);
  }
  if (atomic_load_explicit(&map->run_id, memory_order_acquire) != run_id ||
      atomic_load_explicit(&map->overflow, memory_order_relaxed)) {
    errno = EOVERFLOW;
    return -1;
  }
  if (reserveSnapshot(snapshot, nslots) == -1) {
    return -1;
  }
  snapshot->run_id = run_id;
  snapshot->layout_id = map->layout_id;
  snapshot->mode = CB_COUNTS64;
  for (index = 0; index < nslots; index++) {
    snapshot->counts[index] =
        atomic_load_explicit(&map->counts[index], memory_order_relaxed);
  }
  return 0;
}

void cb_snapshot_free(cb_snapshot *snapshot) {
  if (snapshot != NULL) {
    free(snapshot->counts);
    memset(snapshot, 0, sizeof(*snapshot));
  }
}

void cb_libfuzzer_clear(void) { memset(extra, 0, sizeof(extra)); }

int cb_libfuzzer_import(const cb_snapshot *snapshot, uint32_t offset) {
  uint32_t index;

  if (snapshot == NULL || snapshot->counts == NULL || snapshot->nslots == 0 ||
      snapshot->mode != CB_COUNTS64 || offset > CB_MAX_EDGES ||
      snapshot->nslots > CB_MAX_EDGES - offset) {
    errno = EINVAL;
    return -1;
  }
  for (index = 0; index < snapshot->nslots; index++) {
    uint32_t old = extra[offset + index];
    uint64_t count = snapshot->counts[index];
    extra[offset + index] =
        count >= 255u - old ? 255 : (uint8_t)(old + count);
  }
  return 0;
}

#if defined(__clang__)
#pragma clang attribute pop
#endif
