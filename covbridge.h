/* SPDX-License-Identifier: MIT */
#ifndef APACHE_HTTP_COVBRIDGE_H
#define APACHE_HTTP_COVBRIDGE_H

#include <stddef.h>
#include <stdint.h>

#define CB_MAX_EDGES 1048576u
#define CB_COUNTS64 1u

typedef struct cb_snapshot {
  uint64_t run_id;
  uint64_t layout_id;
  uint32_t mode;
  uint32_t nslots;
  uint64_t *counts;
  uint32_t capacity;
} cb_snapshot;

int cb_init(uint64_t layout_id);
uint32_t cb_slots(void);
int cb_claim_controller(int stale_timeout_ms);
int cb_begin(uint64_t *run_id);
int cb_cancel(uint64_t run_id);

uint64_t cb_connection_begin(void);
void cb_thread_pause(void);
void cb_thread_resume(uint64_t run_id);
int cb_connection_end(uint64_t run_id);

int cb_wait_snapshot(uint64_t run_id, cb_snapshot *snapshot, int timeout_ms);
void cb_snapshot_free(cb_snapshot *snapshot);

void cb_libfuzzer_clear(void);
int cb_libfuzzer_import(const cb_snapshot *snapshot, uint32_t offset);

#endif
