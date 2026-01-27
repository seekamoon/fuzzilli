// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#if !defined(_WIN32)
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/types.h>
#endif

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#endif

#include "libdistance.h"

// Helper functions for target bitmap operations
static inline int target_status(const uint8_t *bits, uint32_t index) {
  // return 1 if the corresponding bit is 1 (reached), 0 if it is 0 (unreached)
  return (bits[index / 8] >> (index % 8)) & 0x1;
}

static inline void clear_target(uint8_t *bits, uint32_t index) {
  // set the corresponding bit as 0 (unreached)
  bits[index / 8] &= ~(1u << (index % 8));
}

static inline void set_target(uint8_t *bits, uint32_t index) {
  // set the corresponding bit as 1 (reached)
  bits[index / 8] |= 1 << (index % 8);
}

int dist_initialize(struct dist_context *context) {
#if defined(_WIN32)
  char key[1024];
  _snprintf(key, sizeof(key), "shm_distance_%u_%u", GetCurrentProcessId(),
            context->id);
  context->hMapping = CreateFileMappingA(
      INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, DISTANCE_SHM_SIZE, key);
  if (!context->hMapping) {
    fprintf(stderr, "[LibDistance] unable to create file mapping: %lu",
            GetLastError());
    return -1;
  }

  context->shmem = MapViewOfFile(context->hMapping, FILE_MAP_ALL_ACCESS, 0, 0,
                                 DISTANCE_SHM_SIZE);
  if (!context->shmem) {
    CloseHandle(context->hMapping);
    context->hMapping = INVALID_HANDLE_VALUE;
    return -1;
  }
#else
  char shm_key[1024];
  snprintf(shm_key, 1024, "shm_distance_%d_%d", getpid(), context->id);

  int fd = shm_open(shm_key, O_RDWR | O_CREAT, S_IREAD | S_IWRITE);
  if (fd <= -1) {
    fprintf(stderr, "[LibDistance] Failed to create shared memory region\n");
    return -1;
  }
  ftruncate(fd, DISTANCE_SHM_SIZE);
  context->shmem =
      mmap(0, DISTANCE_SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  close(fd);
#endif

  // Allocate and initialize virgin_targets bitmap
  // We need (MAX_TARGETS + 7) / 8 bytes to store MAX_TARGETS bits
  uint32_t bitmap_size = (MAX_TARGETS + 7) / 8;
  context->virgin_targets = (uint8_t *)malloc(bitmap_size);
  if (!context->virgin_targets) {
    fprintf(stderr, "[LibDistance] Failed to allocate virgin_targets bitmap\n");
    return -1;
  }
  // Initialize all targets as virgin (not hit yet)
  memset(context->virgin_targets, 0xff, bitmap_size);
  context->found_targets = 0;

  dist_clear_shmem(context);

  return 0;
}

void dist_shutdown(struct dist_context *context) {
  // Free the virgin_targets bitmap
  free(context->virgin_targets);

#if defined(_WIN32)
  (void)UnmapViewOfFile(context->shmem);
  CloseHandle(context->hMapping);
#else
  char shm_key[1024];
  snprintf(shm_key, 1024, "shm_distance_%d_%d", getpid(), context->id);
  shm_unlink(shm_key);
#endif
}

int dist_evaluate(struct dist_context *context, double *distanceToTargets,
                  uint32_t *num_reached_targets, uint32_t *num_targets,
                  struct target_set *new_targets,
                  struct target_distances *per_target_dists,
                  struct reached_target_contexts *reached_contexts) {
  // Create a local snapshot of the shared memory to avoid race conditions
  // between the fuzzer and the target process
  struct shmem_distance_data shmem_snapshot;
  memcpy(&shmem_snapshot, context->shmem, sizeof(shmem_snapshot));

  uint32_t num_bbs = shmem_snapshot.global_stats.num_bbs;
  double accumulated_distance =
      shmem_snapshot.global_stats.accumulated_distance;

  // Initialize new_targets
  new_targets->count = 0;
  new_targets->target_indices = NULL;

  // Initialize per_target_dists
  per_target_dists->count = 0;
  per_target_dists->distances = NULL;

  // Initialize reached_contexts
  reached_contexts->num_reached_targets = 0;
  reached_contexts->target_ids = NULL;
  reached_contexts->context_counts = NULL;
  reached_contexts->context_ids = NULL;

  // Read the total number of targets from snapshot
  uint32_t total_targets = shmem_snapshot.global_stats.num_targets;
  *num_targets = total_targets;

  if (num_bbs == 0) {
    // not triggered any instrumented bb
    return 0;
  }

  double avg_dist = accumulated_distance / (double)num_bbs;
  assert(avg_dist >= 0.0);

  *distanceToTargets = avg_dist;
  *num_reached_targets = shmem_snapshot.global_stats.num_reached_targets;

  // Track newly hit targets
  if (total_targets > MAX_TARGETS) {
    fprintf(
        stderr,
        "[LibDistance] Warning: num_targets (%u) exceeds MAX_TARGETS (%d)\n",
        total_targets, MAX_TARGETS);
    total_targets = MAX_TARGETS;
  }

  // Calculate per-target distances and allocate array
  per_target_dists->count = total_targets;
  per_target_dists->distances =
      (double *)malloc(total_targets * sizeof(double));
  if (per_target_dists->distances == NULL) {
    fprintf(stderr,
            "[LibDistance] Failed to allocate per-target distances array\n");
    return -1;
  }

  // Calculate average distance for each target (using snapshot)
  for (uint32_t i = 0; i < total_targets; i++) {
    uint32_t target_num_bbs = shmem_snapshot.per_target_stats[i].num_bbs;
    if (target_num_bbs > 0) {
      per_target_dists->distances[i] =
          shmem_snapshot.per_target_stats[i].accumulated_distance /
          (double)target_num_bbs;
    } else {
      // No data for this target, set to -1.0 to indicate haven't reached yet
      per_target_dists->distances[i] = -1.0;
    }
  }

  // Check each target to see if it was hit for the first time (using snapshot)
  for (uint32_t i = 0; i < total_targets; i++) {
    if (shmem_snapshot.per_target_stats[i].reached_count > 0 &&
        target_status(context->virgin_targets, i)) {
      // This target was hit and it's a new discovery
      clear_target(context->virgin_targets, i);
      new_targets->count += 1;
      new_targets->target_indices = realloc(
          new_targets->target_indices, new_targets->count * sizeof(uint32_t));
      new_targets->target_indices[new_targets->count - 1] = i;
      context->found_targets += 1;
    }
  }

  // Process contexts for reached targets and build reached_contexts structure
  // First, count how many targets were reached in this execution (using
  // snapshot)
  uint32_t reached_target_count = 0;
  for (uint32_t i = 0; i < total_targets; i++) {
    if (shmem_snapshot.per_target_stats[i].reached_count > 0) {
      reached_target_count++;
    }
  }

  if (reached_target_count != shmem_snapshot.global_stats.num_reached_targets) {
    fprintf(stderr,
            "[LibDistance] Warning: reached_target_count (%u) != "
            "num_reached_targets (%u)\n",
            reached_target_count,
            shmem_snapshot.global_stats.num_reached_targets);
    // This can happen if the snapshot was taken during an update in the target
    // process (memcpy is not atomic, so we may capture inconsistent state). Use
    // the counted value which is consistent with per_target_stats data.
    *num_reached_targets = reached_target_count;
  }

  reached_contexts->num_reached_targets = reached_target_count;

  if (reached_target_count > 0) {
    // Allocate arrays for reached_contexts
    reached_contexts->target_ids =
        (uint32_t *)malloc(reached_target_count * sizeof(uint32_t));
    reached_contexts->context_counts =
        (uint32_t *)malloc(reached_target_count * sizeof(uint32_t));
    reached_contexts->context_ids =
        (uint32_t **)malloc(reached_target_count * sizeof(uint32_t *));
    memset(reached_contexts->context_ids, 0,
           reached_target_count * sizeof(uint32_t *));

    uint32_t reached_idx = 0;
    for (uint32_t target_id = 0; target_id < total_targets; target_id++) {
      if (shmem_snapshot.per_target_stats[target_id].reached_count == 0) {
        continue;
      }
      // Count valid contexts for this target by counting set bits in the context bitmap
      uint32_t valid_context_count = 0;
      const uint8_t *ctx_bitmap = shmem_snapshot.per_target_stats[target_id].context_bitmap;
      for (uint32_t byte_idx = 0; byte_idx < CONTEXT_BITMAP_SIZE_BYTES; byte_idx++) {
        uint8_t byte_val = ctx_bitmap[byte_idx];
        // Count set bits in this byte using Brian Kernighan's algorithm
        while (byte_val) {
          valid_context_count++;
          byte_val &= (byte_val - 1);
        }
      }

      reached_contexts->target_ids[reached_idx] = target_id;
      reached_contexts->context_counts[reached_idx] = valid_context_count;

      if (valid_context_count > 0) {
        reached_contexts->context_ids[reached_idx] =
            (uint32_t *)malloc(valid_context_count * sizeof(uint32_t));
        uint32_t ctx_idx = 0;

        // Extract context IDs from bitmap (bit index = context ID)
        for (uint32_t byte_idx = 0; byte_idx < CONTEXT_BITMAP_SIZE_BYTES; byte_idx++) {
          uint8_t byte_val = ctx_bitmap[byte_idx];
          for (uint32_t bit_idx = 0; bit_idx < 8; bit_idx++) {
            if ((byte_val >> bit_idx) & 1) {
              uint32_t context_id = byte_idx * 8 + bit_idx;
              reached_contexts->context_ids[reached_idx][ctx_idx++] = context_id;
            }
          }
        }
      } else {
        reached_contexts->context_ids[reached_idx] = NULL;
      }

      reached_idx++;
    }

    if (reached_idx != reached_target_count) {
      // raise an error and exit
      fprintf(stderr,
              "reached_idx: %u, reached_target_count: %u, "
              "global_stats.num_reached_targets: %u\n",
              reached_idx, reached_target_count,
              context->shmem->global_stats.num_reached_targets);
      fprintf(stderr,
              "[LibDistance] Error: reached_idx (%u) != reached_target_count "
              "(%u)\n",
              reached_idx, reached_target_count);
      exit(1);
    }
  }

  return 0;
}

void dist_clear_shmem(struct dist_context *context) {
  context->shmem->global_stats.num_bbs = 0;
  context->shmem->global_stats.accumulated_distance = 0.0;
  context->shmem->global_stats.num_reached_targets = 0;
  // NOTE: num_targets should NOT be cleared as it's set only once by the
  // instrumentation and represents the total number of targets
  memset(context->shmem->per_target_stats, 0,
         sizeof(context->shmem->per_target_stats));
}

void dist_reset_state(struct dist_context *context) {
  // Reset virgin_targets bitmap (all targets become virgin again)
  uint32_t bitmap_size = (MAX_TARGETS + 7) / 8;
  memset(context->virgin_targets, 0xff, bitmap_size);
  context->found_targets = 0;

  dist_clear_shmem(context);
}

void dist_clear_target_data(struct dist_context *context, uint32_t target_id) {
  // Check if this target was previously reached (virgin bit = 0)
  if (!target_status(context->virgin_targets, target_id)) {
    // Target was reached before, decrement the counter
    context->found_targets--;
  }

  // Mark this target as unreached again
  set_target(context->virgin_targets, target_id);
}

void dist_free_reached_contexts(
    struct reached_target_contexts *reached_contexts) {
  if (reached_contexts->context_ids != NULL) {
    for (uint32_t i = 0; i < reached_contexts->num_reached_targets; i++) {
      free(reached_contexts->context_ids[i]);
      reached_contexts->context_ids[i] = NULL;
    }
    free(reached_contexts->context_ids);
    reached_contexts->context_ids = NULL;
  }
  if (reached_contexts->target_ids != NULL) {
    free(reached_contexts->target_ids);
    reached_contexts->target_ids = NULL;
  }
  if (reached_contexts->context_counts != NULL) {
    free(reached_contexts->context_counts);
    reached_contexts->context_counts = NULL;
  }

  reached_contexts->num_reached_targets = 0;
}

int dist_check_required_targets_reached(struct dist_context *context,
                                        uint32_t *required_targets,
                                        uint32_t num_required_targets) {

  // all required targets must be reached
  for (uint32_t i = 0; i < num_required_targets; i++) {
    uint32_t tid = required_targets[i];
    if (context->shmem->per_target_stats[tid].reached_count == 0) {
      return 0; // Required target not reached
    }
  }
  return 1; // All required targets reached

  // // at least one of the required targets must be reached
  // for (uint32_t i = 0; i < num_required_targets; i++) {
  //     uint32_t tid = required_targets[i];
  //     if (context->shmem->per_target_stats[tid].reached_count > 0) {
  //         return 1;  // At least one required target reached
  //     }
  // }
  // return 0;  // None of the required targets reached
}
