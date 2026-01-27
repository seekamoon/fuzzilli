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

#ifndef LIBDISTANCE_H
#define LIBDISTANCE_H

#include <stdint.h>
#include <sys/types.h>
#if defined(_WIN32)
#include <Windows.h>
#endif

#define MAX_TARGETS 256
#define CONTEXT_BITMAP_SIZE_BITS 1024
#define CONTEXT_BITMAP_SIZE_BYTES (CONTEXT_BITMAP_SIZE_BITS / 8)
#define DISTANCE_SHM_SIZE sizeof(struct shmem_distance_data)

// Tracks a set of targets by their indices
struct target_set {
    uint32_t count;
    uint32_t* target_indices;
};

// Tracks per-target distance information
struct target_distances {
    uint32_t count;   // the number of targets
    double* distances;  // the array of distances, indexed by target ID
};

// Tracks the reached targets and their contexts for a single execution
struct reached_target_contexts {
    uint32_t num_reached_targets;  // number of reached targets
    uint32_t* target_ids;  // array of target IDs that were reached
    uint32_t* context_counts;  // number of contexts for each target
    uint32_t** context_ids;  // array of context ID arrays for each target
};

struct GlobalStats {
    uint32_t num_targets;          // total number of targets
    uint32_t num_reached_targets;  // number of reached targets (unique)
    uint32_t num_bbs;              // number of recorded basic blocks
    double   accumulated_distance; // accumulated distance to targets (harmonic distance)
};

struct TargetStats {
    uint32_t reached_count;        // reached count for each target
    uint32_t num_bbs;              // number of recorded basic blocks for each target
    double   accumulated_distance; // accumulated distance for each target (geometric distance)
    uint8_t  context_bitmap[CONTEXT_BITMAP_SIZE_BYTES]; // context bitmap for each target
};

struct shmem_distance_data {
    // global stats
    struct GlobalStats global_stats;
    // per-target stats
    struct TargetStats per_target_stats[MAX_TARGETS];
};

struct dist_context {
    int id;
    
    // Bitmap of targets that have been hit so far
    uint8_t* virgin_targets;
    
    // Total number of targets that have been discovered so far
    uint32_t found_targets;
    
#if defined(_WIN32)
    HANDLE hMapping;
#endif

    struct shmem_distance_data* shmem;
};

int dist_initialize(struct dist_context*);
void dist_shutdown(struct dist_context*);

int dist_evaluate(struct dist_context* context, double* average_distance, uint32_t* num_reached_targets, uint32_t* num_targets, struct target_set* new_targets, struct target_distances* per_target_dists, struct reached_target_contexts* reached_contexts);

void dist_clear_shmem(struct dist_context*);
void dist_reset_state(struct dist_context* context);
void dist_clear_target_data(struct dist_context* context, uint32_t target_id);

// Free memory allocated for reached_target_contexts
void dist_free_reached_contexts(struct reached_target_contexts* reached_contexts);

// Check if all specified targets were reached in the execution
// Returns 1 if all targets were reached, 0 otherwise
int dist_check_required_targets_reached(struct dist_context* context, uint32_t* target_ids, uint32_t num_targets);

#endif

