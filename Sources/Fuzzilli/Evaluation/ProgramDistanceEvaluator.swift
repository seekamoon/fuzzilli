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

import Foundation
import libcoverage
import libdistance

public class CovEdgeSetWithDistance: CovEdgeSet {
    internal var distanceToTargets: Double
    internal var minimumDistance: Double
    internal var maximumDistance: Double
    internal var newlyReachedTargets: [UInt32]
    internal var perTargetDistances: [Double]

    // All reached targets and their contexts in this execution
    // Maps target ID to set of context IDs (call stack hashes)
    internal var reachedTargetContexts: [UInt32: Set<UInt32>]

    // Flags to indicate why this aspect is interesting
    public var foundNewContexts: Bool {
        return !newContexts.isEmpty
    }
    public var foundNewEdges: Bool {
        return count > 0
    }

    // Number of reached targets
    public var numReachedTargets: UInt32 {
        return UInt32(reachedTargetContexts.count)
    }

    // Number of total targets
    public var numTotalTargets: UInt32 {
        return UInt32(perTargetDistances.count)
    }

    // Number of newly reached targets
    public var numNewlyReachedTargets: UInt32 {
        return UInt32(newlyReachedTargets.count)
    }

    // The specific new contexts discovered by this execution
    public var newContexts: [(targetId: UInt32, contextId: UInt32)]

    init(
        edges: UnsafeMutablePointer<UInt32>?, numEdges: UInt32, distanceToTargets: Double,
        minimumDistance: Double, maximumDistance: Double, newlyReachedTargets: [UInt32],
        perTargetDistances: [Double], reachedTargetContexts: [UInt32: Set<UInt32>],
        newContexts: [(targetId: UInt32, contextId: UInt32)] = []
    ) {
        // the distance to targets of the current sample
        self.distanceToTargets = distanceToTargets
        // the minimum distance to targets currently observed
        self.minimumDistance = minimumDistance
        // the maximum distance to targets currently observed
        self.maximumDistance = maximumDistance
        // the array of newly reached target IDs
        self.newlyReachedTargets = newlyReachedTargets
        // per-target distance information (indexed by target ID)
        self.perTargetDistances = perTargetDistances
        // all reached targets and their contexts
        self.reachedTargetContexts = reachedTargetContexts

        self.newContexts = newContexts

        super.init(edges: edges, numEdges: numEdges)
    }

    /// Returns an array of all the newly discovered targets of this CovEdgeSetWithDistance.
    public func getTargets() -> [UInt32] {
        return newlyReachedTargets
    }

    public override var description: String {
        return
            "\(super.description), distance to targets: \(String(format: "%.4f", distanceToTargets)), minimum distance: \(String(format: "%.4f", minimumDistance)), maximum distance: \(String(format: "%.4f", maximumDistance)), reached targets: \(numReachedTargets)/\(numTotalTargets), newly hit targets: \(numNewlyReachedTargets), new contexts: \(foundNewContexts)"
    }
}

public class ProgramDistanceEvaluator: ProgramCoverageEvaluator {
    private var distContext = libdistance.dist_context()

    /// The minimum distance to targets currently observed
    private var minimumDistance: Double = -1.0
    /// The maximum distance to targets currently observed
    private var maximumDistance: Double = -1.0

    /// Tracks all known (target, context) pairs that have been discovered
    /// Used to determine which contexts are new when evaluating a program
    private var knownContexts: [UInt32: Set<UInt32>] = [:]

    /// Required targets that must be reached for a program to be considered interesting.
    /// If set, programs that don't reach all these targets will be rejected during evaluation.
    private var requiredTargetsForEvaluation: Set<UInt32>? = nil

    /// Set the required targets that must be reached during evaluation.
    /// Call this before executing a program that needs to maintain target reachability.
    public func setRequiredTargets(_ targets: Set<UInt32>?) {
        requiredTargetsForEvaluation = targets
    }

    /// Clear the required targets after evaluation is complete.
    public func clearRequiredTargets() {
        requiredTargetsForEvaluation = nil
    }

    public override init(runner: ScriptRunner) {
        let id = ProgramDistanceEvaluator.instances

        super.init(runner: runner)

        distContext.id = Int32(id)

        guard libdistance.dist_initialize(&distContext) == 0 else {
            fatalError("Could not initialize libdistance")
        }

        #if os(Windows)
            runner.setEnvironmentVariable(
                "SHM_DISTANCE_ID", to: "shm_distance_\(GetCurrentProcessId())_\(id)")
        #else
            runner.setEnvironmentVariable("SHM_DISTANCE_ID", to: "shm_distance_\(getpid())_\(id)")
        #endif
    }

    override func initialize() {
        fuzzer.registerEventListener(for: fuzzer.events.PreExecute) { execution in
            libcoverage.cov_clear_bitmap(&self.context)
            libdistance.dist_clear_shmem(&self.distContext)
        }

        fuzzer.registerEventListener(for: fuzzer.events.Shutdown) { _ in
            libcoverage.cov_shutdown(&self.context)
            libdistance.dist_shutdown(&self.distContext)
        }

        let _ = fuzzer.execute(Program(), purpose: .startup)
        libcoverage.cov_finish_initialization(&context, shouldTrackEdgeCounts ? 1 : 0)
        logger.info("Initialized, \(context.num_edges) edges")
    }

    public override func evaluate(_ execution: Execution) -> ProgramAspects? {
        assert(execution.outcome == .succeeded)

        // 1. Evaluate Coverage
        var newEdgeSet = libcoverage.edge_set()
        let covResult = libcoverage.cov_evaluate(&context, &newEdgeSet)

        let hasNewEdges = (covResult == 1)

        // 2. Check Required Targets (Before Distance Evaluation)
        // This ensures programs that lose reachability to required targets are not added to corpus
        if let requiredTargets = requiredTargetsForEvaluation, !requiredTargets.isEmpty {
            if !checkRequiredTargetsReached(requiredTargets) {
                // logger.info("Lost reachability to required targets \(requiredTargets), rejecting program")
                return nil
            }
        }

        // 3. Evaluate Distance & Targets
        var distanceToTargets: Double = -1.0
        var numReachedTargets: UInt32 = 0
        var numTotalTargets: UInt32 = 0
        var newTargetSet = libdistance.target_set()
        var perTargetDists = libdistance.target_distances()
        var reachedContexts = libdistance.reached_target_contexts()

        // Always evaluate distance/targets, regardless of coverage result
        let _ = libdistance.dist_evaluate(
            &distContext, &distanceToTargets, &numReachedTargets, &numTotalTargets,
            &newTargetSet, &perTargetDists, &reachedContexts)

        // Update minimum and maximum distance
        if distanceToTargets >= 0 {
            if minimumDistance < 0 || distanceToTargets < minimumDistance {
                minimumDistance = distanceToTargets
            }
            if maximumDistance < 0 || distanceToTargets > maximumDistance {
                maximumDistance = distanceToTargets
            }
        }

        // Copy per-target distances to Swift array
        var perTargetDistancesArray: [Double] = Array(repeating: -1.0, count: Int(numTotalTargets))
        if perTargetDists.count > 0, let distances = perTargetDists.distances {
            perTargetDistancesArray = Array(
                UnsafeBufferPointer(start: distances, count: Int(perTargetDists.count)))
            free(distances)
        }

        guard perTargetDistancesArray.count == numTotalTargets else {
            logger.fatal(
                "Per-target distances array size \(perTargetDistancesArray.count) does not match number of targets \(numTotalTargets)"
            )
        }

        // Check for newly reached targets
        let newlyReachedTargetsArray: [UInt32]
        if newTargetSet.count > 0 {
            guard newTargetSet.target_indices != nil else {
                logger.fatal("target_indices is NULL")
            }
            newlyReachedTargetsArray = Array(
                UnsafeBufferPointer(
                    start: newTargetSet.target_indices, count: Int(newTargetSet.count)))
            logger.info(
                "Discovered \(newlyReachedTargetsArray.count) new target(s): \(newlyReachedTargetsArray)"
            )
            free(newTargetSet.target_indices)
        } else {
            // make an empty array
            newlyReachedTargetsArray = []
        }

        // Check for new contexts
        var reachedTargetContexts: [UInt32: Set<UInt32>] = [:]
        var hasNewContexts = false
        var newContextsList: [(targetId: UInt32, contextId: UInt32)] = []

        if reachedContexts.num_reached_targets > 0 {
            for i in 0..<Int(reachedContexts.num_reached_targets) {
                let targetId = reachedContexts.target_ids[i]
                let contextCount = reachedContexts.context_counts[i]
                var contextSet = Set<UInt32>()

                if contextCount > 0, let contexts = reachedContexts.context_ids[i] {
                    // Get known contexts for this target
                    if knownContexts[targetId] == nil {
                        knownContexts[targetId] = Set<UInt32>()
                    }

                    for j in 0..<Int(contextCount) {
                        let contextId = contexts[j]
                        contextSet.insert(contextId)

                        // Check if this is a new context
                        if !knownContexts[targetId]!.contains(contextId) {
                            hasNewContexts = true
                            newContextsList.append((targetId: targetId, contextId: contextId))
                            knownContexts[targetId]!.insert(contextId)
                        }
                    }
                }
                reachedTargetContexts[targetId] = contextSet
            }
            libdistance.dist_free_reached_contexts(&reachedContexts)
        }

        if hasNewContexts {
            logger.info("New contexts discovered: \(newContextsList)")
        }

        // 5. Return Aspect if Interesting
        if hasNewEdges || hasNewContexts {
            return CovEdgeSetWithDistance(
                edges: newEdgeSet.edge_indices, numEdges: newEdgeSet.count,
                distanceToTargets: distanceToTargets, minimumDistance: self.minimumDistance,
                maximumDistance: self.maximumDistance,
                newlyReachedTargets: newlyReachedTargetsArray,
                perTargetDistances: perTargetDistancesArray,
                reachedTargetContexts: reachedTargetContexts,
                newContexts: newContextsList)
        } else {
            // Not interesting
            assert(
                newEdgeSet.edge_indices == nil && newEdgeSet.count == 0
                    || (!hasNewEdges && !hasNewContexts))
            return nil
        }
    }

    public override func exportState() -> Data {
        var state = super.exportState()

        var minDist = self.minimumDistance
        var maxDist = self.maximumDistance
        state.append(Data(bytes: &minDist, count: MemoryLayout<Double>.size))
        state.append(Data(bytes: &maxDist, count: MemoryLayout<Double>.size))

        return state
    }

    public override func importState(_ state: Data) throws {
        assert(isInitialized)
        let headerSize = 4 * 3

        guard
            state.count == headerSize + Int(context.bitmap_size) * 2 + MemoryLayout<Double>.size * 2
        else {
            throw FuzzilliError.evaluatorStateImportError(
                "Cannot import coverage+distance state as it has an unexpected size. Ensure all instances use the same build of the target"
            )
        }

        let numEdges = state.withUnsafeBytes { $0.load(fromByteOffset: 0, as: UInt32.self) }
        let bitmapSize = state.withUnsafeBytes { $0.load(fromByteOffset: 4, as: UInt32.self) }
        let foundEdges = state.withUnsafeBytes { $0.load(fromByteOffset: 8, as: UInt32.self) }

        guard bitmapSize == context.bitmap_size && numEdges == context.num_edges else {
            throw FuzzilliError.evaluatorStateImportError(
                "Cannot import coverage state due to different bitmap sizes. Ensure all instances use the same build of the target"
            )
        }

        context.found_edges = foundEdges

        var start = state.startIndex + headerSize
        state.copyBytes(to: context.virgin_bits, from: start..<start + Int(bitmapSize))
        start += Int(bitmapSize)
        state.copyBytes(to: context.crash_bits, from: start..<start + Int(bitmapSize))
        start += Int(bitmapSize)

        self.minimumDistance = state.withUnsafeBytes {
            $0.load(fromByteOffset: start, as: Double.self)
        }
        start += MemoryLayout<Double>.size
        self.maximumDistance = state.withUnsafeBytes {
            $0.load(fromByteOffset: start, as: Double.self)
        }

        logger.info(
            "Imported existing coverage state with \(foundEdges) edges already discovered, minimum distance: \(self.minimumDistance), maximum distance: \(self.maximumDistance)"
        )
    }

    public override func resetState() {
        super.resetState()
        libdistance.dist_reset_state(&distContext)
        self.minimumDistance = -1.0
        self.maximumDistance = -1.0
        self.knownContexts.removeAll()
    }

    /// Check if all specified targets were reached in the last execution
    private func checkRequiredTargetsReached(_ requiredTargets: Set<UInt32>) -> Bool {
        guard !requiredTargets.isEmpty else { return true }
        var requiredTargetArray = Array(requiredTargets)
        let result = libdistance.dist_check_required_targets_reached(
            &distContext, &requiredTargetArray, UInt32(requiredTargetArray.count))
        return result == 1
    }

    /// Override hasAspects to also check if targets are preserved during minimization.
    /// This ensures that minimized programs still reach the same targets as the original program.
    public override func hasAspects(_ execution: Execution, _ aspects: ProgramAspects) -> Bool {
        // Check if the parent class conditions are satisfied (edges preserved)
        guard super.hasAspects(execution, aspects) else {
            return false
        }

        // If the aspect is a crash, we don't need to check for distance preservation
        if aspects.outcome.isCrash() {
            return true
        }

        guard let covEdgeSetWithDistance = aspects as? CovEdgeSetWithDistance else {
            logger.fatal("Distance Evaluator received non-distance aspects")
        }

        // Get the targets that were reached in the original program
        let originalTargets = Set(covEdgeSetWithDistance.reachedTargetContexts.keys)

        // Check if all original targets are still reached in the current execution
        if !checkRequiredTargetsReached(originalTargets) {
            logger.info(
                "Minimization failed: program no longer reaches required targets \(originalTargets.sorted())"
            )
            return false
        }

        return true
    }

    public override func computeAspectIntersection(
        of program: Program, with aspects: ProgramAspects
    ) -> ProgramAspects? {
        guard let firstCovEdgeSetWithDistance = aspects as? CovEdgeSetWithDistance else {
            logger.fatal("Distance Evaluator received non distance aspects")
        }

        // Save the targets from the first execution for intersection
        let firstReachedTargets = Set(firstCovEdgeSetWithDistance.reachedTargetContexts.keys)

        // Save the first edge set for intersection
        let firstEdgeSet = Set(
            UnsafeBufferPointer(
                start: firstCovEdgeSetWithDistance.edges,
                count: Int(firstCovEdgeSetWithDistance.count)))

        // Reset edges so they can be retriggered during the next execution
        resetAspects(firstCovEdgeSetWithDistance)

        // Reset targets so they can be re-discovered
        resetTargets(firstCovEdgeSetWithDistance)

        // Reset contexts so they can be re-discovered
        resetContexts(firstCovEdgeSetWithDistance)

        // Execute the program and collect coverage + distance information
        let execution = fuzzer.execute(program, purpose: .checkForDeterministicBehavior)
        guard execution.outcome == .succeeded else { return nil }
        guard let secondCovEdgeSetWithDistance = evaluate(execution) as? CovEdgeSetWithDistance
        else { return nil }

        // Get the second edge set
        let secondEdgeSet = Set(
            UnsafeBufferPointer(
                start: secondCovEdgeSetWithDistance.edges,
                count: Int(secondCovEdgeSetWithDistance.count)))

        // Reset all edges that were only triggered by the 2nd execution
        // (those only triggered by the 1st execution were already reset earlier)
        for edge in secondEdgeSet.subtracting(firstEdgeSet) {
            resetEdge(edge)
        }

        // Compute the intersection of the edges
        let intersectedEdgeSet = secondEdgeSet.intersection(firstEdgeSet)
        guard
            intersectedEdgeSet.count != 0
                || (secondCovEdgeSetWithDistance.foundNewContexts
                    && firstCovEdgeSetWithDistance.foundNewContexts)
        else { return nil }

        // Update edges in the result to be the intersection
        secondCovEdgeSetWithDistance.setEdges(intersectedEdgeSet)

        // Compute intersection of reachedTargetContexts
        // This ensures only deterministically reached targets are kept
        let secondReachedTargets = Set(secondCovEdgeSetWithDistance.reachedTargetContexts.keys)
        let intersectedTargets = firstReachedTargets.intersection(secondReachedTargets)

        // Only keep targets that were reached in both executions
        // This filters out non-deterministic target reaching behavior
        if intersectedTargets != secondReachedTargets {
            let removedTargets = secondReachedTargets.subtracting(intersectedTargets)
            if !removedTargets.isEmpty {
                logger.info(
                    "First Reached Targets: \(firstReachedTargets.sorted()), Second Reached Targets: \(secondReachedTargets.sorted()), Non-deterministic targets: \(removedTargets.sorted())"
                )
            }
            secondCovEdgeSetWithDistance.reachedTargetContexts = secondCovEdgeSetWithDistance
                .reachedTargetContexts.filter {
                    intersectedTargets.contains($0.key)
                }
        }

        return secondCovEdgeSetWithDistance
    }

    private func resetTargets(_ aspects: CovEdgeSetWithDistance) {
        for targetId in aspects.newlyReachedTargets {
            libdistance.dist_clear_target_data(&distContext, targetId)
        }
    }

    private func resetContexts(_ aspects: CovEdgeSetWithDistance) {
        // If aspects has new contexts, remove them from knownContexts so they can be 'rediscovered'
        // This requires 'aspects' to carry the specific new contexts.
        // Since we didn't store the exact new contexts list in CovEdgeSetWithDistance (only the flag),
        // we might be in trouble here if we don't store them.
        // However, we can iterate reachedTargetContexts and remove any that are currently in knownContexts?
        // No, that would remove old contexts too.
        // We MUST store newContexts in CovEdgeSetWithDistance.
        if !aspects.newContexts.isEmpty {
            for (targetId, contextId) in aspects.newContexts {
                knownContexts[targetId]?.remove(contextId)
            }
        }
    }
}
