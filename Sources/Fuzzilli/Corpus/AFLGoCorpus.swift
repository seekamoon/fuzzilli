// Copyright 2020 Google LLC
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

/// Corpus for mutation-based fuzzing.
///
/// The corpus contains FuzzIL programs that can be used as input for mutations.
/// Any newly found interesting program is added to the corpus.
/// Programs are evicted from the corpus for two reasons:
///
///  - if the corpus grows too large (larger than maxCorpusSize), in which
///    case the oldest programs are removed.
///  - if a program has been mutated often enough (at least
///    minMutationsPerSample times).
///
/// However, once reached, the corpus will never shrink below minCorpusSize again.
/// Further, once initialized, the corpus is guaranteed to always contain at least one program.
public class AFLGoCorpus: ComponentBase, Collection, Corpus {
    /// The minimum number of samples that should be kept in the corpus.
    private let minSize: Int

    // The default mutation budget for samples
    private let defaultMutationBudget: Int

    // The total number of targets
    private var numTotalTargets: Int? = nil

    /// Pre-target seeds: programs that haven't reached any target yet
    private var preTargetSeeds: RingBuffer<Program>
    // mutation count for each pre-target sample
    private var preTargetAges: RingBuffer<Int>
    // mutation budgets for each pre-target sample
    private var preTargetMutationBudgets: RingBuffer<Int>

    // pre-calculated weights based on harmonic distance
    private var preTargetHarmonicWeights: RingBuffer<Double>
    // Per-target distances for each pre-target seed (replaces preTargetPerTargetWeights)
    private var preTargetPerTargetDistances: RingBuffer<[Double]>

    // Cumulative weight caches for O(log N) selection
    private var cachedCumulativeHarmonicWeights: [Double] = []
    private var cachedPerTargetCumulativeWeights: [UInt32: [Double]] = [:]

    // Cache validity flags
    private var harmonicWeightsCacheValid: Bool = false
    private var perTargetWeightsCacheValid: Bool = false

    // Track seed count at last cache build (to detect RingBuffer overflow)
    private var lastCachedPreTargetCount: Int = 0

    /// Post-target seeds: programs that reached targets or discovered new contexts
    private var postTargetSeeds: RingBuffer<Program>
    // mutation count for each post-target sample
    private var postTargetAges: RingBuffer<Int>
    // mutation budgets for each post-target sample
    private var postTargetMutationBudgets: RingBuffer<Int>

    // Required targets for each post-target seed (targets that the seed reached)
    private var postTargetRequiredTargets: RingBuffer<Set<UInt32>>
    private var postTargetRarityScores: RingBuffer<Double>
    // Current mutation target's required targets (set when randomElementForMutating is called)
    private var currentMutationRequiredTargets: Set<UInt32>? = nil

    /// Counts the total number of entries in the corpus.
    private var totalEntryCounter = 0

    /// The time when each target was first reached (in milliseconds since fuzzing started).
    /// Array indexed by target ID. 0 means the target hasn't been reached yet.
    private var firstTargetReachedTime: [UInt64] = []

    /// Counts how many times each target was reached
    /// Key: target ID, Value: number of samples that reached this target
    private var targetReachedCount: [UInt32: UInt32] = [:]

    /// Counts how many pre-target seeds have known distance to each target
    /// Key: target ID, Value: number of pre-target seeds with known distance (d >= 0)
    private var preTargetKnownDistanceCount: [UInt32: Int] = [:]

    /// Counts how many times each target was selected by selectTargetBasedOnRarity
    private var targetSelectionCount: [UInt32: UInt32] = [:]

    /// Counts the number of times cleanup has been executed
    private var cleanupCount = 0

    /// Counts the total number of pre-target seeds removed during cleanup
    private var removedPreTargetSeedsCount = 0

    /// Counts the total number of post-target seeds removed during cleanup
    private var removedPostTargetSeedsCount = 0

    /// Counts the number of times a pre-target seed was selected for mutation
    private var preTargetSelectionCount = 0

    /// Counts the number of times a post-target seed was selected for mutation
    private var postTargetSelectionCount = 0

    // Whether to guide the mutation process by target-specific distance
    // If true, the mutation process will be guided by target-specific distance
    // If false, the mutation process will be guided by the harmonic distance of all targets
    public var guidedByTargetSpecificDistance: Bool = false

    public init(
        minSize: Int, maxSize: Int, defaultMutationBudget: Int,
        guidedByTargetSpecificDistance: Bool = false
    ) {
        // The corpus must never be empty. Other components, such as the ProgramBuilder, rely on this
        assert(minSize >= 1)
        assert(maxSize >= minSize)

        self.minSize = minSize
        self.defaultMutationBudget = defaultMutationBudget
        self.guidedByTargetSpecificDistance = guidedByTargetSpecificDistance

        self.preTargetSeeds = RingBuffer(maxSize: maxSize)
        self.preTargetAges = RingBuffer(maxSize: maxSize)
        self.preTargetMutationBudgets = RingBuffer(maxSize: maxSize)
        self.preTargetHarmonicWeights = RingBuffer(maxSize: maxSize)
        self.preTargetPerTargetDistances = RingBuffer(maxSize: maxSize)

        self.postTargetSeeds = RingBuffer(maxSize: maxSize)
        self.postTargetAges = RingBuffer(maxSize: maxSize)
        self.postTargetMutationBudgets = RingBuffer(maxSize: maxSize)
        self.postTargetRequiredTargets = RingBuffer(maxSize: maxSize)
        self.postTargetRarityScores = RingBuffer(maxSize: maxSize)
        super.init(name: "Corpus")
    }

    override func initialize() {
        // Schedule a timer to perform cleanup regularly, but only if we're not running as static corpus.
        if !fuzzer.config.staticCorpus {
            fuzzer.timers.scheduleTask(every: 15 * Minutes, cleanup)
        }
    }

    public var size: Int {
        return preTargetSeeds.count + postTargetSeeds.count
    }

    public var isEmpty: Bool {
        return preTargetSeeds.isEmpty && postTargetSeeds.isEmpty
    }

    public var supportsFastStateSynchronization: Bool {
        return true
    }

    /// Calculate target rarity score [1.0, 100.0]
    private func calculateTargetRarityScore(reachedTargets: Set<UInt32>) -> Double {
        guard !reachedTargets.isEmpty && !targetReachedCount.isEmpty else {
            return 1.0
        }

        // Calculate average sample count across all reached targets
        let totalCount = targetReachedCount.values.reduce(0, +)
        let avgCount = Double(totalCount) / Double(targetReachedCount.count)

        // Calculate rarity bonus for each reached target and average them
        var totalBonus = 0.0
        for targetId in reachedTargets {
            let count = Double(targetReachedCount[targetId] ?? 1)
            // the bonus should be between 1.0 and 100.0
            let bonus = Swift.min(Swift.max(1.0, avgCount / count), 100.0)
            totalBonus += bonus
        }

        let avgBonus = totalBonus / Double(reachedTargets.count)

        guard avgBonus >= 1.0 && avgBonus <= 100.0 else {
            logger.fatal("avgBonus < 1.0 or > 100.0: \(avgBonus)")
        }
        return avgBonus
    }

    public func add(_ program: Program, _ aspects: ProgramAspects) {
        // check the aspects of the program
        guard let covEdgeSetWithDistance = aspects as? CovEdgeSetWithDistance else {
            // this will happen when fully importing corpus and no interesting behavior was found
            // based on Fuzzer.swift, it will execute "corpus.add(program, ProgramAspects(outcome: .succeeded))"
            logger.error(
                "AFLGo Corpus needs to be provided a CovEdgeSetWithDistance when adding a program")
            return
        }

        // Log per-target distances for verification
        // check if target-specific distance is not equal to -1.0
        // -1.0 means that the target was not reached
        if !covEdgeSetWithDistance.perTargetDistances.isEmpty {
            var targetDistInfo = "Per-target distances: "
            for (idx, distance) in covEdgeSetWithDistance.perTargetDistances.enumerated() {
                if distance != -1.0 {
                    targetDistInfo += "[\(idx): \(String(format: "%.2f", distance))] "
                } else {
                    targetDistInfo += "[\(idx): N/A] "
                }
            }
            logger.info(targetDistInfo)
        }

        // Initialize the firstTargetReachedTime array if needed
        if numTotalTargets == nil {
            numTotalTargets = Int(covEdgeSetWithDistance.numTotalTargets)
            logger.info("numTotalTargets: \(numTotalTargets!)")

            // Initialize the firstTargetReachedTime array
            firstTargetReachedTime = Array(repeating: 0, count: numTotalTargets!)
        } else {
            // detect if numTotalTargets has changed (maybe due to race condition)
            guard numTotalTargets == Int(covEdgeSetWithDistance.numTotalTargets) else {
                logger.error(
                    "numTotalTargets \(numTotalTargets!) does not match covEdgeSetWithDistance.numTotalTargets \(covEdgeSetWithDistance.numTotalTargets)"
                )
                return  // discard the program
            }
        }

        // Update target reaching count and first reached time
        let reachedTargetIds = Set(covEdgeSetWithDistance.reachedTargetContexts.keys)
        let elapsedTime = currentMillis() - fuzzer.fuzzingStartTime

        for targetId in reachedTargetIds {
            targetReachedCount[targetId, default: 0] += 1

            // Update first reached time if not set yet
            let idx = Int(targetId)
            if idx < firstTargetReachedTime.count && firstTargetReachedTime[idx] == 0 {
                firstTargetReachedTime[idx] = elapsedTime
                let timeInHours = Double(elapsedTime) / 3600000.0
                logger.info(
                    "Target \(targetId) first reached after \(String(format: "%.2f", timeInHours)) hours"
                )
            }
        }

        // Determine Queue Placement based on Two-Phase Scheduling Rules
        let foundNewEdges = covEdgeSetWithDistance.foundNewEdges
        // Found new contexts means that the program reached certain targets (new or old)
        // since only target site has the context information
        let foundNewContexts = covEdgeSetWithDistance.foundNewContexts
        let reachesTarget = covEdgeSetWithDistance.numReachedTargets > 0

        var isPostTargetSeed = false
        var shouldAdd = false

        if foundNewEdges {
            // Rule: Triggered new edges
            if reachesTarget {
                // Rule: ...and reached a target -> Post-Target Queue
                isPostTargetSeed = true
                shouldAdd = true
            } else {
                // Rule: ...and reached NO target -> Pre-Target Queue
                isPostTargetSeed = false
                shouldAdd = true
            }
        } else {
            // Rule: No new edges
            if foundNewContexts {
                // Rule: ...but triggered new context -> Post-Target Queue
                // (Implies target reached, as context is associated with target)
                isPostTargetSeed = true
                shouldAdd = true
            } else {
                // Rule: No new edges, no new contexts -> Discard
                shouldAdd = false
            }
        }

        if !shouldAdd {
            return
        }

        let mutationBudget = defaultMutationBudget
        var rarityScore = 1.0
        if reachesTarget {
            // if reached any target, calculate the rarity score
            rarityScore = calculateTargetRarityScore(reachedTargets: reachedTargetIds)
        }

        // add the program to the corpus
        addInternal(
            program, 0, mutationBudget, isPostTargetSeed,
            covEdgeSetWithDistance.reachedTargetContexts, rarityScore,
            covEdgeSetWithDistance.distanceToTargets, covEdgeSetWithDistance.perTargetDistances)
    }

    public func addInternal(
        _ program: Program, _ age: Int, _ mutationBudget: Int, _ isPostTargetSeed: Bool = false,
        _ reachedContexts: [UInt32: Set<UInt32>] = [:], _ rarityScore: Double = 1.0,
        _ distance: Double = -1.0, _ perTargetDistances: [Double] = []
    ) {
        if program.size > 0 {
            prepareProgramForInclusion(program, index: totalEntryCounter)

            if !isPostTargetSeed {
                // deal with pre-target seed
                self.preTargetSeeds.append(program)
                self.preTargetAges.append(age)
                self.preTargetMutationBudgets.append(mutationBudget)

                // Calculate and store the weight
                let weight: Double
                if distance < 0 {
                    weight = 0.0001
                } else {
                    weight = 100.0 / (distance + 1.0)
                }
                self.preTargetHarmonicWeights.append(weight)

                // Store per-target distances (instead of computing weights for each target), O(1)
                self.preTargetPerTargetDistances.append(perTargetDistances)

                // Update preTargetKnownDistanceCount for each target with known distance
                for (idx, distance) in perTargetDistances.enumerated() {
                    if distance >= 0 {
                        preTargetKnownDistanceCount[UInt32(idx), default: 0] += 1
                    }
                }

                // Incrementally update cumulative harmonic weight cache if valid, O(1)
                if harmonicWeightsCacheValid && preTargetSeeds.count == lastCachedPreTargetCount + 1
                {
                    let lastCum = cachedCumulativeHarmonicWeights.last ?? 0.0
                    cachedCumulativeHarmonicWeights.append(lastCum + weight)
                    lastCachedPreTargetCount = preTargetSeeds.count
                } else {
                    // RingBuffer overflow or other cases, invalidate cache
                    harmonicWeightsCacheValid = false
                }

                // Invalidate per-target cache (will be rebuilt lazily when needed)
                perTargetWeightsCacheValid = false
            } else {
                // deal with post-target seed
                self.postTargetSeeds.append(program)
                self.postTargetAges.append(age)
                self.postTargetMutationBudgets.append(mutationBudget)
                // Store the required targets for this seed (the targets it reached)
                let requiredTargets = Set(reachedContexts.keys)
                self.postTargetRequiredTargets.append(requiredTargets)
                self.postTargetRarityScores.append(rarityScore)
                logger.info(
                    "Added post-target seed, reached targets: \(reachedContexts.keys.sorted()), rarity score: \(rarityScore)"
                )
            }

            self.totalEntryCounter += 1
        }
    }

    /// Returns a random program from this corpus for use in splicing to another program
    public func randomElementForSplicing() -> Program {
        let totalCount = preTargetSeeds.count + postTargetSeeds.count
        assert(totalCount > 0, "Corpus should not be empty")

        let idx = Int.random(in: 0..<totalCount)
        let program: Program
        if idx < preTargetSeeds.count {
            program = preTargetSeeds[idx]
        } else {
            program = postTargetSeeds[idx - preTargetSeeds.count]
        }
        assert(!program.isEmpty)
        return program
    }

    /// Returns a random program from this corpus and increases its age by one.
    public func randomElementForMutating() -> Program {
        guard !preTargetSeeds.isEmpty || !postTargetSeeds.isEmpty else {
            logger.fatal("Corpus should not be empty")
        }

        // // get the current target coverage
        // let targetCoverage = Double(targetReachedCounts.count) / Double(numTotalTargets!)
        // logger.info("Target coverage: \(String(format: "%.2f", targetCoverage * 100))%")

        // Decide whether to pick from pre-target or post-target seeds, 50/50
        let pickPreTarget = postTargetSeeds.isEmpty || Bool.random()

        var program: Program
        if pickPreTarget {
            preTargetSelectionCount += 1
            var selectedIdx = -1

            if guidedByTargetSpecificDistance, let targetId = selectTargetBasedOnRarity() {
                // Now we have selected a target to focus on
                // Update target selection count
                targetSelectionCount[targetId, default: 0] += 1

                // Target-specific guidance using cached cumulative weights
                ensurePerTargetWeightsCacheValid(targetId: targetId)
                if let cumWeights = cachedPerTargetCumulativeWeights[targetId], !cumWeights.isEmpty
                {
                    // O(log N) binary search on cached cumulative weights
                    selectedIdx = binarySearchInCumulativeWeights(cumWeights)
                } else {
                    // Should not happen if logic is correct, but fallback safely
                    selectedIdx = Int.random(in: 0..<preTargetSeeds.count)
                }
            }

            if selectedIdx == -1 {
                // Fallback to harmonic distance guidance
                // Pre-target seed: Weighted selection based on harmonic distance
                // We want to favor seeds with smaller distances.

                // Ensure cached cumulative harmonic weights are valid
                ensureHarmonicWeightsCacheValid()

                // O(log N) binary search on cached cumulative weights
                selectedIdx = binarySearchInCumulativeWeights(cachedCumulativeHarmonicWeights)
                if selectedIdx == -1 {
                    // Fallback if cache is somehow empty
                    selectedIdx = Int.random(in: 0..<preTargetSeeds.count)
                }
            }

            preTargetAges[selectedIdx] += 1
            currentMutationRequiredTargets = nil
            program = preTargetSeeds[selectedIdx]
        } else {
            postTargetSelectionCount += 1
            // Post-target seed: Select randomly (Uniform Distribution)
            // Since we do not know which target will contribute to the bug triggering
            let selectedIdx = Int.random(in: 0..<postTargetSeeds.count)

            postTargetAges[selectedIdx] += 1
            currentMutationRequiredTargets = postTargetRequiredTargets[selectedIdx]
            program = postTargetSeeds[selectedIdx]
        }
        assert(!program.isEmpty)
        return program
    }

    /// Returns the required targets for the current mutation seed
    /// Returns nil if the seed is not a post-target seed
    public func getCurrentRequiredTargets() -> Set<UInt32>? {
        return currentMutationRequiredTargets
    }

    public func allPrograms() -> [Program] {
        return Array(preTargetSeeds) + Array(postTargetSeeds)
    }

    public func exportState() throws -> Data {
        let allPrograms = Array(preTargetSeeds) + Array(postTargetSeeds)
        let res = try encodeProtobufCorpus(allPrograms)
        logger.info("Successfully serialized \(allPrograms.count) programs")
        return res
    }

    public func importState(_ buffer: Data) throws {
        let newPrograms = try decodeProtobufCorpus(buffer)
        preTargetSeeds.removeAll()
        preTargetAges.removeAll()
        preTargetMutationBudgets.removeAll()
        preTargetHarmonicWeights.removeAll()
        preTargetPerTargetDistances.removeAll()
        postTargetSeeds.removeAll()
        postTargetAges.removeAll()
        postTargetMutationBudgets.removeAll()
        postTargetRequiredTargets.removeAll()
        targetReachedCount.removeAll()
        preTargetKnownDistanceCount.removeAll()
        currentMutationRequiredTargets = nil

        // Invalidate caches
        harmonicWeightsCacheValid = false
        perTargetWeightsCacheValid = false
        cachedCumulativeHarmonicWeights.removeAll()
        cachedPerTargetCumulativeWeights.removeAll()
        lastCachedPreTargetCount = 0

        // for each program, add it to the corpus with age = 0 and mutation threshold = defaultMutationsPerSample
        newPrograms.forEach { program in
            addInternal(program, 0, defaultMutationBudget, false, [:])
        }
    }

    /// Selects an index based on the provided weights using the cumulative weight method.
    /// Complexity: O(N) to build cumulative weights + O(log N) to search.
    private func weightedRandomSelection(weights: [Double]) -> Int {
        assert(!weights.isEmpty)

        // 1. Build cumulative weights, O(N)
        var cumWeights = [Double]()
        cumWeights.reserveCapacity(weights.count)
        var currentSum = 0.0
        for i in 0..<weights.count {
            currentSum += weights[i]
            cumWeights.append(currentSum)
        }

        // 2. Random selection, O(log N)
        let totalWeight = currentSum
        // Handle case where all weights are 0
        if totalWeight == 0 {
            return Int.random(in: 0..<weights.count)
        }

        let r = Double.random(in: 0..<totalWeight)

        // 3. Binary search for the first element > r
        var low = 0
        var high = cumWeights.count - 1
        var selectedIdx = 0

        while low <= high {
            let mid = (low + high) / 2
            if cumWeights[mid] <= r {
                low = mid + 1
            } else {
                selectedIdx = mid
                high = mid - 1
            }
        }

        return selectedIdx
    }

    private func selectTargetBasedOnRarity() -> UInt32? {
        guard let numTargets = numTotalTargets, numTargets > 0 else { return nil }

        var weights = [Double]()
        weights.reserveCapacity(numTargets)
        var targets = [UInt32]()
        targets.reserveCapacity(numTargets)

        let k: UInt32 = 100

        for i in 0..<numTargets {
            let targetId = UInt32(i)
            let count = targetReachedCount[targetId] ?? 0
            // Weight = 1.0 / (count + k)
            // Targets with 0 count get weight 1.0
            // Targets with high count get lower weight
            weights.append(1.0 / Double(count + k))
            targets.append(targetId)
        }

        if weights.isEmpty { return nil }

        let idx = weightedRandomSelection(weights: weights)
        return targets[idx]
    }

    /// Ensures the harmonic weights cumulative cache is valid.
    /// Rebuilds the cache if it's invalid, O(N).
    private func ensureHarmonicWeightsCacheValid() {
        guard !harmonicWeightsCacheValid else { return }

        // Rebuild cumulative weights from scratch, O(N)
        cachedCumulativeHarmonicWeights.removeAll()
        cachedCumulativeHarmonicWeights.reserveCapacity(preTargetHarmonicWeights.count)

        var cumSum = 0.0
        for i in 0..<preTargetHarmonicWeights.count {
            cumSum += preTargetHarmonicWeights[i]
            cachedCumulativeHarmonicWeights.append(cumSum)
        }

        harmonicWeightsCacheValid = true
        lastCachedPreTargetCount = preTargetSeeds.count
    }

    /// Ensures the cumulative weights cache for a specific target is valid.
    /// Rebuilds from preTargetPerTargetDistances if needed, O(N).
    private func ensurePerTargetWeightsCacheValid(targetId: UInt32) {
        // If per-target cache is already valid and this target exists, return
        if perTargetWeightsCacheValid, cachedPerTargetCumulativeWeights[targetId] != nil {
            return
        }

        let k = 1.0  // smoothing parameter for distance weight
        let alpha = 1.0  // maximum weight for unknown-distance seeds

        // O(1) calculation of r(t*) using preTargetKnownDistanceCount
        let knownCount = preTargetKnownDistanceCount[targetId] ?? 0
        let totalCount = preTargetPerTargetDistances.count
        let r_t = totalCount > 0 ? Double(knownCount) / Double(totalCount) : 0.0

        // epsilon(t*) = alpha * (1 - r(t*))
        // When distance info is sparse (r_t small), epsilon is large -> encourage exploration
        // When distance info is abundant (r_t large), epsilon is small -> inverse-distance dominates
        let epsilon_t = alpha * (1.0 - r_t)

        // Rebuild cumulative weights for this target from distances
        var cumWeights = [Double]()
        cumWeights.reserveCapacity(totalCount)

        var cumSum = 0.0
        for i in 0..<totalCount {
            let distances = preTargetPerTargetDistances[i]
            let weight: Double
            if Int(targetId) < distances.count && distances[Int(targetId)] >= 0 {
                // Known distance: use inverse-distance weight
                weight = 1.0 / (distances[Int(targetId)] + k)
            } else {
                // Unknown distance: use dynamic epsilon(t*)
                weight = epsilon_t
            }
            cumSum += weight
            cumWeights.append(cumSum)
        }

        cachedPerTargetCumulativeWeights[targetId] = cumWeights
    }

    /// Marks all per-target weight caches as valid after a full rebuild pass.
    private func markPerTargetCacheValid() {
        perTargetWeightsCacheValid = true
    }

    /// Binary search on cumulative weights to select an index, O(log N).
    /// Returns -1 if cumulative weights are empty.
    private func binarySearchInCumulativeWeights(_ cumWeights: [Double]) -> Int {
        guard !cumWeights.isEmpty else { return -1 }

        let totalWeight = cumWeights.last!
        // Handle case where all weights are 0
        if totalWeight == 0 {
            return Int.random(in: 0..<cumWeights.count)
        }

        let r = Double.random(in: 0..<totalWeight)

        // Binary search for the first element > r
        var low = 0
        var high = cumWeights.count - 1
        var selectedIdx = 0

        while low <= high {
            let mid = (low + high) / 2
            if cumWeights[mid] <= r {
                low = mid + 1
            } else {
                selectedIdx = mid
                high = mid - 1
            }
        }

        return selectedIdx
    }

    private func cleanup() {
        // regularly clean up the corpus
        assert(!fuzzer.config.staticCorpus)

        // Clean up pre-target seeds
        var newPreTargetSeeds = RingBuffer<Program>(maxSize: preTargetSeeds.maxSize)
        var newPreTargetAges = RingBuffer<Int>(maxSize: preTargetAges.maxSize)
        var newPreTargetMutationBudgets = RingBuffer<Int>(maxSize: preTargetMutationBudgets.maxSize)
        var newPreTargetHarmonicWeights = RingBuffer<Double>(
            maxSize: preTargetHarmonicWeights.maxSize)
        var newPreTargetPerTargetDistances = RingBuffer<[Double]>(
            maxSize: preTargetPerTargetDistances.maxSize)

        for i in 0..<preTargetSeeds.count {
            let remaining = preTargetSeeds.count - i
            // keep the sample if it has been mutated less than the mutation budget,
            // or if the corpus is not full yet
            if preTargetAges[i] < preTargetMutationBudgets[i]
                || remaining <= (minSize - newPreTargetSeeds.count)
            {
                newPreTargetSeeds.append(preTargetSeeds[i])
                newPreTargetAges.append(preTargetAges[i])
                newPreTargetMutationBudgets.append(preTargetMutationBudgets[i])
                newPreTargetHarmonicWeights.append(preTargetHarmonicWeights[i])
                newPreTargetPerTargetDistances.append(preTargetPerTargetDistances[i])
            }
        }

        // Clean up post-target seeds
        var newPostTargetSeeds = RingBuffer<Program>(maxSize: postTargetSeeds.maxSize)
        var newPostTargetAges = RingBuffer<Int>(maxSize: postTargetAges.maxSize)
        var newPostTargetMutationBudgets = RingBuffer<Int>(
            maxSize: postTargetMutationBudgets.maxSize)
        var newPostTargetRequiredTargets = RingBuffer<Set<UInt32>>(
            maxSize: postTargetRequiredTargets.maxSize)
        var newPostTargetRarityScores = RingBuffer<Double>(maxSize: postTargetRarityScores.maxSize)

        for i in 0..<postTargetSeeds.count {
            let remaining = postTargetSeeds.count - i
            // keep the sample if it has been mutated less than the mutation budget,
            // or if the corpus is not full yet
            if postTargetAges[i] < postTargetMutationBudgets[i]
                || remaining <= (minSize - newPreTargetSeeds.count)
            {
                newPostTargetSeeds.append(postTargetSeeds[i])
                newPostTargetAges.append(postTargetAges[i])
                newPostTargetMutationBudgets.append(postTargetMutationBudgets[i])
                newPostTargetRequiredTargets.append(postTargetRequiredTargets[i])
                newPostTargetRarityScores.append(postTargetRarityScores[i])
            }
        }

        cleanupCount += 1
        removedPreTargetSeedsCount += (preTargetSeeds.count - newPreTargetSeeds.count)
        removedPostTargetSeedsCount += (postTargetSeeds.count - newPostTargetSeeds.count)

        logger.info(
            "Corpus cleanup finished: Pre-target seeds: \(preTargetSeeds.count) -> \(newPreTargetSeeds.count), Post-target seeds: \(postTargetSeeds.count) -> \(newPostTargetSeeds.count)"
        )

        preTargetSeeds = newPreTargetSeeds
        preTargetAges = newPreTargetAges
        preTargetMutationBudgets = newPreTargetMutationBudgets
        preTargetHarmonicWeights = newPreTargetHarmonicWeights
        preTargetPerTargetDistances = newPreTargetPerTargetDistances
        postTargetSeeds = newPostTargetSeeds
        postTargetAges = newPostTargetAges
        postTargetMutationBudgets = newPostTargetMutationBudgets
        postTargetRequiredTargets = newPostTargetRequiredTargets
        postTargetRarityScores = newPostTargetRarityScores

        // Rebuild preTargetKnownDistanceCount from the new preTargetPerTargetDistances
        preTargetKnownDistanceCount.removeAll()
        for i in 0..<preTargetPerTargetDistances.count {
            let distances = preTargetPerTargetDistances[i]
            for (idx, distance) in distances.enumerated() {
                if distance >= 0 {
                    preTargetKnownDistanceCount[UInt32(idx), default: 0] += 1
                }
            }
        }

        // Invalidate caches after cleanup
        harmonicWeightsCacheValid = false
        perTargetWeightsCacheValid = false
        cachedPerTargetCumulativeWeights.removeAll()
    }

    public var startIndex: Int {
        return 0
    }

    public var endIndex: Int {
        return preTargetSeeds.count + postTargetSeeds.count
    }

    public subscript(index: Int) -> Program {
        if index < preTargetSeeds.count {
            return preTargetSeeds[index]
        } else {
            return postTargetSeeds[index - preTargetSeeds.count]
        }
    }

    public func index(after i: Int) -> Int {
        return i + 1
    }

    public func getNumTotalTargets() -> Int {
        return numTotalTargets ?? 0
    }

    public func getLengthOfPreTargetSeeds() -> Int {
        return preTargetSeeds.count
    }

    public func getLengthOfPostTargetSeeds() -> Int {
        return postTargetSeeds.count
    }

    public func getAvgAgeOfPreTargetSeeds() -> Double {
        guard !preTargetAges.isEmpty else { return 0.0 }
        return Double(preTargetAges.reduce(0, +)) / Double(preTargetAges.count)
    }

    public func getMaxAgeOfPreTargetSeeds() -> Int {
        return preTargetAges.max() ?? 0
    }

    public func getMinAgeOfPreTargetSeeds() -> Int {
        return preTargetAges.min() ?? 0
    }

    public func getMidAgeOfPreTargetSeeds() -> Int {
        guard !preTargetAges.isEmpty else { return 0 }
        return preTargetAges.sorted()[preTargetAges.count / 2]
    }

    public func getAvgAgeOfPostTargetSeeds() -> Double {
        guard !postTargetAges.isEmpty else { return 0.0 }
        return Double(postTargetAges.reduce(0, +)) / Double(postTargetAges.count)
    }

    public func getMaxAgeOfPostTargetSeeds() -> Int {
        return postTargetAges.max() ?? 0
    }

    public func getMinAgeOfPostTargetSeeds() -> Int {
        return postTargetAges.min() ?? 0
    }

    public func getMidAgeOfPostTargetSeeds() -> Int {
        guard !postTargetAges.isEmpty else { return 0 }
        return postTargetAges.sorted()[postTargetAges.count / 2]
    }

    /// Returns the time (in milliseconds) when each target was first reached.
    /// Array indexed by target ID. 0 means the target hasn't been reached yet.
    public func getFirstTargetReachingTime() -> [UInt64] {
        return firstTargetReachedTime
    }

    /// Returns the number of programs that reached each target.
    /// Key: target ID, Value: number of programs that reached this target
    public func getTargetReachingCount() -> [UInt32: UInt32] {
        return targetReachedCount
    }

    public func getTargetSelectionCount() -> [UInt32: UInt32] {
        return targetSelectionCount
    }

    public func getCleanupStats() -> (
        cleanupCount: Int, removedPreTargetSeeds: Int, removedPostTargetSeeds: Int
    ) {
        return (cleanupCount, removedPreTargetSeedsCount, removedPostTargetSeedsCount)
    }

    public func getMutationSelectionStats() -> (preTarget: Int, postTarget: Int) {
        return (preTargetSelectionCount, postTargetSelectionCount)
    }
}
