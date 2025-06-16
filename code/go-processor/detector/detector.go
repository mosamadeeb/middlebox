package detector

import (
	"log"
	"sort"
	"sync"
)

const (
	// DefaultDisplacementThreshold is the default value for DT.
	// Packets with displacement |D| > DT are not counted in RD.
	DefaultDisplacementThreshold = 10 // As per RFC examples, can be tuned.
	// DefaultRDFrameSize is the default number of packets to analyze in one frame for RD.
	DefaultRDFrameSize = 50 // Can be tuned.
)

// RDCalculator computes Reorder Density for frames of packets.
type RDCalculator struct {
	dt                  int
	frameSize           int
	outputChan          chan map[int]float64
	logFunc             func(format string, args ...interface{})
	mu                  sync.Mutex
	currentFramePackets []uint64
}

// NewRDCalculator creates a new RDCalculator.
// dt: Displacement Threshold.
// frameSize: Number of packets per RD calculation frame.
// outputChan: Channel to send computed RD maps (displacement -> density).
// logFunc: Logger function.
func NewRDCalculator(dt, frameSize int, outputChan chan map[int]float64, logFunc func(format string, args ...interface{})) *RDCalculator {
	if logFunc == nil {
		logFunc = log.Printf // Default logger
	}
	return &RDCalculator{
		dt:                  dt,
		frameSize:           frameSize,
		outputChan:          outputChan,
		logFunc:             logFunc,
		currentFramePackets: make([]uint64, 0, frameSize),
	}
}

// AddPacket adds a sequence number to the current frame.
// If the frame becomes full, it triggers RD computation for that frame.
func (rdc *RDCalculator) AddPacket(seq uint64) {
	rdc.mu.Lock()
	defer rdc.mu.Unlock()

	rdc.currentFramePackets = append(rdc.currentFramePackets, seq)

	if len(rdc.currentFramePackets) >= rdc.frameSize {
		// Copy current frame for processing to allow new packets to be added concurrently
		frameToProcess := make([]uint64, len(rdc.currentFramePackets))
		copy(frameToProcess, rdc.currentFramePackets)
		rdc.currentFramePackets = make([]uint64, 0, rdc.frameSize) // Reset for next frame

		// Process in a goroutine to not block AddPacket caller if outputChan is slow
		go rdc.computeAndSendRD(frameToProcess)
	}
}

// computeAndSendRD calculates the Reorder Density for the given frame of sequence numbers
// and sends the result to the output channel.
func (rdc *RDCalculator) computeAndSendRD(sequences []uint64) {
	if len(sequences) == 0 {
		// rdc.logFunc("RDCalculator: No sequences in frame to compute RD.")
		return
	}

	// 1. Filter duplicates, maintaining arrival order, and assign RI.
	// RI is the 1-based arrival index among unique packets.
	type PacketArrival struct {
		Seq uint64
		RI  int // Receive Index (1-based arrival order of unique packets)
	}
	uniqueArrivals := make([]PacketArrival, 0, len(sequences))
	seenSequences := make(map[uint64]bool)
	currentRI := 1
	for _, seq := range sequences {
		if !seenSequences[seq] {
			uniqueArrivals = append(uniqueArrivals, PacketArrival{Seq: seq, RI: currentRI})
			seenSequences[seq] = true
			currentRI++
		}
	}

	nPrime := len(uniqueArrivals)
	if nPrime == 0 {
		// rdc.logFunc("RDCalculator: No unique sequences in frame to compute RD.")
		return
	}

	// 2. Determine expected order for unique packets.
	// Create a list of just the unique sequence numbers to sort them.
	seqsForSorting := make([]uint64, nPrime)
	for i, arrival := range uniqueArrivals {
		seqsForSorting[i] = arrival.Seq
	}
	sort.Slice(seqsForSorting, func(i, j int) bool {
		return seqsForSorting[i] < seqsForSorting[j]
	})

	// Map sequence number to its 1-based expected position in the sorted list.
	seqToExpectedOrder := make(map[uint64]int, nPrime)
	for i, seq := range seqsForSorting {
		seqToExpectedOrder[seq] = i + 1
	}

	// 3. Calculate Displacement Frequencies (FD).
	fd := make(map[int]int)
	for _, arrival := range uniqueArrivals {
		expectedPos, ok := seqToExpectedOrder[arrival.Seq]
		if !ok {
			// Should not happen if logic is correct
			rdc.logFunc("RDCalculator: Error - sequence %d not found in expected order map.", arrival.Seq)
			continue
		}

		displacement := arrival.RI - expectedPos
		if abs(displacement) <= rdc.dt {
			fd[displacement]++
		}
	}

	// 4. Normalize FD to get RD.
	rdMap := make(map[int]float64)
	if nPrime > 0 {
		for d, count := range fd {
			rdMap[d] = float64(count) / float64(nPrime)
		}
	}

	// rdc.logFunc("RDCalculator: Computed RD for frame of %d unique packets: %v", nPrime, rdMap)
	rdc.outputChan <- rdMap
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// Close stops the RDCalculator, primarily for signaling that no more RD maps will be sent.
// It's the responsibility of the user to ensure AddPacket is no longer called.
func (rdc *RDCalculator) Close() {
	rdc.mu.Lock()
	defer rdc.mu.Unlock()
	// If there are any remaining packets, process them.
	if len(rdc.currentFramePackets) > 0 {
		frameToProcess := make([]uint64, len(rdc.currentFramePackets))
		copy(frameToProcess, rdc.currentFramePackets)
		rdc.currentFramePackets = make([]uint64, 0, rdc.frameSize)
		// Process synchronously as we are closing.
		rdc.computeAndSendRD(frameToProcess)
	}
	close(rdc.outputChan)
}
