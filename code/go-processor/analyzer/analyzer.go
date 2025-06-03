package analyzer

import (
	"fmt"
	"log"
	"math"
	"sort"
	"strings"
	"time"
)

// Config holds configuration for the Analyzer.
type Config struct {
	FrameSizeN            int           // For RD, and general frame processing.
	PermutationFrameSizeK int           // For permutation analysis (k <= N is typical but not enforced here).
	ReportInterval        time.Duration // How often to report metrics.
}

// MetricsReport is a snapshot of the calculated metrics.
type MetricsReport struct {
	Timestamp                time.Time
	RDHistogram              map[int]int // Displacement -> Count
	RBDCurrentOccupancy      int
	RBDMaxObservedInInterval int            // Max RBD observed since last report
	PermutationFrequencies   map[string]int // Permutation (e.g., "0-2-1") -> Count
	PermutationEntropy       float64
	TotalPermutations        int // Total permutations processed in the interval for entropy calculation
}

// Analyzer processes packets and calculates reordering metrics.
type Analyzer struct {
	config  Config
	inChan  <-chan Packet
	outChan chan<- MetricsReport // Channel to send out periodic reports

	// Internal state
	packetBufferForFrameN []packetWithOriginalIndex // Buffer N packets for frame-based RD
	lastReportTime        time.Time

	// RD state
	rdDisplacementCounts map[int]int // displacement -> count (for the current reporting interval)

	// RBD state
	rbdReorderBuffer  Packets // Buffer for out-of-order packets for RBD
	rbdExpectedSeqNum uint64  // Next sequence number expected to be "released"
	rbdMaxInInterval  int     // Max RBD observed in the current reporting interval
	rbdInitialized    bool    // Flag to manage initial rbdExpectedSeqNum setting

	// Permutation state
	currentPermutationWindow    []Packet       // Collects k packets for one permutation
	permutationCounts           map[string]int // Stores frequencies of permutations for the current interval
	totalPermutationsInInterval int            // Counter for permutations in the interval
}

// packetWithOriginalIndex helps in RD calculation by tracking original arrival order within a frame.
type packetWithOriginalIndex struct {
	Packet
	OriginalIndexInFrame int
}

// NewAnalyzer creates a new Analyzer.
func NewAnalyzer(config Config, inChan <-chan Packet, outChan chan<- MetricsReport) *Analyzer {
	if config.PermutationFrameSizeK < 0 {
		config.PermutationFrameSizeK = 0 // Disable if negative
	}
	if config.FrameSizeN < 0 {
		config.FrameSizeN = 0 // Disable if negative
	}
	return &Analyzer{
		config:                      config,
		inChan:                      inChan,
		outChan:                     outChan,
		packetBufferForFrameN:       make([]packetWithOriginalIndex, 0, config.FrameSizeN),
		lastReportTime:              time.Now(),
		rdDisplacementCounts:        make(map[int]int),
		rbdReorderBuffer:            make(Packets, 0),
		rbdExpectedSeqNum:           0, // Will be initialized by the first packet or adapt
		rbdInitialized:              false,
		rbdMaxInInterval:            0,
		currentPermutationWindow:    make([]Packet, 0, config.PermutationFrameSizeK),
		permutationCounts:           make(map[string]int),
		totalPermutationsInInterval: 0,
	}
}

// Start begins the analysis process. This should be run in a goroutine.
func (a *Analyzer) Start() {
	log.Println("Analyzer started...")
	if a.config.FrameSizeN == 0 {
		log.Println("Info: FrameSizeN is 0, RD calculation will be skipped.")
	}
	if a.config.PermutationFrameSizeK == 0 {
		log.Println("Info: PermutationFrameSizeK is 0, permutation metrics will be skipped.")
	}

	ticker := time.NewTicker(a.config.ReportInterval)
	defer ticker.Stop()

	for {
		select {
		case packet, ok := <-a.inChan:
			if !ok {
				log.Println("Input channel closed. Analyzer generating final report and stopping.")
				a.generateReport()
				if a.outChan != nil {
					close(a.outChan)
				}
				return
			}

			a.processRBD(packet)
			if a.config.PermutationFrameSizeK > 0 {
				a.processPermutations(packet)
			}
			if a.config.FrameSizeN > 0 {
				a.addToFrameNBuffer(packet)

				// Generate report after every frame
				if len(a.packetBufferForFrameN) == 0 {
					a.generateReport()

					// Reset ticker after report
					ticker.Reset(a.config.ReportInterval)
				}
			}

		case <-ticker.C:
			// Still generate report on interval, in case frames are not complete
			a.generateReport()
		}
	}
}

func (a *Analyzer) addToFrameNBuffer(packet Packet) {
	a.packetBufferForFrameN = append(a.packetBufferForFrameN, packetWithOriginalIndex{
		Packet:               packet,
		OriginalIndexInFrame: len(a.packetBufferForFrameN),
	})

	if len(a.packetBufferForFrameN) == a.config.FrameSizeN {
		a.calculateRDForFrame()
		a.packetBufferForFrameN = make([]packetWithOriginalIndex, 0, a.config.FrameSizeN) // Reset buffer
	}
}

func (a *Analyzer) processRBD(packet Packet) {
	if !a.rbdInitialized {
		// Initialize with the first packet's sequence number.
		// This assumes sequence numbers are generally increasing.
		a.rbdExpectedSeqNum = packet.SequenceNumber
		a.rbdInitialized = true
	}

	a.rbdReorderBuffer = append(a.rbdReorderBuffer, packet)
	sort.Sort(a.rbdReorderBuffer) // Sort by sequence number

	// Measure and update max occupancy *after* adding the packet and sorting,
	// but *before* any dispatch attempts in this call.
	// This reflects the buffer's state with the newly arrived packet.
	currentPotentialOccupancy := len(a.rbdReorderBuffer)
	if currentPotentialOccupancy > a.rbdMaxInInterval {
		a.rbdMaxInInterval = currentPotentialOccupancy
	}

	// Remove stale packets (seq < current rbdExpectedSeqNum) from the front of the buffer.
	// These are packets "older" than what we are currently waiting for.
	// This handles duplicates or very late packets if rbdExpectedSeqNum somehow jumped
	// in a more complex scenario (though here it advances sequentially).
	i := 0
	for i < len(a.rbdReorderBuffer) && a.rbdReorderBuffer[i].SequenceNumber < a.rbdExpectedSeqNum {
		i++
	}
	if i > 0 {
		a.rbdReorderBuffer = a.rbdReorderBuffer[i:]
	}

	// Dispatch in-order packets from the buffer.
	// rbdExpectedSeqNum only advances if a packet is dispatched.
	// This loop will run as long as the head of the buffer matches the expected sequence number
	// and will consume all contiguous in-order packets.
	for len(a.rbdReorderBuffer) > 0 && a.rbdReorderBuffer[0].SequenceNumber == a.rbdExpectedSeqNum {
		a.rbdReorderBuffer = a.rbdReorderBuffer[1:]
		a.rbdExpectedSeqNum++
	}

	// After these operations, len(a.rbdReorderBuffer) is the current number of packets
	// being buffered because they are out of order (i.e., their sequence number is
	// greater than rbdExpectedSeqNum).
	// This current length will be used by generateReport for RBDCurrentOccupancy.
	// The rbdMaxInInterval has captured the peak size observed right after any packet
	// was added during the processing cycle within the reporting interval.
}

func (a *Analyzer) calculateRDForFrame() {
	if len(a.packetBufferForFrameN) == 0 {
		return
	}

	frameCopy := make([]packetWithOriginalIndex, len(a.packetBufferForFrameN))
	copy(frameCopy, a.packetBufferForFrameN)

	sort.Slice(frameCopy, func(i, j int) bool {
		return frameCopy[i].SequenceNumber < frameCopy[j].SequenceNumber
	})

	for sortedIndex, pkt := range frameCopy {
		displacement := pkt.OriginalIndexInFrame - sortedIndex
		a.rdDisplacementCounts[displacement]++
	}
}

func (a *Analyzer) processPermutations(packet Packet) {
	a.currentPermutationWindow = append(a.currentPermutationWindow, packet)

	if len(a.currentPermutationWindow) == a.config.PermutationFrameSizeK {
		k := a.config.PermutationFrameSizeK

		type seqWithIndex struct {
			seq   uint64
			index int // Original index in the k-window (0 to k-1)
		}

		tempSlice := make([]seqWithIndex, k)
		for i, p := range a.currentPermutationWindow {
			tempSlice[i] = seqWithIndex{seq: p.SequenceNumber, index: i}
		}

		sort.Slice(tempSlice, func(i, j int) bool {
			return tempSlice[i].seq < tempSlice[j].seq
		})

		// permutation[original_index] = rank (sorted_index)
		permutationRanks := make([]int, k)
		for rank, swi := range tempSlice {
			permutationRanks[swi.index] = rank
		}

		var sb strings.Builder
		for i, rankVal := range permutationRanks {
			if i > 0 {
				sb.WriteString("-")
			}
			sb.WriteString(fmt.Sprintf("%d", rankVal))
		}
		permKey := sb.String()

		a.permutationCounts[permKey]++
		a.totalPermutationsInInterval++

		a.currentPermutationWindow = make([]Packet, 0, a.config.PermutationFrameSizeK) // Reset window
	}
}

func (a *Analyzer) calculateEntropy() float64 {
	if a.totalPermutationsInInterval == 0 {
		return 0.0
	}

	entropy := 0.0
	for _, count := range a.permutationCounts {
		if count > 0 {
			p := float64(count) / float64(a.totalPermutationsInInterval)
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func (a *Analyzer) generateReport() {
	entropy := a.calculateEntropy()

	rdHistCopy := make(map[int]int)
	for k, v := range a.rdDisplacementCounts {
		rdHistCopy[k] = v
	}

	permFreqCopy := make(map[string]int)
	for k, v := range a.permutationCounts {
		permFreqCopy[k] = v
	}

	report := MetricsReport{
		Timestamp:                time.Now(),
		RDHistogram:              rdHistCopy,
		RBDCurrentOccupancy:      len(a.rbdReorderBuffer),
		RBDMaxObservedInInterval: a.rbdMaxInInterval,
		PermutationFrequencies:   permFreqCopy,
		PermutationEntropy:       entropy,
		TotalPermutations:        a.totalPermutationsInInterval,
	}

	if a.outChan != nil {
		select {
		case a.outChan <- report:
		default:
			log.Println("Warning: Metrics report channel is full. Report dropped.")
		}
	} else {
		log.Printf("Metrics Report (no output channel) at %s:\n  RD: %v\n  RBD Current: %d, Max: %d\n  Perm Freq: %v (Total: %d)\n  Entropy: %.4f\n",
			report.Timestamp.Format(time.RFC3339), report.RDHistogram, report.RBDCurrentOccupancy, report.RBDMaxObservedInInterval,
			report.PermutationFrequencies, report.TotalPermutations, report.PermutationEntropy)
	}

	// Reset interval-based metrics
	a.rdDisplacementCounts = make(map[int]int)
	a.rbdMaxInInterval = len(a.rbdReorderBuffer) // Current occupancy becomes the starting max for next interval
	a.permutationCounts = make(map[string]int)
	a.totalPermutationsInInterval = 0
	a.lastReportTime = time.Now()
}

// Factorial calculates n!
// Useful for understanding the number of possible permutations (k!) for entropy context.
func Factorial(n int) int {
	if n < 0 {
		return 0 // Or handle error
	}
	if n == 0 {
		return 1
	}
	res := 1
	for i := 2; i <= n; i++ {
		res *= i
	}
	return res
}
