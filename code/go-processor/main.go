package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"os"
	"sort"    // Added for sorting sequence numbers
	"strconv" // Added for sequence logging
	"strings" // Added for sequence logging
	"sync"    // Added for graceful shutdown
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/nats-io/nats.go"
)

// Create a seeded random source for reproducibility
var (
	random                = rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
	delay                 float64 // Delay in milliseconds
	meanJitter            float64 // Jitter mean in milliseconds
	enableMitigation      bool    // Enable covert channel mitigation
	totalSequencesLogged  uint64  // Counter for logged sequences
	reorderBufferInstance *ReorderBuffer
	reorderSignalChan     chan struct{}
	nextExpectedSeq       uint32 = 1001 // Initial expected sequence number for mitigation
)

const reorderBufferCapacity = 10 // Max packets in reorder buffer before flush

// ReorderBuffer holds packets to be sent in order
type ReorderBuffer struct {
	packets    map[uint32][]byte // Map sequence number to packet data
	sortedSeqs []uint32          // Slice of unique sequence numbers, kept sorted
	mu         sync.Mutex
	// isInitialized bool // Removed, state inferred from collections
}

// NewReorderBuffer creates a new ReorderBuffer
func NewReorderBuffer() *ReorderBuffer {
	return &ReorderBuffer{
		packets:    make(map[uint32][]byte),
		sortedSeqs: make([]uint32, 0),
	}
}

// AddPacket adds a packet to the reorder buffer
func (rb *ReorderBuffer) AddPacket(seq uint32, data []byte) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if _, exists := rb.packets[seq]; exists {
		log.Printf("Mitigation: Packet with SEQ %d already in buffer, ignoring duplicate.\n", seq)
		return // Don't re-add or re-signal for an existing packet
	}

	rb.packets[seq] = data
	rb.sortedSeqs = append(rb.sortedSeqs, seq)
	sort.Slice(rb.sortedSeqs, func(i, j int) bool { return rb.sortedSeqs[i] < rb.sortedSeqs[j] })

	// if !rb.isInitialized && len(rb.sortedSeqs) > 0 { // Logic related to isInitialized removed
	// 	rb.isInitialized = true
	// }

	// Signal sender that a new packet is available or buffer state changed
	select {
	case reorderSignalChan <- struct{}{}:
	default: // Channel is full, sender is busy or will pick it up
	}
}

var seqLogFilename string // Filename for sequence logs
const (
	seqBufferMaxSize = 1000 // Buffer size for batching sequence writes
	timeout          = 10 * time.Second
)

// Function to write sequences to file
func writeSequencesToFile(sequences []uint64, filename string) {
	if len(sequences) == 0 {
		return
	}

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("Error opening sequence log file %s: %v\n", filename, err)
		return
	}
	defer f.Close()

	var b strings.Builder
	for _, seq := range sequences {
		b.WriteString(strconv.FormatUint(seq, 10) + " ")
	}

	if _, err := f.WriteString(b.String()); err != nil {
		log.Printf("Error writing sequences to file %s: %v\n", filename, err)
		return // Don't count if write fails
	}
	totalSequencesLogged += uint64(len(sequences)) // Increment counter
}

// reorderSenderGoroutine sends packets from the ReorderBuffer in sequence order
func reorderSenderGoroutine(nc *nats.Conn, seqChan chan<- uint64) {
	for {
		<-reorderSignalChan // Wait for a signal that new data might be ready

	senderLoop:
		for { // This loop attempts to send packets as long as conditions are met
			reorderBufferInstance.mu.Lock()

			// Condition 1: Buffer capacity reached - flush all sorted packets
			if len(reorderBufferInstance.packets) >= reorderBufferCapacity && len(reorderBufferInstance.sortedSeqs) > 0 {
				log.Printf("Mitigation: Reorder buffer capacity (%d) reached. Flushing %d packets.", reorderBufferCapacity, len(reorderBufferInstance.sortedSeqs))

				highestSentInFlush := nextExpectedSeq - 1 // Initialize to ensure nextExpectedSeq updates correctly

				for len(reorderBufferInstance.sortedSeqs) > 0 {
					seqToFlush := reorderBufferInstance.sortedSeqs[0]
					dataToFlush := reorderBufferInstance.packets[seqToFlush]

					delete(reorderBufferInstance.packets, seqToFlush)
					reorderBufferInstance.sortedSeqs = reorderBufferInstance.sortedSeqs[1:]

					reorderBufferInstance.mu.Unlock() // Unlock for send

					log.Printf("Mitigation (Flush): Sending SEQ %d from reorder buffer.", seqToFlush)
					randomJitterVal := meanJitter * random.ExpFloat64()
					time.Sleep(time.Duration(delay+randomJitterVal) * time.Millisecond)
					err := nc.Publish("outpktinsec", dataToFlush)
					if err != nil {
						log.Printf("Mitigation (Flush): Error publishing message for SEQ %d: %v", seqToFlush, err)
					}
					seqChan <- uint64(seqToFlush)

					if seqToFlush > highestSentInFlush {
						highestSentInFlush = seqToFlush
					}

					reorderBufferInstance.mu.Lock() // Re-lock for the next iteration of the flush loop
				}
				// After loop, lock is held
				if highestSentInFlush >= (nextExpectedSeq-1) && len(reorderBufferInstance.packets) == 0 { // Ensure it was a full flush
					nextExpectedSeq = highestSentInFlush + 1
				} else if highestSentInFlush >= (nextExpectedSeq-1) && len(reorderBufferInstance.packets) > 0 {
					// If flush happened but buffer isn't empty (e.g. new packets arrived during flush)
					// still update nextExpectedSeq based on what was flushed.
					nextExpectedSeq = highestSentInFlush + 1
				}

				log.Printf("Mitigation: Buffer flushed. Next expected SEQ is now %d.", nextExpectedSeq)
				reorderBufferInstance.mu.Unlock()
				break senderLoop // After flush, wait for new signal
			}

			// Condition 2: Send nextExpectedSeq if available
			dataToSend, exists := reorderBufferInstance.packets[nextExpectedSeq]
			if exists {
				delete(reorderBufferInstance.packets, nextExpectedSeq)
				// Remove nextExpectedSeq from sortedSeqs
				foundIndex := -1
				for i, s := range reorderBufferInstance.sortedSeqs {
					if s == nextExpectedSeq {
						foundIndex = i
						break
					}
				}
				if foundIndex != -1 {
					reorderBufferInstance.sortedSeqs = append(reorderBufferInstance.sortedSeqs[:foundIndex], reorderBufferInstance.sortedSeqs[foundIndex+1:]...)
				} else {
					log.Printf("Mitigation Error: SEQ %d in packets map but not in sortedSeqs. Inconsistency.", nextExpectedSeq)
				}

				reorderBufferInstance.mu.Unlock() // Unlock before sleep and NATS publish

				log.Printf("Mitigation: Sending expected SEQ %d from reorder buffer.", nextExpectedSeq)
				randomJitterVal := meanJitter * random.ExpFloat64()
				time.Sleep(time.Duration(delay+randomJitterVal) * time.Millisecond)
				err := nc.Publish("outpktinsec", dataToSend)
				if err != nil {
					log.Printf("Mitigation: Error publishing message for SEQ %d: %v", nextExpectedSeq, err)
				}
				seqChan <- uint64(nextExpectedSeq)

				nextExpectedSeq++
				// Lock is not held, continue senderLoop will re-acquire at the top
				continue senderLoop
			}

			// Condition 3: Expected packet not available and buffer not full, or buffer is empty.
			reorderBufferInstance.mu.Unlock()
			break senderLoop // Go back to waiting for a signal
		}
	}
}

// Function to process the ethernet packet
func processEthernetPacket(nc *nats.Conn, iface string, data []byte, seqChan chan<- uint64) { // Added seqChan parameter
	// Use gopacket to dissect the packet
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	if packet.ErrorLayer() != nil {
		log.Println("Error decoding some part of the packet:", packet.ErrorLayer().Error())
		return
	}

	var tcp *layers.TCP
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp = tcpLayer.(*layers.TCP)

		if tcp.SYN || !tcp.PSH {
			tcp = nil // Ignore packets used in the TCP handshake
		}
	}

	if enableMitigation && iface == "inpktsec" && tcp != nil {
		// Create a copy of data, as the original slice might be reused by NATS or gopacket
		dataCopy := make([]byte, len(data))
		copy(dataCopy, data)
		log.Printf("Mitigation: Buffering SEQ %d\n", tcp.Seq)
		reorderBufferInstance.AddPacket(tcp.Seq, dataCopy)
		// Packet is buffered; reorderSenderGoroutine will handle sending and logging to seqChan
	} else {
		// Original behavior for non-mitigation or non-"inpktsec" packets (e.g., from "inpktinsec")
		go func() {
			// Add a random delay before publishing the packet
			randomJitterVal := meanJitter * random.ExpFloat64()
			time.Sleep(time.Duration(delay+randomJitterVal) * time.Millisecond)

			if iface == "inpktsec" && tcp != nil { // This branch now only active if !enableMitigation
				log.Printf("Sequence arrived (no mitigation): %d\n", tcp.Seq) // Log sequence number as it arrives
				seqChan <- uint64(tcp.Seq)
			}

			// Publish the processed packet to the appropriate subject
			var subject string
			if iface == "inpktsec" {
				subject = "outpktinsec"
			} else {
				subject = "outpktsec"
			}
			err := nc.Publish(subject, data)
			if err != nil {
				log.Println("Error publishing message:", err)
			}
		}()
	}
}

func logSlowConsumer(nc *nats.Conn, sub *nats.Subscription, err error) {
	if err != nil {
		log.Printf("Slow consumer detected: %v\n", err)
	}
}

func main() {
	log.Println("Hello, World!")
	url := os.Getenv("NATS_SURVEYOR_SERVERS")
	if url == "" {
		url = nats.DefaultURL
	}
	log.Println("NATS_SURVEYOR_SERVERS: ", url)

	// Set up command-line flags
	flag.Float64Var(&delay, "delay", 20.0, "Fixed delay to add in milliseconds")
	flag.Float64Var(&meanJitter, "jitter", 1.0, "Mean jitter in milliseconds for exponential distribution")
	flag.BoolVar(&enableMitigation, "mitigate", false, "Enable covert channel mitigation")
	flag.Parse()

	log.Printf("Using mean jitter of %.5f milliseconds\n", meanJitter)
	if enableMitigation {
		log.Println("Covert channel mitigation IS ENABLED.")
	} else {
		log.Println("Covert channel mitigation IS DISABLED.")
	}

	// Setup sequence channel
	seqChan := make(chan uint64, 10000) // Channel buffer for sequence numbers

	// Generate sequence log filename
	timestampStr := time.Now().Format("20060102_150405")
	seqLogFilename = fmt.Sprintf("sequence_log_jitter%.2f_%s.txt",
		meanJitter, timestampStr)
	log.Printf("Sequence numbers will be saved to: %s", seqLogFilename)

	var wg sync.WaitGroup // WaitGroup for the sequence logger

	// Goroutine to log sequence numbers to a file
	wg.Add(1)
	go func() {
		defer wg.Done()
		seqBuffer := make([]uint64, 0, seqBufferMaxSize) // Initialize buffer with max size

		// Inner defer to ensure buffer is flushed when this goroutine exits (e.g., channel closed)
		defer func() {
			if len(seqBuffer) > 0 {
				writeSequencesToFile(seqBuffer, seqLogFilename)
				log.Printf("Flushed remaining %d sequences to %s.\n", len(seqBuffer), seqLogFilename)
			}
			log.Printf("Total sequences logged to file: %d\n", totalSequencesLogged) // Print total count
			log.Println("Sequence logging goroutine finished.")
		}()

		for seq := range seqChan {
			seqBuffer = append(seqBuffer, seq)
			if len(seqBuffer) >= seqBufferMaxSize {
				writeSequencesToFile(seqBuffer, seqLogFilename)
				seqBuffer = []uint64{} // Clear buffer
			}
		}
	}()

	// Connect to a server
	nc, _ := nats.Connect(url, nats.ErrorHandler(logSlowConsumer))
	defer nc.Drain()
	log.Println("Connected to NATS server") // Changed from println

	if enableMitigation {
		reorderBufferInstance = NewReorderBuffer()
		reorderSignalChan = make(chan struct{}, 1) // Buffered channel
		go reorderSenderGoroutine(nc, seqChan)
		log.Println("Reorder sender goroutine started for mitigation.")
	}

	lastMessageTime := time.Now()

	// Function to reset the timer
	resetInPktSecTimer := func() {
		lastMessageTime = time.Now()
	}

	// Timer for stopping the program if no message is received from inpktsec
	go func() {
		for {
			time.Sleep(1 * time.Second)
			if time.Since(lastMessageTime) > timeout {
				log.Printf("Timeout: No message received from inpktsec in %s. Closing sequence channel and exiting.\n", timeout)
				close(seqChan) // Signal sequence logger to flush and finish
				wg.Wait()      // Wait for sequence logger to complete its final write
				log.Println("Exiting due to timeout.")
				os.Exit(1) // Exit the program
			}
		}
	}()

	// Simple Subscriber
	nc.Subscribe("inpktsec", func(m *nats.Msg) {
		processEthernetPacket(nc, m.Subject, m.Data, seqChan) // Pass seqChan
		resetInPktSecTimer()                                  // Reset the timer on receiving a message
	})

	// Simple Subscriber
	nc.Subscribe("inpktinsec", func(m *nats.Msg) {
		processEthernetPacket(nc, m.Subject, m.Data, seqChan) // Pass seqChan
	})

	// Keep the connection alive
	select {}

	// Drain connection (Preferred for responders)
	// Close() not needed if this is called.
	// nc.Drain() is deferred in main

	// Close connection
	// nc.Close() // Covered by nc.Drain()
}
