package detector

import (
	"log"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

const reorderBufferCapacity = 10 // Max packets in reorder buffer before flush

// ReorderBuffer holds packets to be sent in order
type ReorderBuffer struct {
	packets    map[uint32][]byte // Map sequence number to packet data
	sortedSeqs []uint32          // Slice of unique sequence numbers, kept sorted
	mu         sync.Mutex
}

// NewReorderBuffer creates a new ReorderBuffer
func NewReorderBuffer() *ReorderBuffer {
	return &ReorderBuffer{
		packets:    make(map[uint32][]byte),
		sortedSeqs: make([]uint32, 0),
	}
}

// AddPacket adds a packet to the reorder buffer
func (rb *ReorderBuffer) AddPacket(seq uint32, data []byte) bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if _, exists := rb.packets[seq]; exists {
		log.Printf("Mitigation: Packet with SEQ %d already in buffer, ignoring duplicate.\n", seq)
		return false // Indicate duplicate
	}

	rb.packets[seq] = data
	rb.sortedSeqs = append(rb.sortedSeqs, seq)
	slices.Sort(rb.sortedSeqs)
	return true // Indicate success
}

// Mitigator handles the covert channel mitigation logic.
type Mitigator struct {
	buffer          *ReorderBuffer
	signalChan      chan struct{}
	nextExpectedSeq uint32
	nc              *nats.Conn
	seqChan         chan<- uint64
	delay           float64
	meanJitter      float64
	random          *rand.Rand
	wg              *sync.WaitGroup
}

// NewMitigator creates and starts a new Mitigator.
func NewMitigator(nc *nats.Conn, seqChan chan<- uint64, initialNextSeq uint32, delay, meanJitter float64, wg *sync.WaitGroup) *Mitigator {
	m := &Mitigator{
		buffer:          NewReorderBuffer(),
		signalChan:      make(chan struct{}, 1), // Buffered channel
		nextExpectedSeq: initialNextSeq,
		nc:              nc,
		seqChan:         seqChan,
		delay:           delay,
		meanJitter:      meanJitter,
		random:          rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64())), // Own random source
		wg:              wg,
	}
	m.wg.Add(1)
	go m.senderGoroutine()
	log.Println("Mitigator sender goroutine started.")
	return m
}

// AddPacketToReorderBuffer adds a packet to the mitigation buffer and signals the sender.
func (m *Mitigator) AddPacketToReorderBuffer(seq uint32, data []byte) {
	if m.buffer.AddPacket(seq, data) {
		// Signal sender that a new packet is available or buffer state changed
		select {
		case m.signalChan <- struct{}{}:
		default: // Channel is full, sender is busy or will pick it up
		}
	}
}

// senderGoroutine sends packets from the ReorderBuffer in sequence order.
func (m *Mitigator) senderGoroutine() {
	defer m.wg.Done()
	for {
		_, ok := <-m.signalChan // Wait for a signal that new data might be ready
		if !ok {
			log.Println("Mitigator signal channel closed, sender goroutine exiting.")
			return // Exit if channel is closed
		}

	senderLoop:
		for { // This loop attempts to send packets as long as conditions are met
			m.buffer.mu.Lock()

			// Condition 1: Buffer capacity reached - flush all sorted packets
			if len(m.buffer.packets) >= reorderBufferCapacity && len(m.buffer.sortedSeqs) > 0 {
				log.Printf("Mitigation: Reorder buffer capacity (%d) reached. Flushing %d packets.", reorderBufferCapacity, len(m.buffer.sortedSeqs))
				highestSentInFlush := m.nextExpectedSeq - 1

				for len(m.buffer.sortedSeqs) > 0 {
					seqToFlush := m.buffer.sortedSeqs[0]
					dataToFlush := m.buffer.packets[seqToFlush]

					delete(m.buffer.packets, seqToFlush)
					m.buffer.sortedSeqs = m.buffer.sortedSeqs[1:]
					m.buffer.mu.Unlock()

					log.Printf("Mitigation (Flush): Sending SEQ %d from reorder buffer.", seqToFlush)
					randomJitterVal := m.meanJitter * m.random.ExpFloat64()
					time.Sleep(time.Duration(m.delay+randomJitterVal) * time.Millisecond)
					err := m.nc.Publish("outpktinsec", dataToFlush)
					if err != nil {
						log.Printf("Mitigation (Flush): Error publishing message for SEQ %d: %v", seqToFlush, err)
					}
					m.seqChan <- uint64(seqToFlush)
					if seqToFlush > highestSentInFlush {
						highestSentInFlush = seqToFlush
					}
					m.buffer.mu.Lock()
				}
				if highestSentInFlush >= (m.nextExpectedSeq-1) && len(m.buffer.packets) == 0 {
					m.nextExpectedSeq = highestSentInFlush + 1
				} else if highestSentInFlush >= (m.nextExpectedSeq-1) && len(m.buffer.packets) > 0 {
					m.nextExpectedSeq = highestSentInFlush + 1
				}
				log.Printf("Mitigation: Buffer flushed. Next expected SEQ is now %d.", m.nextExpectedSeq)
				m.buffer.mu.Unlock()
				break senderLoop
			}

			// Condition 2: Send nextExpectedSeq if available
			dataToSend, exists := m.buffer.packets[m.nextExpectedSeq]
			if exists {
				delete(m.buffer.packets, m.nextExpectedSeq)
				foundIndex := -1
				for i, s := range m.buffer.sortedSeqs {
					if s == m.nextExpectedSeq {
						foundIndex = i
						break
					}
				}
				if foundIndex != -1 {
					m.buffer.sortedSeqs = append(m.buffer.sortedSeqs[:foundIndex], m.buffer.sortedSeqs[foundIndex+1:]...)
				} else {
					log.Printf("Mitigation Error: SEQ %d in packets map but not in sortedSeqs. Inconsistency.", m.nextExpectedSeq)
				}
				m.buffer.mu.Unlock()

				log.Printf("Mitigation: Sending expected SEQ %d from reorder buffer.", m.nextExpectedSeq)
				randomJitterVal := m.meanJitter * m.random.ExpFloat64()
				time.Sleep(time.Duration(m.delay+randomJitterVal) * time.Millisecond)
				err := m.nc.Publish("outpktinsec", dataToSend)
				if err != nil {
					log.Printf("Mitigation: Error publishing message for SEQ %d: %v", m.nextExpectedSeq, err)
				}
				m.seqChan <- uint64(m.nextExpectedSeq)
				m.nextExpectedSeq++
				continue senderLoop
			}

			m.buffer.mu.Unlock()
			break senderLoop
		}
	}
}

// Close shuts down the mitigator, primarily by closing the signal channel.
func (m *Mitigator) Close() {
	// Note: Closing signalChan will cause senderGoroutine to exit.
	// Ensure buffer is flushed if needed, though current logic relies on capacity or sequence.
	// For a graceful shutdown, one might want to add a flush mechanism here.
	log.Println("Closing Mitigator signal channel.")
	close(m.signalChan)
}
