package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"os"
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
	random               = rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
	meanDelay            float64 // Mean in milliseconds
	totalSequencesLogged uint64  // Counter for logged sequences
)

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

// Function to process the ethernet packet
func processEthernetPacket(nc *nats.Conn, iface string, data []byte, seqChan chan<- uint64) { // Added seqChan parameter
	// Use gopacket to dissect the packet
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	if packet.ErrorLayer() != nil {
		log.Println("Error decoding some part of the packet:", packet.ErrorLayer().Error())
		return
	}

	go func() {
		// Add a random delay before publishing the packet
		randomValue := meanDelay * random.ExpFloat64()
		time.Sleep(time.Duration(randomValue) * time.Millisecond)

		if iface == "inpktsec" {
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp := tcpLayer.(*layers.TCP)
				log.Printf("Sequence arrived: %d\n", tcp.Seq) // Log sequence number as it arrives

				// Send the sequence number to the analyzer channel
				seqChan <- uint64(tcp.Seq)
			}
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

func main() {
	log.Println("Hello, World!")
	url := os.Getenv("NATS_SURVEYOR_SERVERS")
	if url == "" {
		url = nats.DefaultURL
	}
	log.Println("NATS_SURVEYOR_SERVERS: ", url)

	// Set up command-line flags
	flag.Float64Var(&meanDelay, "mean", 1.0, "Mean delay in milliseconds for exponential distribution")
	flag.Parse()

	log.Printf("Using mean delay of %.5f milliseconds\n", meanDelay)

	// Setup sequence channel
	seqChan := make(chan uint64, 10000) // Channel buffer for sequence numbers

	// Generate sequence log filename
	timestampStr := time.Now().Format("20060102_150405")
	seqLogFilename = fmt.Sprintf("sequence_log_delay%.2f_%s.txt",
		meanDelay, timestampStr)
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
	nc, _ := nats.Connect(url)
	defer nc.Drain()
	// Simple Publisher
	// nc.Publish("foo", []byte("Hello World"))

	println("Connected to NATS server")

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

	// Close connection
	nc.Close()
}
