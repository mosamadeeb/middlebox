package main

import (
	"flag"
	"fmt"
	"log"
	"math"
	"math/rand/v2"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/nats-io/nats.go"

	"go-processor/analyzer"
)

// Create a seeded random source for reproducibility
var (
	// random    = rand.New(rand.NewPCG(41, 42))
	random    = rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
	meanDelay float64 // Mean in milliseconds
)

// TODO: check channel buffer size
var packetChan = make(chan analyzer.Packet, 1000)

var csvFilename string

const timeout = 10 * time.Second

// Function to process the ethernet packet
func processEthernetPacket(nc *nats.Conn, iface string, data []byte) {
	// Use gopacket to dissect the packet
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	if packet.ErrorLayer() != nil {
		log.Println("Error decoding some part of the packet:", packet.ErrorLayer().Error())
		return
	}

	go func() {
		// Add a random delay before publishing the packet
		randomValue := meanDelay * random.ExpFloat64()

		// log.Println("Sleeping for:", randomValue, "ms")
		time.Sleep(time.Duration(randomValue) * time.Millisecond)

		if iface == "inpktsec" {
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp := tcpLayer.(*layers.TCP)
				// log.Printf("TCP packet received from sec: Seq: %d\n", tcp.Seq)

				// Add the packet to the analyzer channel
				packetChan <- analyzer.Packet{
					SequenceNumber: uint64(tcp.Seq),
					ArrivalTime:    time.Now(),
				}
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

	// Setup analyzer channel and configuration
	metricsChan := make(chan analyzer.MetricsReport, 100)

	config := analyzer.Config{
		FrameSizeN:            24,                // Calculate RD over frames of N packets
		PermutationFrameSizeK: 3,                 // Analyze permutations of K packets
		ReportInterval:        100 * time.Second, // Report metrics every x seconds if a frame was not completed before that
	}

	// Generate CSV filename
	timestampStr := time.Now().Format("20060102_150405")
	csvFilename = fmt.Sprintf("metrics_delay%.2f_N%d_K%d_%s.csv",
		meanDelay, config.FrameSizeN, config.PermutationFrameSizeK, timestampStr)
	log.Printf("Metrics will be saved to: %s", csvFilename)

	// Pre-generate canonical permutation keys if k > 0 for header consistency
	if config.PermutationFrameSizeK > 0 {
		canonicalPermutationKeys = generateCanonicalPermutationKeys(config.PermutationFrameSizeK)
	}

	reorderAnalyzer := analyzer.NewAnalyzer(config, packetChan, metricsChan)
	go reorderAnalyzer.Start()

	// Goroutine to print metrics from metricsChan and save to CSV
	go func() {
		var reportsBuffer []analyzer.MetricsReport
		const batchSize = 10

		for report := range metricsChan {
			log.Printf("--- Metrics Report at %s ---\n", report.Timestamp.Format(time.RFC3339))
			if len(report.RDHistogram) > 0 {
				log.Printf("  RD Histogram (N=%d): %v\n", config.FrameSizeN, report.RDHistogram)
			} else {
				log.Printf("  RD Histogram (N=%d): No data yet or FrameSizeN is 0.\n", config.FrameSizeN)
			}
			log.Printf("  RBD Current Occupancy: %d\n", report.RBDCurrentOccupancy)
			log.Printf("  RBD Max In Interval: %d\n", report.RBDMaxObservedInInterval)
			if report.TotalPermutations > 0 {
				log.Printf("  Permutation Frequencies (k=%d): %v (Total Perms: %d)\n", config.PermutationFrameSizeK, report.PermutationFrequencies, report.TotalPermutations)
				log.Printf("  Permutation Entropy: %.4f\n", report.PermutationEntropy)
				if config.PermutationFrameSizeK > 0 {
					maxEntropy := math.Log2(float64(analyzer.Factorial(config.PermutationFrameSizeK)))
					log.Printf("    (Max possible entropy for k=%d: %.4f)\n", config.PermutationFrameSizeK, maxEntropy)
				}
			} else {
				log.Printf("  No permutations processed in this interval (or k=0).\n")
			}
			log.Println("------------------------------------")

			reportsBuffer = append(reportsBuffer, report)
			if len(reportsBuffer) >= batchSize {
				writeReportsToCSV(reportsBuffer, csvFilename, config.PermutationFrameSizeK)
				reportsBuffer = []analyzer.MetricsReport{} // Clear buffer
			}
		}
		// Write any remaining reports in the buffer after the channel is closed
		if len(reportsBuffer) > 0 {
			writeReportsToCSV(reportsBuffer, csvFilename, config.PermutationFrameSizeK)
		}
		log.Println("Metrics reporting goroutine finished. CSV saving complete.")

		// Exit the program gracefully
		os.Exit(0)
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
				log.Printf("Timeout: No message received from inpktsec in %s. Exiting.\n", timeout)
				os.Exit(1)
			}
		}
	}()

	// Simple Subscriber
	nc.Subscribe("inpktsec", func(m *nats.Msg) {
		// log.Printf("Received a message: %s\n", string(m.Data))
		// Process the incoming ethernet packet here
		processEthernetPacket(nc, m.Subject, m.Data)
		resetInPktSecTimer() // Reset the timer on receiving a message
	})

	// Simple Subscriber
	nc.Subscribe("inpktinsec", func(m *nats.Msg) {
		// log.Printf("Received a message: %s\n", string(m.Data))
		// Process the incoming ethernet packet here
		processEthernetPacket(nc, m.Subject, m.Data)
	})

	// Keep the connection alive
	select {}

	// Drain connection (Preferred for responders)
	// Close() not needed if this is called.

	// Close connection
	nc.Close()
}
