package main

import (
	"flag"
	"log"
	"math/rand/v2"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/nats-io/nats.go"

	// Import the detector package
	"go-processor/detector"
)

// Create a seeded random source for reproducibility
var (
	random           = rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
	delay            float64 // Delay in milliseconds
	meanJitter       float64 // Jitter mean in milliseconds
	enableMitigation bool    // Enable covert channel mitigation

	mitigatorInstance *detector.Mitigator // Instance of the new Mitigator

	// RD Calculator related variables
	rdCalculatorInstance  *detector.RDCalculator
	rdOutputChan          chan map[int]float64
	rdFrameSize           int
	displacementThreshold int
	enableRDAnalysis      bool

	// LogWriter instance
	logWriter *LogWriter
)

const (
	// seqBufferMaxSize = 1000 // Moved to writer.go (as defaultSeqBufferMaxSize)
	timeout = 10 * time.Second
)

// Function to process the ethernet packet
func processEthernetPacket(nc *nats.Conn, iface string, data []byte, seqChan chan<- uint64) { // seqChan is for logging/RD
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

	if enableMitigation && iface == "inpktsec" && tcp != nil && mitigatorInstance != nil {
		// Create a copy of data, as the original slice might be reused by NATS or gopacket
		dataCopy := make([]byte, len(data))
		copy(dataCopy, data)
		log.Printf("Mitigation: Buffering SEQ %d\n", tcp.Seq)
		// Mitigator will send the sequence number to its configured seqChan (which is the main seqChan)
		// after processing and sending the packet.
		mitigatorInstance.AddPacketToReorderBuffer(tcp.Seq, dataCopy)
	} else {
		// Original behavior for non-mitigation or non-"inpktsec" packets (e.g., from "inpktinsec")
		go func() {
			// Add a random delay before publishing the packet
			randomJitterVal := meanJitter * random.ExpFloat64() // Uses global random from main
			time.Sleep(time.Duration(delay+randomJitterVal) * time.Millisecond)

			if iface == "inpktsec" && tcp != nil { // This branch now only active if !enableMitigation
				log.Printf("Sequence arrived (no mitigation): %d\n", tcp.Seq) // Log sequence number as it arrives
				seqChan <- uint64(tcp.Seq)                                    // Send to central seqChan for logging/RD
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

	initialNextExpectedMitigationSeq := uint32(1001) // Default for mitigator

	// Set up command-line flags
	flag.Float64Var(&delay, "delay", 20.0, "Fixed delay to add in milliseconds")
	flag.Float64Var(&meanJitter, "jitter", 1.0, "Mean jitter in milliseconds for exponential distribution")
	flag.BoolVar(&enableMitigation, "mitigate", false, "Enable covert channel mitigation")
	flag.BoolVar(&enableRDAnalysis, "rdanalysis", false, "Enable Reorder Density analysis")
	flag.IntVar(&rdFrameSize, "rdframesize", detector.DefaultRDFrameSize, "Frame size for Reorder Density analysis")
	flag.IntVar(&displacementThreshold, "rdthreshold", detector.DefaultDisplacementThreshold, "Displacement threshold (DT) for Reorder Density analysis")
	flag.Parse()

	log.Printf("Using mean jitter of %.5f milliseconds\n", meanJitter)
	if enableMitigation {
		log.Println("Covert channel mitigation IS ENABLED.")
	} else {
		log.Println("Covert channel mitigation IS DISABLED.")
	}

	if enableRDAnalysis {
		log.Printf("Reorder Density analysis IS ENABLED. Frame size: %d, DT: %d\n", rdFrameSize, displacementThreshold)
	} else {
		log.Println("Reorder Density analysis IS DISABLED.")
	}

	// Setup sequence channel (central channel for sequences to be logged or analyzed by RD)
	// Both mitigated and non-mitigated paths will send sequence numbers to this channel.
	seqChan := make(chan uint64, 10000) // Channel buffer for sequence numbers

	var wg sync.WaitGroup // WaitGroup for goroutines

	// Initialize LogWriter
	timestampStr := time.Now().Format("20060102_150405")
	logWriter = NewLogWriter(meanJitter, rdFrameSize, displacementThreshold, enableRDAnalysis, timestampStr, &wg)

	// Goroutine to process sequences from seqChan (for logging and RD analysis)
	wg.Add(1)
	go func() {
		defer wg.Done()
		// seqBuffer logic moved to LogWriter

		defer func() { // Ensure final flush and RD close on exit
			logWriter.FlushSequenceBuffer() // Flushes sequence log
			log.Println("Sequence processing goroutine finished.")
			if enableRDAnalysis && rdCalculatorInstance != nil {
				log.Println("Closing RDCalculator from sequence processing goroutine.")
				rdCalculatorInstance.Close() // Close RD calculator after all sequences are processed
			}
		}()

		for seq := range seqChan { // This channel is closed by the timeout goroutine
			logWriter.AddSequenceToBuffer(seq)
			if enableRDAnalysis && rdCalculatorInstance != nil {
				rdCalculatorInstance.AddPacket(seq)
			}
		}
	}()

	// Connect to a server
	nc, _ := nats.Connect(url, nats.ErrorHandler(logSlowConsumer))
	defer nc.Drain()
	log.Println("Connected to NATS server")

	if enableMitigation {
		// The Mitigator will also send its output sequence numbers to the same seqChan
		mitigatorInstance = detector.NewMitigator(nc, seqChan, initialNextExpectedMitigationSeq, delay, meanJitter, &wg)
	}

	// Initialize RD Calculator if enabled
	if enableRDAnalysis {
		rdOutputChan = make(chan map[int]float64, 100) // Buffered channel for RD results
		rdCalculatorInstance = detector.NewRDCalculator(displacementThreshold, rdFrameSize, rdOutputChan, log.Printf)
		log.Println("RD Calculator initialized.")

		// Goroutine to process RD results
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Println("RD results processing goroutine started.")
			var frameCounter uint64 = 0
			for rdMap := range rdOutputChan { // This channel is closed by RDCalculator.Close()
				frameCounter++
				log.Printf("Frame %d - Reorder Density (RD) map: %v", frameCounter, rdMap)

				detected := false
				if earlyOrLate, exists := rdMap[-1]; exists && earlyOrLate > 0.15 {
					log.Printf("Frame %d - DETECTION: Potential covert channel - high proportion (%.2f%%) of packets arrived 1 position early (D=-1).", frameCounter, earlyOrLate*100)
					detected = true
				}
				if earlyOrLate, exists := rdMap[1]; exists && earlyOrLate > 0.15 {
					log.Printf("Frame %d - DETECTION: Potential covert channel - high proportion (%.2f%%) of packets arrived 1 position late (D=1).", frameCounter, earlyOrLate*100)
					detected = true
				}
				if rdZero, exists := rdMap[0]; exists && rdZero < 1.0 {
					if rdZero < 0.6 {
						log.Printf("Frame %d - DETECTION: High reordering detected (RD[0] = %.3f). This may indicate a covert channel.", frameCounter, rdZero)
						detected = true
					} else {
						log.Printf("Frame %d - INFO: Reordering detected in frame. RD[0] = %.3f", frameCounter, rdZero)
					}
				} else if !exists && len(rdMap) > 0 {
					log.Printf("Frame %d - INFO: Reordering detected in frame (no packets in order).", frameCounter)
					if len(rdMap) > 0 { // Check to ensure rdMap is not empty
						detected = true
						log.Printf("Frame %d - DETECTION: Significant reordering (RD[0] is absent, other displacements present).", frameCounter)
					}
				}

				// Store result using LogWriter
				result := DetectionResult{ // This is main.DetectionResult type from writer.go
					FrameNumber:           frameCounter,
					DetectedCovertChannel: detected,
					RD_neg3:               rdMap[-3],
					RD_neg2:               rdMap[-2],
					RD_neg1:               rdMap[-1],
					RD_0:                  rdMap[0],
					RD_pos1:               rdMap[1],
					RD_pos2:               rdMap[2],
					RD_pos3:               rdMap[3],
				}
				logWriter.AddDetectionResult(result)
			}
			log.Println("RD results processing goroutine finished.")
		}()
	}

	lastMessageTime := time.Now()

	resetInPktSecTimer := func() {
		lastMessageTime = time.Now()
	}

	// Timer for stopping the program if no message is received from inpktsec
	go func() {
		for {
			time.Sleep(1 * time.Second)
			if time.Since(lastMessageTime) > timeout {
				log.Printf("Timeout: No message received from inpktsec in %s. Initiating shutdown.\n", timeout)

				if enableMitigation && mitigatorInstance != nil {
					log.Println("Closing mitigator...")
					mitigatorInstance.Close() // This will signal its senderGoroutine to exit, which then calls wg.Done()
				}

				log.Println("Closing sequence channel (seqChan)...")
				close(seqChan) // Signals sequence processing goroutine (logger & RD input) to finish

				log.Println("Waiting for all goroutines to complete...")
				wg.Wait() // Waits for:
				// 1. sequence processing goroutine (which also closes RDCalculator)
				// 2. RD results processing goroutine (if enabled)
				// 3. mitigator sender goroutine (if enabled)

				// Sequence logs are flushed by the sequence processing goroutine's defer (via logWriter.FlushSequenceBuffer)
				// RD results are written by LogWriter if RD analysis was enabled
				if enableRDAnalysis {
					log.Println("Writing detection results...")
					logWriter.WriteDetectionResultsToFile() // Writes detection results CSV
				}

				log.Println("All goroutines completed. Exiting due to timeout.")
				os.Exit(1)
			}
		}
	}()

	nc.Subscribe("inpktsec", func(m *nats.Msg) {
		processEthernetPacket(nc, m.Subject, m.Data, seqChan)
		resetInPktSecTimer()
	})

	nc.Subscribe("inpktinsec", func(m *nats.Msg) {
		processEthernetPacket(nc, m.Subject, m.Data, seqChan)
	})

	select {} // Keep the main goroutine alive until os.Exit is called
}
