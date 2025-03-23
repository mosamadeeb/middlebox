package main

import (
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/nats-io/nats.go"
)

// Create a seeded random source for reproducibility
var random = rand.New(rand.NewPCG(41, 42))
var meanDelay float64 // Mean in milliseconds

// Function to process the ethernet packet
func processEthernetPacket(nc *nats.Conn, iface string, data []byte) {
	// Add your ethernet packet processing logic here
	fmt.Printf("Processing ethernet packet: %s\n", iface)

	// Use gopacket to dissect the packet
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	if packet.ErrorLayer() != nil {
		fmt.Println("Error decoding some part of the packet:", packet.ErrorLayer().Error())
		return
	}
	// Check for Ethernet layer
	if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
		fmt.Println("Ethernet layer detected.")
		fmt.Println(gopacket.LayerDump(ethernetLayer))
	}

	// Check for IP layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		fmt.Println("IPv4 layer detected.")
		fmt.Println(gopacket.LayerDump(ipLayer))
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		fmt.Println("IPv6 layer detected.")
		fmt.Println(gopacket.LayerDump(ipLayer))
	}

	// Check for TCP layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		fmt.Println("TCP layer detected.")
		fmt.Println(gopacket.LayerDump(tcpLayer))
	}

	// Check for UDP layer
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		fmt.Println("UDP layer detected.")
		fmt.Println(gopacket.LayerDump(udpLayer))
	}

	// Add a random delay before publishing the packet
	randomValue := meanDelay * random.ExpFloat64()

	fmt.Println("Sleeping for:", randomValue, "ms")
	time.Sleep(time.Duration(randomValue) * time.Millisecond)

	// Publish the processed packet to the appropriate subject
	var subject string
	if iface == "inpktsec" {
		subject = "outpktinsec"
	} else {
		subject = "outpktsec"
	}
	err := nc.Publish(subject, data)
	if err != nil {
		fmt.Println("Error publishing message:", err)
	}
}

func main() {
	fmt.Println("Hello, World!")
	url := os.Getenv("NATS_SURVEYOR_SERVERS")
	if url == "" {
		url = nats.DefaultURL
	}
	fmt.Println("NATS_SURVEYOR_SERVERS: ", url)

	// Set up command-line flags
	flag.Float64Var(&meanDelay, "mean", 1.0, "Mean delay in milliseconds for exponential distribution")
	flag.Parse()

	fmt.Printf("Using mean delay of %.5f milliseconds\n", meanDelay)

	// Connect to a server
	nc, _ := nats.Connect(url)
	defer nc.Drain()
	// Simple Publisher
	// nc.Publish("foo", []byte("Hello World"))

	println("Connected to NATS server")

	// Simple Subscriber
	nc.Subscribe("inpktsec", func(m *nats.Msg) {
		// fmt.Printf("Received a message: %s\n", string(m.Data))
		// Process the incoming ethernet packet here
		processEthernetPacket(nc, m.Subject, m.Data)
	})

	// Simple Subscriber
	nc.Subscribe("inpktinsec", func(m *nats.Msg) {
		// fmt.Printf("Received a message: %s\n", string(m.Data))
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
