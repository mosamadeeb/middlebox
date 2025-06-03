package analyzer

import "time"

// Packet represents a network packet with a sequence number.
type Packet struct {
	SequenceNumber uint64
	ArrivalTime    time.Time // Time when packet was "received" by the analyzer
}

// Packets is a slice of Packet, for sorting by SequenceNumber.
type Packets []Packet

func (p Packets) Len() int           { return len(p) }
func (p Packets) Less(i, j int) bool { return p[i].SequenceNumber < p[j].SequenceNumber }
func (p Packets) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
