package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
)

// DetectionResult holds the analysis outcome for a single frame
type DetectionResult struct {
	FrameNumber           uint64
	DetectedCovertChannel bool
	RD_neg3               float64
	RD_neg2               float64
	RD_neg1               float64
	RD_0                  float64
	RD_pos1               float64
	RD_pos2               float64
	RD_pos3               float64
}

const (
	defaultSeqBufferMaxSize = 1000 // Buffer size for batching sequence writes
)

// LogWriter handles writing sequence logs and detection results to files.
type LogWriter struct {
	seqLogFilename        string
	detectionLogFilename  string
	totalSequencesLogged  uint64
	seqBuffer             []uint64
	seqBufferMaxSize      int
	detectionResults      []DetectionResult
	detectionResultsMutex sync.Mutex
	wg                    *sync.WaitGroup // To wait for async writes if any, or just for consistency
}

// NewLogWriter creates and initializes a new LogWriter.
func NewLogWriter(meanJitter float64, rdFrameSize int, displacementThreshold int, enableRDAnalysis bool, timestampStr string, wg *sync.WaitGroup) *LogWriter {
	lw := &LogWriter{
		seqBufferMaxSize: defaultSeqBufferMaxSize,
		seqBuffer:        make([]uint64, 0, defaultSeqBufferMaxSize),
		detectionResults: make([]DetectionResult, 0),
		wg:               wg,
	}

	lw.seqLogFilename = fmt.Sprintf("sequence_log_jitter%.2f_%s.txt", meanJitter, timestampStr)
	log.Printf("Sequence numbers will be saved to: %s", lw.seqLogFilename)

	if enableRDAnalysis {
		lw.detectionLogFilename = fmt.Sprintf("detection_results_jitter%.2f_frame%d_dt%d_%s.csv",
			meanJitter, rdFrameSize, displacementThreshold, timestampStr)
		log.Printf("Detection results will be saved to: %s", lw.detectionLogFilename)
	}
	return lw
}

// AddSequenceToBuffer adds a sequence to the buffer and writes to file if buffer is full.
func (lw *LogWriter) AddSequenceToBuffer(seq uint64) {
	lw.seqBuffer = append(lw.seqBuffer, seq)
	if len(lw.seqBuffer) >= lw.seqBufferMaxSize {
		lw.writeSequencesToFileInternal()
		lw.seqBuffer = make([]uint64, 0, lw.seqBufferMaxSize) // Clear buffer
	}
}

// writeSequencesToFileInternal writes the current sequence buffer to its log file.
func (lw *LogWriter) writeSequencesToFileInternal() {
	if len(lw.seqBuffer) == 0 {
		return
	}

	f, err := os.OpenFile(lw.seqLogFilename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("Error opening sequence log file %s: %v\n", lw.seqLogFilename, err)
		return
	}
	defer f.Close()

	var b strings.Builder
	for _, seq := range lw.seqBuffer {
		b.WriteString(strconv.FormatUint(seq, 10) + " ")
	}

	if _, err := f.WriteString(b.String()); err != nil {
		log.Printf("Error writing sequences to file %s: %v\n", lw.seqLogFilename, err)
		return // Don't count if write fails
	}
	lw.totalSequencesLogged += uint64(len(lw.seqBuffer)) // Increment counter
}

// FlushSequenceBuffer writes any remaining sequences in the buffer to file.
func (lw *LogWriter) FlushSequenceBuffer() {
	if len(lw.seqBuffer) > 0 {
		lw.writeSequencesToFileInternal()
		log.Printf("Flushed remaining %d sequences to %s.\n", len(lw.seqBuffer), lw.seqLogFilename)
		lw.seqBuffer = make([]uint64, 0, lw.seqBufferMaxSize) // Clear buffer
	}
	log.Printf("Total sequences logged to file: %d\n", lw.totalSequencesLogged)
}

// AddDetectionResult adds a detection result to the internal slice.
func (lw *LogWriter) AddDetectionResult(result DetectionResult) {
	lw.detectionResultsMutex.Lock()
	defer lw.detectionResultsMutex.Unlock()
	lw.detectionResults = append(lw.detectionResults, result)
}

// WriteDetectionResultsToFile writes all collected detection results to a CSV file.
func (lw *LogWriter) WriteDetectionResultsToFile() {
	lw.detectionResultsMutex.Lock()
	defer lw.detectionResultsMutex.Unlock()

	if lw.detectionLogFilename == "" {
		log.Println("Detection log filename not set, skipping writing detection results.")
		return
	}
	if len(lw.detectionResults) == 0 {
		log.Println("No detection results to write.")
		return
	}

	file, err := os.Create(lw.detectionLogFilename)
	if err != nil {
		log.Printf("Error creating detection log file %s: %v\n", lw.detectionLogFilename, err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"FrameNumber", "DetectedCovertChannel",
		"RD_neg3", "RD_neg2", "RD_neg1", "RD_0", "RD_pos1", "RD_pos2", "RD_pos3",
	}
	if err := writer.Write(header); err != nil {
		log.Printf("Error writing header to detection log file %s: %v\n", lw.detectionLogFilename, err)
		return
	}

	for _, res := range lw.detectionResults {
		detectedStr := "0"
		if res.DetectedCovertChannel {
			detectedStr = "1"
		}
		record := []string{
			strconv.FormatUint(res.FrameNumber, 10),
			detectedStr,
			fmt.Sprintf("%.5f", res.RD_neg3),
			fmt.Sprintf("%.5f", res.RD_neg2),
			fmt.Sprintf("%.5f", res.RD_neg1),
			fmt.Sprintf("%.5f", res.RD_0),
			fmt.Sprintf("%.5f", res.RD_pos1),
			fmt.Sprintf("%.5f", res.RD_pos2),
			fmt.Sprintf("%.5f", res.RD_pos3),
		}
		if err := writer.Write(record); err != nil {
			log.Printf("Error writing record to detection log file %s: %v\n", lw.detectionLogFilename, err)
		}
	}
	log.Printf("Successfully wrote %d detection results to %s\n", len(lw.detectionResults), lw.detectionLogFilename)
}
