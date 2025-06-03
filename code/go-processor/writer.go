package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"go-processor/analyzer"
)

var canonicalPermutationKeys []string

// nextPermutation generates the next lexicographical permutation of a slice of integers.
// Returns false if the current permutation is the last one.
func nextPermutation(p []int) bool {
	// Find the largest index k such that p[k] < p[k+1]
	k := -1
	for i := 0; i < len(p)-1; i++ {
		if p[i] < p[i+1] { // Check p[i] < p[i+1]
			// To ensure we find the rightmost such k, we iterate and update
			// This loop structure was finding the leftmost, let's correct.
		}
	}
	// Corrected logic to find k:
	// Find the largest index k such that p[k] < p[k+1]. If no such index exists, the permutation is the last permutation.
	for i := len(p) - 2; i >= 0; i-- {
		if p[i] < p[i+1] {
			k = i
			break
		}
	}
	if k == -1 {
		return false // This is the last permutation
	}

	// Find the largest index l greater than k such that p[k] < p[l].
	l := -1
	for i := len(p) - 1; i > k; i-- {
		if p[k] < p[i] {
			l = i
			break
		}
	}

	// Swap p[k] and p[l]
	p[k], p[l] = p[l], p[k]

	// Reverse the sequence from p[k+1] up to the end of the slice p[k+1:]
	left, right := k+1, len(p)-1
	for left < right {
		p[left], p[right] = p[right], p[left]
		left++
		right--
	}
	return true
}

// generateCanonicalPermutationKeys generates all unique permutation strings for a given k.
// The permutations are of ranks {0, 1, ..., k-1}.
func generateCanonicalPermutationKeys(k int) []string {
	if k <= 0 {
		return []string{}
	}
	if k > 7 { // Factorial grows very fast, limit k for practical CSV columns
		log.Printf("Warning: PermutationFrameSizeK (%d) is large, may result in many CSV columns.", k)
	}

	nums := make([]int, k)
	for i := 0; i < k; i++ {
		nums[i] = i // Initialize with sorted sequence e.g., [0, 1, 2] for k=3
	}

	var permKeys []string
	var sb strings.Builder

	for {
		sb.Reset()
		for i, val := range nums {
			if i > 0 {
				sb.WriteString("-")
			}
			sb.WriteString(strconv.Itoa(val))
		}
		permKeys = append(permKeys, sb.String())
		if !nextPermutation(nums) {
			break
		}
	}
	sort.Strings(permKeys) // Ensure lexicographical order for consistent CSV headers
	return permKeys
}

func getCSVHeader(k int) []string {
	header := []string{"Timestamp", "RBD_Max_In_Interval"}
	// RD Histogram Headers
	for i := -4; i <= 4; i++ {
		header = append(header, fmt.Sprintf("RD_Displacement_%d", i))
	}

	// Permutation Frequencies Headers
	if k > 0 {
		canonicalPermutationKeys = generateCanonicalPermutationKeys(k)
		for _, pKey := range canonicalPermutationKeys {
			header = append(header, fmt.Sprintf("Perm_Freq_%s", pKey))
		}
	}
	header = append(header, "Permutation_Entropy")
	return header
}

func writeReportsToCSV(reports []analyzer.MetricsReport, filename string, k int) {
	if len(reports) == 0 {
		return
	}

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("Error opening CSV file %s: %v", filename, err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	fileInfo, err := file.Stat()
	if err != nil {
		log.Printf("Error getting file info for %s: %v", filename, err)
		return
	}

	// Write header only if file is new/empty
	if fileInfo.Size() == 0 {
		header := getCSVHeader(k)
		if err := writer.Write(header); err != nil {
			log.Printf("Error writing CSV header to %s: %v", filename, err)
			return
		}
	}

	// Write data rows
	for _, report := range reports {
		row := []string{
			report.Timestamp.Format(time.RFC3339Nano),
			strconv.Itoa(report.RBDMaxObservedInInterval),
		}
		// RD Histogram Data
		for i := -4; i <= 4; i++ {
			count, ok := report.RDHistogram[i]
			if !ok {
				count = 0
			}
			row = append(row, strconv.Itoa(count))
		}
		// Permutation Frequencies Data
		if k > 0 {
			if len(canonicalPermutationKeys) == 0 { // Should be populated by getCSVHeader if k > 0
				canonicalPermutationKeys = generateCanonicalPermutationKeys(k)
			}
			for _, pKey := range canonicalPermutationKeys {
				count, ok := report.PermutationFrequencies[pKey]
				if !ok {
					count = 0
				}
				row = append(row, strconv.Itoa(count))
			}
		}
		row = append(row, fmt.Sprintf("%.6f", report.PermutationEntropy))

		if err := writer.Write(row); err != nil {
			log.Printf("Error writing CSV row to %s: %v", filename, err)
		}
	}
	log.Printf("Successfully wrote %d reports to CSV: %s", len(reports), filename)
}
