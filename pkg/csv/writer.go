package csv

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"sort"

	"github.com/stackrox/rox/pkg/sliceutils"
)

// Header represents a CSV's header line.
type Header []string

// Value represents a CSV's value (non-header row).
type Value []string

// Writer is the interface for something that writes to CSV files.
type Writer interface {
	AddValue(value Value)
	Write(w http.ResponseWriter, filename string)
}

// GenericWriter is a generic CSV Writer.
type GenericWriter struct {
	header Header
	values []Value
}

// NewGenericWriter creates a new CSV Writer using the given header.
func NewGenericWriter(header Header) *GenericWriter {
	return &GenericWriter{header: header}
}

// AddValue adds a CSV value (row) to the CSV file.
func (c *GenericWriter) AddValue(value Value) {
	c.values = append(c.values, value)
}

// Write writes back the CSV file contents into the http.ResponseWriter.
func (c *GenericWriter) Write(w http.ResponseWriter, filename string) {
	w.Header().Set("Content-Type", `text/csv; charset="utf-8"`)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, filename))
	w.WriteHeader(http.StatusOK)

	sort.Slice(c.values, func(i, j int) bool {
		first, second := c.values[i], c.values[j]
		for len(first) > 0 {
			// first has more values, so greater
			if len(second) == 0 {
				return false
			}
			if first[0] < second[0] {
				return true
			}
			if first[0] > second[0] {
				return false
			}
			first = first[1:]
			second = second[1:]
		}
		// second has more values, so first is lesser
		return len(second) > 0
	})

	header := sliceutils.StringClone(c.header)
	header[0] = "\uFEFF" + header[0]
	cw := csv.NewWriter(w)
	cw.UseCRLF = true
	_ = cw.Write(header)
	for _, v := range c.values {
		_ = cw.Write(v)
	}
	cw.Flush()
}
