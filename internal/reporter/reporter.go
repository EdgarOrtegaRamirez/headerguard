package reporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/EdgarOrtegaRamirez/headerguard/internal/models"
)

// Reporter writes scan results in a specific format.
type Reporter struct {
	Writer io.Writer
}

// NewReporter creates a new Reporter writing to the given writer.
func NewReporter(w io.Writer) *Reporter {
	return &Reporter{Writer: w}
}

// Text writes results in human-readable text format.
func (r *Reporter) Text(results []*models.ScanResult) error {
	for i, res := range results {
		if i > 0 {
			fmt.Fprintln(r.Writer)
		}
		r.printResult(res)
	}
	return nil
}

func (r *Reporter) printResult(res *models.ScanResult) {
	fmt.Fprintf(r.Writer, "\n%s\n", strings.Repeat("=", 60))
	fmt.Fprintf(r.Writer, "URL: %s\n", res.URL)
	fmt.Fprintf(r.Writer, "Status: %d | Score: %d/%d | Grade: %s\n",
		res.StatusCode, res.Score, res.MaxScore, res.Grade)

	if len(res.CriticalMissing) > 0 {
		fmt.Fprintf(r.Writer, "⚠ Critical headers missing: %s\n",
			strings.Join(res.CriticalMissing, ", "))
	}

	fmt.Fprintf(r.Writer, "%s\n", strings.Repeat("-", 60))
	fmt.Fprintf(r.Writer, "%-40s %5s  %s\n", "Header", "Score", "Value")
	fmt.Fprintf(r.Writer, "%s\n", strings.Repeat("-", 60))

	for _, result := range res.Results {
		status := "✓"
		if !result.Found {
			status = "✗"
		}
		if result.Forbidden && result.Found {
			status = "!"
		}

		value := ""
		if result.Present {
			value = result.Value
			if len(value) > 50 {
				value = value[:47] + "..."
			}
		}

		fmt.Fprintf(r.Writer, "%s %-35s %4d/  %s\n",
			status, result.Name, result.Weight, value)
	}
}

// JSON writes results in JSON format.
func (r *Reporter) JSON(results []*models.ScanResult) error {
	encoder := json.NewEncoder(r.Writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

// CSV writes results in CSV format.
func (r *Reporter) CSV(results []*models.ScanResult) error {
	w := csv.NewWriter(r.Writer)
	defer w.Flush()

	// Header row
	w.Write([]string{"URL", "Status", "Score", "MaxScore", "Grade", "CriticalMissing"})

	for _, res := range results {
		criticalMissing := strings.Join(res.CriticalMissing, ";")
		w.Write([]string{
			res.URL,
			fmt.Sprintf("%d", res.StatusCode),
			fmt.Sprintf("%d", res.Score),
			fmt.Sprintf("%d", res.MaxScore),
			res.Grade,
			criticalMissing,
		})
	}

	return nil
}

// PrintHeader prints the tool header.
func PrintHeader() {
	fmt.Fprintln(os.Stdout,
		"  ╔═══════════════════════════════════════════════╗",
		"  ║  HeaderGuard — HTTP Security Headers Analyzer ║",
		"  ║  Check 15+ security headers in seconds        ║",
		"  ╚═══════════════════════════════════════════════╝",
	)
}
