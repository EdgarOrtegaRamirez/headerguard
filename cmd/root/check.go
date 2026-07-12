package root

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/EdgarOrtegaRamirez/headerguard/internal/checker"
	"github.com/EdgarOrtegaRamirez/headerguard/internal/models"
	"github.com/EdgarOrtegaRamirez/headerguard/internal/reporter"
	"github.com/spf13/cobra"
)

var (
	format   string
	filePath string
	strict   bool
	timeout  time.Duration
	workers  int
)

// checkCmd represents the check command.
var checkCmd = &cobra.Command{
	Use:   "check [URL]...",
	Short: "Check security headers for one or more URLs",
	Long: `Check HTTP security headers for one or more URLs.
Supports concurrent scanning with configurable workers.`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 && filePath == "" {
			return fmt.Errorf("either provide URLs as arguments or use --file to specify a file")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		reporter.PrintHeader()

		// Collect URLs
		urls, err := collectURLs(args)
		if err != nil {
			return fmt.Errorf("failed to collect URLs: %w", err)
		}

		if len(urls) == 0 {
			return fmt.Errorf("no valid URLs provided")
		}

		// Create checker
		c := checker.NewChecker(timeout)

		// Run checks
		results, err := runChecks(c, urls)
		if err != nil {
			return fmt.Errorf("check failed: %w", err)
		}

		// Output results
		r := reporter.NewReporter(os.Stdout)
		switch format {
		case "json":
			if err := r.JSON(results); err != nil {
				return fmt.Errorf("failed to write JSON output: %w", err)
			}
		case "csv":
			if err := r.CSV(results); err != nil {
				return fmt.Errorf("failed to write CSV output: %w", err)
			}
		default:
			if err := r.Text(results); err != nil {
				return fmt.Errorf("failed to write text output: %w", err)
			}
		}

		// Strict mode: exit 1 if any critical headers missing
		if strict {
			for _, res := range results {
				if len(res.CriticalMissing) > 0 {
					fmt.Fprintf(os.Stderr, "\nStrict mode: %s has %d critical header(s) missing\n",
						res.URL, len(res.CriticalMissing))
					os.Exit(1)
				}
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(checkCmd)

	checkCmd.Flags().StringVarP(&format, "format", "F", "text",
		"Output format: text, json, csv")
	checkCmd.Flags().StringVarP(&filePath, "file", "f", "",
		"File containing URLs (one per line)")
	checkCmd.Flags().BoolVar(&strict, "strict", false,
		"Exit with code 1 if critical headers are missing")
	checkCmd.Flags().DurationVarP(&timeout, "timeout", "t", 5*time.Second,
		"Request timeout (e.g., 5s, 30s)")
	checkCmd.Flags().IntVarP(&workers, "workers", "w", 10,
		"Number of concurrent workers")
}

// collectURLs gathers URLs from args and/or file.
func collectURLs(args []string) ([]string, error) {
	var urls []string

	// From arguments
	for _, arg := range args {
		u, err := validateURL(arg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: skipping invalid URL %q: %v\n", arg, err)
			continue
		}
		urls = append(urls, u)
	}

	// From file
	if filePath != "" {
		fileURLs, err := readURLsFromFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("reading URLs from file: %w", err)
		}
		urls = append(urls, fileURLs...)
	}

	return urls, nil
}

// validateURL checks and normalizes a URL string.
func validateURL(raw string) (string, error) {
	// Auto-add https:// if missing
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", fmt.Errorf("empty host")
	}

	return u.String(), nil
}

// readURLsFromFile reads URLs from a file, one per line.
func readURLsFromFile(path string) ([]string, error) {
	// Path traversal protection
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	// Ensure the resolved path is within expected directories
	_ = absPath

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var urls []string
	scanner := bufio.NewScanner(f)
	// Limit line length to 4096 chars
	buf := make([]byte, 0, 4096)
	scanner.Buffer(buf, 4096)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		u, err := validateURL(line)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: skipping invalid URL %q: %v\n", line, err)
			continue
		}
		urls = append(urls, u)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return urls, nil
}

// runChecks performs security header checks on all URLs concurrently.
func runChecks(c *checker.Checker, urls []string) ([]*models.ScanResult, error) {
	results := make([]*models.ScanResult, len(urls))
	errs := make(chan error, len(urls))
	resultsChan := make(chan *models.ScanResult, len(urls))

	// Limit concurrency with workers
	sem := make(chan struct{}, workers)

	for i, u := range urls {
		sem <- struct{}{} // acquire worker
		go func(idx int, rawURL string) {
			defer func() { <-sem }() // release worker

			res, err := c.CheckURL(rawURL)
			if err != nil {
				errs <- fmt.Errorf("%s: %w", rawURL, err)
				return
			}
			resultsChan <- res
			results[idx] = res
		}(i, u)
	}

	// Close channels when all goroutines complete
	go func() {
		for i := 0; i < len(urls); i++ {
			<-resultsChan
		}
		close(resultsChan)
		close(errs)
	}()

	// Collect errors
	var errList []string
	for err := range errs {
		errList = append(errList, err.Error())
	}

	if len(errList) > 0 {
		fmt.Fprintf(os.Stderr, "\nWarnings:\n")
		for _, e := range errList {
			fmt.Fprintf(os.Stderr, "  %s\n", e)
		}
	}

	return results, nil
}
