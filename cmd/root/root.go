package root

import (
	"github.com/spf13/cobra"
)

var version = "dev"

// SetVersion sets the version string.
func SetVersion(v string) {
	version = v
}

// rootCmd represents the base command.
var rootCmd = &cobra.Command{
	Use:   "headerguard",
	Short: "HTTP Security Headers Analyzer",
	Long: `HeaderGuard is a CLI tool for analyzing HTTP security headers.
It checks 15+ security headers, computes a weighted security score (A-F grade),
and outputs results in text, JSON, or CSV format.`,
	Version: version,
}

// Execute adds all child commands and runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
