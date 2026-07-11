package root

import (
	"fmt"

	"github.com/spf13/cobra"
)

// versionCmd represents the version command.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long:  `Print the version of HeaderGuard.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "HeaderGuard version %s\n", version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
