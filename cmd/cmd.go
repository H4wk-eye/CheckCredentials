package cmd

import (
	"fmt"
	"os"

	"checkcredentials/pkg/scanner"

	"github.com/spf13/cobra"
)

var (
	path       string
	verbose    bool
	format     string
	workers    int
	outputFile string
)

const (
	defaultWorkers = 10
)

var rootCmd = &cobra.Command{
	Use:   "Checkcredentials",
	Short: "find users/passwords in configurations files",
	Long:  `When we need to find some secrets in lateralmovement or local check `,
	Run: func(cmd *cobra.Command, args []string) {
		if len(os.Args) == 1 {
			cmd.Help()
			return
		}
		if verbose {
			fmt.Printf("Checking path: %s\n", path)
			fmt.Printf("Output format: %s\n", format)
			fmt.Printf("Workers: %d\n", workers)
			fmt.Printf("Output files: %s\n", outputFile)
			fmt.Println("____________________________________________________")
		}
		s := scanner.New(workers, verbose, format, outputFile)
		s.Scan(path)
	},
}

func init() {
	rootCmd.Flags().StringVarP(&path, "path", "p", "/", "Path to scan (default:/)")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", true, "More details,default True")
	rootCmd.Flags().StringVarP(&format, "format", "f", "text", "Output format")
	rootCmd.Flags().IntVarP(&workers, "workers", "w", defaultWorkers, "Workers number")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "result.txt", "output file")
}
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
