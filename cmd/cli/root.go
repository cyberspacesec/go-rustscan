package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	cfgFile string
	port    string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "go-rustscan",
	Short: "A Go wrapper for RustScan with HTTP API support",
	Long: `go-rustscan is a powerful wrapper around RustScan that provides both
command line interface and HTTP API for port scanning operations.
It combines the speed of RustScan with the flexibility of HTTP APIs.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.go-rustscan.yaml)")
	rootCmd.PersistentFlags().StringVar(&port, "port", "8080", "port for the HTTP server")
}
