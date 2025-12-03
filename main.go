package main

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"shaihuludscanner/internal/hunter"
	"shaihuludscanner/internal/reports"
	"shaihuludscanner/internal/rules"
)

var AppVersion string = "dev"

func parseArgs() ([]string, error) {
	// Parse args - path to scan
	if len(os.Args) < 2 || os.Args[1] == "" {
		fmt.Printf("Usage: %s <path>\n", os.Args[0])
		return nil, fmt.Errorf("missing file path to scan")
	}

	// Check path exists
	for _, path := range os.Args[1:] {
		root := os.Args[1]
		if _, err := os.Stat(root); os.IsNotExist(err) {
			return nil, fmt.Errorf("path does not exist:", path)
		}
	}
	return os.Args[1:], nil
}

func main() {
	// Handle Ctrl+C
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	filePaths, err := parseArgs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to retrieve arguments;%w", err)
		os.Exit(1)
	}

	fmt.Printf("%s version %s\n", filepath.Base(os.Args[0]), AppVersion)
	fmt.Printf("Using %s yara rules set\n", rules.DefaultRulesName())
	fmt.Println()

	rules, err := rules.DefaultRules()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load yara rules;%w", err)
		os.Exit(1)
	}
	// Scan Filesystem
	results, walkedDirs, walkedFiles, scannedFiles := hunter.ScanFileSystem(ctx, rules, filePaths)
	// Reporting
	reports.GenerateReport(results, walkedDirs, walkedFiles, scannedFiles)
}
