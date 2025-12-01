package main

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/go-enry/go-enry/v2"
	"github.com/hillu/go-yara/v4"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"shaihuludscanner/internal/config"
	"shaihuludscanner/pkg/progress"
	"slices"
	"strings"
	"sync"
	"text/tabwriter"
)

var AppVersion string = "dev"
var excludeDirs = []string{"/proc", "/sys", "/dev", "/run"}

func shouldReportDirectory(name string) bool {
	return name == ".truffler-cache"
}

// Helper to read just the header
func readFileHeader(path string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, limit)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return buf[:n], nil
}

var shouldScan = shouldScanV2

func shouldScanV1(path string, filename string) bool {
	// Read the first 8KB of the file (standard sniffing limit)
	content, err := readFileHeader(path, 8000)
	if err != nil {
		return false // Skip files we can't read
	}

	// Run go-enry to detect if it is binary
	if enry.IsBinary(content) {
		return false // Skip binary files
	}

	// Exact filenames
	switch filename {
	case "package.json", "setup_bun.js", "bun_environment.js",
		"bundle.js", "actionsSecrets.json", "truffleSecrets.json":
		return true
	}

	// .truffler-cache directory
	if strings.Contains(path, ".truffler-cache") {
		return true
	}

	// GitHub workflows
	if strings.Contains(path, ".github/workflows") &&
		(strings.HasSuffix(filename, ".yml") || strings.HasSuffix(filename, ".yaml")) {
		return true
	}

	// JS in node_modules
	if strings.HasSuffix(filename, ".js") && strings.Contains(path, "node_modules") {
		return true
	}

	return false
}

func shouldScanV2(path string, filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4":
		return false
	}

	// Read the first 8KB of the file (standard sniffing limit)
	content, err := readFileHeader(path, 8000)
	if err != nil {
		return false // Skip files we can't read
	}

	// Run go-enry to detect if it is binary
	if enry.IsBinary(content) {
		return false // Skip binary files
	}

	switch strings.ToLower(enry.GetLanguage(filepath.Base(filename), content)) {
	case "javascript", "yaml", "json", "typescript":
		return true
	}

	// Allow ALL target extensions
	// This lets v2.0.12 detect renamed malware (e.g. "evil_script.js")
	if strings.HasSuffix(filename, ".js") ||
		strings.HasSuffix(filename, ".json") {
		return true
	}

	// GitHub Workflows
	if strings.Contains(path, ".github/workflows") &&
		(strings.HasSuffix(filename, ".yml") || strings.HasSuffix(filename, ".yaml")) {
		return true
	}

	// Cache
	if strings.Contains(path, ".truffler-cache") {
		return true
	}

	return false
}

type Match struct {
	Rule string
	Path string
}

func reportFinding(resultChan chan Match, rule string, path string) {
	resultChan <- Match{Rule: rule, Path: path}
}

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

func WalkDirectories(ctx context.Context, fileChan chan string, resultChan chan Match, dirs []string) (int, int, int) {
	var walkedFiles, walkedDirs, scannedFiles int

	for _, dir := range dirs {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			select {
			case <-ctx.Done():
				return nil
			default:
			}

			// Check for suspicious directories
			if info.IsDir() {
				walkedDirs += 1
				if shouldReportDirectory(info.Name()) {
					reportFinding(resultChan, "ShaiHulud2_TrufflerCache_Directory", path)
					return nil
				}
				if slices.Contains(excludeDirs, path) {
					return filepath.SkipDir
				}
				return nil
			}

			walkedFiles += 1
			if err == nil && !info.IsDir() && info.Mode().IsRegular() && shouldScan(path, info.Name()) {
				scannedFiles += 1
				fileChan <- path
			}
			return nil
		})
	}

	return walkedDirs, walkedFiles, scannedFiles
}

func ScanWorker(ctx context.Context, fileChan chan string, resultChan chan Match, rules *yara.Rules, pw *progress.Writer) {
	// Each worker gets its own scanner
	scanner, _ := yara.NewScanner(rules)
	defer scanner.Destroy()
	var (
		err  error
		path string
		ok   bool
		fd   *os.File
	)

	for {
		select {
		case <-ctx.Done():
			pw.Println("Terminating! user interrupted")
			return
		case path, ok = <-fileChan:
			if !ok {
				return
			}

			pw.Progress("\rScanning: %s", path)
		}

		//_ = scanner.DefineVariable("filename", filepath.Base(path))
		//_ = scanner.DefineVariable("filepath", path)

		var matches yara.MatchRules

		fd, err = os.Open(path)
		if err != nil {
			pw.Println("Cannot open file %s;%s\n", path, err.Error())
			continue
		}

		if err := scanner.SetCallback(&matches).ScanFileDescriptor(fd.Fd()); err != nil {
			pw.Println("Yara error: %s for %s file\n", err.Error(), path)
			fd.Close()
			continue
		}
		fd.Close()

		for _, m := range matches {
			resultChan <- Match{Rule: m.Rule, Path: path}
		}

		matches = nil
	}
}

func ScanFileSystem(ctx context.Context, rulesContent string, filePaths []string) ([]Match, int, int, int) {
	// Compile rules ONCE
	compiler, _ := yara.NewCompiler()
	err := compiler.AddString(rulesContent, "shai_hulud")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Yara failed to define add rules; %s\n", err.Error())
		os.Exit(1)
	}
	rules, err := compiler.GetRules()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Yara failed to compile rules; %s\n", err.Error())
		os.Exit(1)
	}
	compiler.Destroy()
	defer rules.Destroy()

	// Print scan start
	fmt.Printf("Scanning %s\n", strings.Join(filePaths, ","))

	// Channels and waitgroup
	numWorkers := runtime.NumCPU()
	fileChan := make(chan string, 100)
	resultChan := make(chan Match, 100)
	var workerWg sync.WaitGroup

	pw := progress.New(os.Stderr)
	defer pw.Done()

	fmt.Printf("Running scan in %d threads\n", numWorkers)
	// Spawn workers - each creates its own scanner
	for i := 0; i < numWorkers; i++ {
		workerWg.Go(
			func() {
				ScanWorker(ctx, fileChan, resultChan, rules, pw)
			})
	}

	walkedFiles := 0
	walkedDirs := 0
	scannedFiles := 0
	// Feed files to workers
	go func() {
		walkedDirs, walkedFiles, scannedFiles = WalkDirectories(ctx, fileChan, resultChan, filePaths)
		close(fileChan)
	}()

	// Collect results
	go func() {
		workerWg.Wait()
		close(resultChan)
	}()

	var results []Match
	for match := range resultChan {
		results = append(results, match)
	}

	pw.Done()

	return results, walkedDirs, walkedFiles, scannedFiles
}

func GenerateReport(results []Match, walkedDirs, walkedFiles, scannedFiles int) {
	fmt.Println()
	fmt.Printf("Walked %d dirs and %d files\n", walkedDirs, walkedFiles)
	fmt.Printf("Scanned %d files\n", scannedFiles)
	fmt.Println("Scan complete")

	if len(results) == 0 {
		fmt.Println()
		fmt.Println("No Shai Hulud IoCs found")
	}
	if len(results) > 0 {
		fmt.Println()
		fmt.Println("Shai Hulud IoCs found! System infected!")
		// Print results
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

		_, _ = fmt.Fprintf(tw, "Rule\tPath\n")
		for _, match := range results {
			fmt.Fprintf(tw, "%s\t%s\n", match.Rule, match.Path)
		}
		tw.Flush()
	}
}

func main() {
	// Handle Ctrl+C
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	rulesContent, err := config.GetRules()
	if err != nil {
		fmt.Printf("%s\n", err.Error())
		os.Exit(1)
	}

	filePaths, err := parseArgs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to retrieve arguments;%w", err)
		os.Exit(1)
	}

	fmt.Printf("%s version %s\n", filepath.Base(os.Args[0]), AppVersion)
	fmt.Printf("Using %s yara rules set\n", config.GetRulesFilename())
	fmt.Println()

	// Scan Filesystem
	results, walkedDirs, walkedFiles, scannedFiles := ScanFileSystem(ctx, rulesContent, filePaths)
	// Reporting
	GenerateReport(results, walkedDirs, walkedFiles, scannedFiles)
}
