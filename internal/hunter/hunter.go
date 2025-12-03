package hunter

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"shaihuludscanner/pkg/progress"
	"slices"
	"strings"
	"sync"

	"github.com/go-enry/go-enry/v2"
	"github.com/hillu/go-yara/v4"
	yh "shaihuludscanner/internal/yara"
)

//type ThreatScanner struct {
//	rulesContent string
//	compiler     *yara.Compiler
//	compiledRules
//}

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

func reportFinding(resultChan chan yh.Match, rule string, path string) {
	resultChan <- yh.Match{Rule: rule, FilePath: path}
}

func WalkDirectories(ctx context.Context, fileChan chan string, resultChan chan yh.Match, dirs []string) (int, int, int) {
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

func ScanWorker(ctx context.Context, fileChan chan string, resultChan chan yh.Match, rules *yara.Rules, pw *progress.Writer) {
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

		for _, m := range yh.ToMatches(matches, path) {
			resultChan <- *m
		}

		matches = nil
	}
}

func ScanFileSystem(ctx context.Context, compiledYaraRules *yara.Rules, filePaths []string) ([]yh.Match, int, int, int) {
	if compiledYaraRules == nil {
		return nil, 0, 0, 0
	}
	// Print scan start
	fmt.Printf("Scanning %s\n", strings.Join(filePaths, ","))

	// Channels and waitgroup
	numWorkers := runtime.NumCPU()
	fileChan := make(chan string, 100)
	resultChan := make(chan yh.Match, 100)
	var workerWg sync.WaitGroup

	pw := progress.New(os.Stderr)
	defer pw.Done()

	fmt.Printf("Running scan in %d threads\n", numWorkers)
	// Spawn workers - each creates its own scanner
	for i := 0; i < numWorkers; i++ {
		workerWg.Go(
			func() {
				ScanWorker(ctx, fileChan, resultChan, compiledYaraRules, pw)
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

	var results []yh.Match
	for match := range resultChan {
		results = append(results, match)
	}

	pw.Done()

	return results, walkedDirs, walkedFiles, scannedFiles
}
