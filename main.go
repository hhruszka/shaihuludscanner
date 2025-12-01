package main

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/hillu/go-yara/v4"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"text/tabwriter"
)

//go:embed shai_hulud_2_1_0_go.yara
var rulesContent string

var excludeDirs = []string{"/proc", "/sys", "/dev", "/run"}

func shouldReportDirectory(name string) bool {
	return name == ".truffler-cache"
}

func shouldScan(path string, filename string) bool {
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

type Match struct {
	Rule string
	Path string
}

func reportFinding(resultChan chan Match, rule string, path string) {
	resultChan <- Match{Rule: rule, Path: path}
}

func main() {
	// Handle Ctrl+C
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	// Parse args - path to scan
	if len(os.Args) < 2 || os.Args[1] == "" {
		fmt.Println("Usage: %s <path>", os.Args[0])
		os.Exit(1)
	}

	// Check path exists
	root := os.Args[1]
	if _, err := os.Stat(root); os.IsNotExist(err) {
		fmt.Println("Path does not exist:", root)
		os.Exit(1)
	}

	// Compile rules ONCE
	compiler, _ := yara.NewCompiler()
	err := compiler.DefineVariable("filename", "")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	err = compiler.DefineVariable("filepath", "")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	err = compiler.AddString(rulesContent, "shai_hulud")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	rules, err := compiler.GetRules()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	compiler.Destroy()

	// Print scan start
	fmt.Printf("Scanning %s\n", root)

	// Channels and waitgroup
	numWorkers := runtime.NumCPU()
	fileChan := make(chan string, 100)
	resultChan := make(chan Match, 100)
	var workerWg sync.WaitGroup

	// Spawn workers - each creates its own scanner
	for i := 0; i < numWorkers; i++ {
		workerWg.Go(
			func() {
				// Each worker gets its own scanner
				scanner, _ := yara.NewScanner(rules)
				defer scanner.Destroy()
				var path string
				var ok bool

				for {
					select {
					case <-ctx.Done():
						fmt.Println("Terminating! user interrupted")
						return
					case path, ok = <-fileChan:
						if !ok {
							return
						}
					default:
					}
					_ = scanner.DefineVariable("filename", filepath.Base(path))
					_ = scanner.DefineVariable("filepath", path)

					var matches yara.MatchRules
					if err := scanner.SetCallback(&matches).ScanFile(path); err != nil {
						fmt.Println(err)
						continue
					}

					for _, m := range matches {
						resultChan <- Match{Rule: m.Rule, Path: path}
					}
				}
			})
	}

	// Feed files to workers
	go func() {
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			select {
			case <-ctx.Done():
				return nil
			default:
			}

			// Check for suspicious directories
			if info.IsDir() {
				if shouldReportDirectory(info.Name()) {
					reportFinding(resultChan, "ShaiHulud2_TrufflerCache_Directory", path)
					return nil
				}
				if slices.Contains(excludeDirs, path) {
					return filepath.SkipDir
				}
				return nil
			}

			if err == nil && !info.IsDir() && shouldScan(path, info.Name()) {
				fileChan <- path
			}
			return nil
		})
		close(fileChan)
	}()

	// Collect results
	go func() {
		workerWg.Wait()
		close(resultChan)
	}()

	// Print results
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.AlignRight)
	defer tw.Flush()

	_, _ = fmt.Fprintf(tw, "Rule\tPath\n")
	for match := range resultChan {
		fmt.Fprintf(tw, "%s\t%s\n", match.Rule, match.Path)
	}

	rules.Destroy()
}
