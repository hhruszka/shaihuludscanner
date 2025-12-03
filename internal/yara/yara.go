package yara

import (
	"fmt"
	"path/filepath"
	"shaihuludscanner/internal/rules"

	"github.com/VirusTotal/yara-x/go"
)

// YaraHunter represents a structure for managing YARA rules, including file paths, rule content, and compiled rules.
// It allows scanning of data, files, and file descriptors using YARA rules.
// The compiledRules field contains the compiled YARA rules for scanning, and scanner facilitates the actual scanning logic.
type YaraHunter struct {
	rulesFilePath string
	rulesContent  string
	compiledRules *yara_x.Rules
	scanner       *yara_x.Scanner
}

// YaraOptionFunc is a function type used to modify or configure a YaraHunter instance during its initialization.
type YaraHunterOptionFunc func(*YaraHunter)

// NewYaraRules initializes a new YaraHunter object with the provided options or defaults, and compiles YARA rules if needed.
func NewYaraHunter(opts ...YaraHunterOptionFunc) (*YaraHunter, error) {
	yh := &YaraHunter{}
	for _, opt := range opts {
		opt(yh)
	}
	if yh.compiledRules == nil {
		var err error
		yh.rulesFilePath = rules.DefaultRulesName()
		yh.compiledRules, err = rules.DefaultRules()
		if err != nil {
			return nil, fmt.Errorf("")
		}
		yh.scanner = yara_x.NewScanner(yh.compiledRules)
	}

	return yh, nil
}

// GetRules returns the rules content
func (yh *YaraHunter) GetRules() (*yara_x.Rules, error) {
	if yh.compiledRules == nil {
		return nil, fmt.Errorf("rules not compiled yet")
	}
	return yh.compiledRules, nil
}

// GetRulesName returns the base name of the YARA rules file's filepath.
func (yh *YaraHunter) GetRulesName() string {
	return filepath.Base(yh.rulesFilePath)
}

// ScanData scans the provided data slice in memory using YARA rules and returns matching rules or an error.
func (yh *YaraHunter) ScanData(data []byte) ([]*Match, error) {
	yaraMatches, err := yh.scanner.Scan(data)
	if err != nil {
		return nil, err
	}
	return ToMatches(yaraMatches, ""), nil
}

// ScanFile scans a file specified by its file path using YARA rules and returns matching rules or an error.
func (yh *YaraHunter) ScanFile(filePath string) ([]*Match, error) {
	yaraMatches, err := yh.scanner.ScanFile(filePath)
	if err != nil {
		return nil, err
	}
	return ToMatches(yaraMatches, filePath), nil
}
