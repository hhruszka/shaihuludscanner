package rules

import (
	"embed"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/VirusTotal/yara-x/go"
)

//go:embed data
var rulesFiles embed.FS

//go:embed data/rules.yara
var rulesContent string

//go:embed data/name.txt
var rulesName string

// rulesFilename is the name of the embedded YARA rules file used for threat detection.
const rulesFilename = "rules.yara"

// YaraRulesNamespace defines the namespace for organizing YARA rules used in the threat detection system.
const yaraRulesNamespace = "threat_hunter"

// defaultYaraRules holds the precompiled YARA rules used for threat detection, initialized with embedded rules content.
var defaultYaraRules *yara_x.Rules

// _getRules returns the content of the embedded rules file or reads it from the embedded filesystem if not already loaded.
func _getRules() (string, error) {
	if rulesContent != "" {
		return rulesContent, nil
	}
	data, err := rulesFiles.ReadFile(filepath.Join("data/", rulesFilename))
	if err != nil {
		return "", fmt.Errorf("failed to read embedded file %s; %w", rulesFilename, err)
	}
	return string(data), nil
}

// compileRulesOnce ensures that the rules compilation logic is executed only once, regardless of how many times it's invoked.
var compileRulesOnce sync.Once

// DefaultRules returns the compiled YARA rules for threat detection, initializing them only once using an embedded rules file.
func DefaultRules() (*yara_x.Rules, error) {
	var err error
	compileRulesOnce.Do(func() {
		err = defaultRules()
	})
	return defaultYaraRules, err
}

// DefaultRulesName returns the base name of the embedded YARA rules file used for threat detection.
func DefaultRulesName() string {
	return rulesName
}

// defaultRules initializes and returns the default YaraRules object using embedded rules content.
func defaultRules() error {
	rulesContent, err := _getRules()
	if err != nil {
		return fmt.Errorf("failed to read embedded file %s; %w", rulesFilename, err)
	}
	compiler, err := yara_x.NewCompiler()
	if err != nil {
		return fmt.Errorf("failed to create yara compiler; %w", err)
	}
	err = compiler.AddSource(rulesContent, yara_x.WithOrigin(rulesFilename))
	if err != nil {
		return fmt.Errorf("failed to add yara rules; %w", err)
	}
	defaultYaraRules = compiler.Build()

	return nil
}
