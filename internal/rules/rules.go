package rules

import (
	"embed"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/hillu/go-yara/v4"
)

//go:embed data/
var rulesFiles embed.FS

// rulesFilename is the name of the embedded YARA rules file used for threat detection.
const rulesFilename = "shai_hulud_2_0_12.yara"

// YaraRulesNamespace defines the namespace for organizing YARA rules used in the threat detection system.
const yaraRulesNamespace = "threat_hunter"

// defaultYaraRules holds the precompiled YARA rules used for threat detection, initialized with embedded rules content.
var defaultYaraRules *yara.Rules

// _getRules reads the embedded YARA rules file and returns its content as a string or an error if encountered.
func _getRules() (string, error) {
	data, err := rulesFiles.ReadFile(filepath.Join("data/", rulesFilename))
	if err != nil {
		return "", fmt.Errorf("failed to read embedded file %s; %w", rulesFilename, err)
	}
	return string(data), nil
}

// compileRulesOnce ensures that the rules compilation logic is executed only once, regardless of how many times it's invoked.
var compileRulesOnce sync.Once

// DefaultRules returns the compiled YARA rules for threat detection, initializing them only once using an embedded rules file.
func DefaultRules() (*yara.Rules, error) {
	var err error
	compileRulesOnce.Do(func() {
		err = defaultRules()
	})
	return defaultYaraRules, err
}

// DefaultRulesName returns the base name of the embedded YARA rules file used for threat detection.
func DefaultRulesName() string {
	return filepath.Base(rulesFilename)
}

// defaultRules initializes and returns the default YaraRules object using embedded rules content.
func defaultRules() error {
	rulesContent, err := _getRules()
	if err != nil {
		return fmt.Errorf("failed to read embedded file %s; %w", rulesFilename, err)
	}
	compiler, err := yara.NewCompiler()
	if err != nil {
		return fmt.Errorf("failed to create yara compiler; %w", err)
	}
	err = compiler.AddString(rulesContent, yaraRulesNamespace)
	if err != nil {
		return fmt.Errorf("failed to add yara rules; %w", err)
	}
	defaultYaraRules, err = compiler.GetRules()
	if err != nil {
		return fmt.Errorf("failed to compile yara rules; %w", err)
	}

	return nil
}
