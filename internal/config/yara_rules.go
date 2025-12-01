package config

import (
	"embed"
	"fmt"
	"path/filepath"
)

//go:embed data
var rulesFiles embed.FS

// const rulesFilename = "shai_hulud_2_1_0_go.yara"
const rulesFilename = "shai_hulud_2_0_12.yara"

func GetRules() (string, error) {
	data, err := rulesFiles.ReadFile(filepath.Join("data/", rulesFilename))
	if err != nil {
		return "", fmt.Errorf("failed to read embedded file %s; %w", rulesFilename, err)
	}
	return string(data), nil
}

func GetRulesFilename() string {
	return rulesFilename
}
