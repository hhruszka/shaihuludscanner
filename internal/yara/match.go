package yara

import (
	"fmt"
)

type Match struct {
	Rule        string
	FilePath    string
	Severity    string
	Description string
}

func (m Match) String() string {
	return fmt.Sprintf("Rule: %s, File: %s, Severity: %s, Description: %s", m.Rule, m.FilePath, m.Severity, m.Description)
}
