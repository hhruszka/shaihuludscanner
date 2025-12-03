package yara

import "fmt"

type Match struct {
	Rule        string
	FilePath    string
	Severity    string
	Description string
}

func NewMatch(rule string, filePath string, severity string, description string) *Match {
	return &Match{Rule: rule, FilePath: filePath, Severity: severity, Description: description}
}

func (m Match) String() string {
	return fmt.Sprintf("Rule: %s, File: %s, Severity: %s, Description: %s", m.Rule, m.FilePath, m.Severity, m.Description)
}
