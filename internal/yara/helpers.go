package yara

import (
	yara_x "github.com/VirusTotal/yara-x/go"
)

// getYaraMatchRuleMeta retrieves the string value of a specified metadata identifier from a YARA match rule.
// If the identifier does not exist, it returns the identifier concatenated with "not defined".
func yaraMeta(m *yara_x.Rule, identifier string) string {
	for _, meta := range m.Metadata() {
		if meta.Identifier() == identifier {
			value, ok := meta.Value().(string)
			if ok {
				return value
			}
		}
	}
	return identifier + "not defined"
}

func ToMatches(yaraMatches *yara_x.ScanResults, fileName string) []*Match {
	matchingRules := yaraMatches.MatchingRules()
	if len(matchingRules) == 0 {
		return nil
	}

	matches := make([]*Match, len(matchingRules))
	for i, match := range matchingRules {
		matches[i] = &Match{
			Rule:        match.Identifier(),
			FilePath:    fileName,
			Severity:    yaraMeta(match, "severity"),
			Description: yaraMeta(match, "description"),
		}
	}
	return matches
}
