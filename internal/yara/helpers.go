package yara

import "github.com/hillu/go-yara/v4"

// getYaraMatchRuleMeta retrieves the string value of a specified metadata identifier from a YARA match rule.
// If the identifier does not exist, it returns the identifier concatenated with "not defined".
func getYaraMatchRuleMeta(m yara.MatchRule, identifier string) string {
	for _, meta := range m.Metas {
		if meta.Identifier == identifier {
			value, ok := meta.Value.(string)
			if ok {
				return value
			}
		}
	}
	return identifier + "not defined"
}

func ToMatches(yaraMatches yara.MatchRules, fileName string) []*Match {
	matches := make([]*Match, len(yaraMatches))
	for _, match := range yaraMatches {
		matches = append(matches, NewMatch(match.Rule, fileName, getYaraMatchRuleMeta(match, "severity"), getYaraMatchRuleMeta(match, "description")))
	}
	return matches
}
