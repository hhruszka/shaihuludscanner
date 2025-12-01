package scanner

import "github.com/hillu/go-yara/v4"

type ThreatScanner struct {
	rulesContent string
	compiler     *yara.Compiler
	compiledRules
}
