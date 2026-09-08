package util

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// ShellWord returns the literal value of a shell word made only of literals
// and quoted strings. It reports false when the word contains expansions
// (variables, substitutions, globs), so callers can reject them.
func ShellWord(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", false
	}
	var b strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok {
					return "", false
				}
				b.WriteString(lit.Value)
			}
		default:
			return "", false
		}
	}
	return b.String(), true
}
