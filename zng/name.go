package zng

import (
	"strconv"
	"unicode"
)

func IdChar(c rune) bool {
	return unicode.IsLetter(c) || c == '_' || c == '$'
}

func TypeChar(c rune) bool {
	return IdChar(c) || unicode.IsDigit(c) || c == '/' || c == '.'
}

func IsIdentifier(s string) bool {
	first := true
	for _, c := range s {
		if !IdChar(c) && (first || !unicode.IsDigit(c)) {
			return false
		}
		first = false
	}
	return true
}

// IsTypeName returns true iff s is a valid zson typedef name (exclusive
// of integer names for locally-scoped typedefs).
func IsTypeName(s string) bool {
	for _, c := range s {
		if !TypeChar(c) {
			return false
		}
	}
	_, err := strconv.ParseInt(s, 10, 64)
	return err != nil
}
