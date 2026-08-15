package integrity

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// SRI is a Subresource Integrity metadata list.
type SRI []Digest

// ParseSRI parses a whitespace-separated Subresource Integrity metadata list.
func ParseSRI(value string) (SRI, error) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return nil, fmt.Errorf("parse SRI: empty metadata")
	}

	digests := make(SRI, 0, len(fields))
	for _, field := range fields {
		name, encoded, ok := strings.Cut(field, "-")
		if !ok {
			return nil, fmt.Errorf("parse SRI entry %q: missing algorithm prefix", field)
		}
		algorithm, err := parseAlgorithm(name)
		if err != nil {
			return nil, fmt.Errorf("parse SRI entry %q: %w", field, err)
		}
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("parse SRI entry %q: %w", field, err)
		}
		digest, err := newDigest(algorithm, raw)
		if err != nil {
			return nil, fmt.Errorf("parse SRI entry %q: %w", field, err)
		}
		digests = append(digests, digest)
	}
	return digests, nil
}

// FormatSRI formats a metadata list with lower-case algorithm names, standard
// base64, and one space between entries.
func FormatSRI(sri SRI) string {
	entries := make([]string, len(sri))
	for i, digest := range sri {
		entries[i] = digest.SRI()
	}
	return strings.Join(entries, " ")
}

func strongestAlgorithm(sri SRI) (Algorithm, error) {
	if len(sri) == 0 {
		return 0, fmt.Errorf("verify integrity: no expected digests")
	}
	strongest := sri[0].Algorithm()
	if _, err := digestSize(strongest); err != nil {
		return 0, fmt.Errorf("verify integrity: %w", err)
	}
	for _, digest := range sri[1:] {
		algorithm := digest.Algorithm()
		if _, err := digestSize(algorithm); err != nil {
			return 0, fmt.Errorf("verify integrity: %w", err)
		}
		if algorithm > strongest {
			strongest = algorithm
		}
	}
	return strongest, nil
}
