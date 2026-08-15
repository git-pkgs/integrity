package integrity

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// SRI is a Subresource Integrity metadata list.
type SRI []Digest

// ParseSRI parses a whitespace-separated Subresource Integrity metadata list.
// It accepts standard and URL-safe base64 with optional padding and ignores
// options, which SRI currently leaves undefined.
func ParseSRI(value string) (SRI, error) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return nil, fmt.Errorf("parse SRI: empty metadata")
	}

	digests := make(SRI, 0, len(fields))
	for index, field := range fields {
		expression, _, _ := strings.Cut(field, "?")
		name, encoded, ok := strings.Cut(expression, "-")
		if !ok {
			return nil, fmt.Errorf("parse SRI entry %d: missing algorithm prefix", index+1)
		}
		algorithm, err := parseAlgorithm(name)
		if err != nil {
			return nil, fmt.Errorf("parse SRI entry %d: %w", index+1, err)
		}
		raw, err := decodeBase64Digest(algorithm, encoded)
		if err != nil {
			return nil, fmt.Errorf("parse SRI entry %d: %w", index+1, err)
		}
		digest, err := newDigest(algorithm, raw)
		if err != nil {
			return nil, fmt.Errorf("parse SRI entry %d: %w", index+1, err)
		}
		digests = append(digests, digest)
	}
	return digests, nil
}

func decodeBase64Digest(algorithm Algorithm, encoded string) ([]byte, error) {
	want, err := digestSize(algorithm)
	if err != nil {
		return nil, err
	}

	paddedLength := base64.StdEncoding.EncodedLen(want)
	rawLength := base64.RawStdEncoding.EncodedLen(want)
	encoding := base64.StdEncoding
	if len(encoded) == rawLength && rawLength != paddedLength {
		encoding = base64.RawStdEncoding
	} else if len(encoded) != paddedLength {
		return nil, fmt.Errorf("%s digest encoding has %d bytes, incompatible with %d-byte digest", algorithm, len(encoded), want)
	}

	encoded = strings.ReplaceAll(encoded, "-", "+")
	encoded = strings.ReplaceAll(encoded, "_", "/")
	return encoding.DecodeString(encoded)
}

// FormatSRI formats a metadata list with lower-case algorithm names, padded
// standard base64, and one space between entries.
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
