package integrity

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

func digestBytes(algorithm Algorithm, value string) []byte {
	switch algorithm {
	case SHA256:
		sum := sha256.Sum256([]byte(value))
		return sum[:]
	case SHA384:
		sum := sha512.Sum384([]byte(value))
		return sum[:]
	case SHA512:
		sum := sha512.Sum512([]byte(value))
		return sum[:]
	default:
		return nil
	}
}

func sriEntry(algorithm Algorithm, value string) string {
	return algorithm.String() + "-" + base64.StdEncoding.EncodeToString(digestBytes(algorithm, value))
}

func TestParseAndFormatSRIAlgorithms(t *testing.T) {
	for _, algorithm := range []Algorithm{SHA256, SHA384, SHA512} {
		t.Run(algorithm.String(), func(t *testing.T) {
			entry := sriEntry(algorithm, "")
			parsed, err := ParseSRI(" \t" + entry + "\n")
			if err != nil {
				t.Fatalf("ParseSRI: %v", err)
			}
			if len(parsed) != 1 {
				t.Fatalf("len(ParseSRI) = %d, want 1", len(parsed))
			}
			if parsed[0].Algorithm() != algorithm {
				t.Errorf("Algorithm = %s, want %s", parsed[0].Algorithm(), algorithm)
			}
			if got, want := parsed[0].Hex(), hex.EncodeToString(digestBytes(algorithm, "")); got != want {
				t.Errorf("Hex = %q, want %q", got, want)
			}
			if got := parsed[0].SRI(); got != entry {
				t.Errorf("SRI = %q, want %q", got, entry)
			}
			if got := FormatSRI(parsed); got != entry {
				t.Errorf("FormatSRI = %q, want %q", got, entry)
			}
		})
	}
}

func TestParseSRIMultipleHashesCanonicalFormat(t *testing.T) {
	want := []struct {
		algorithm Algorithm
		value     string
	}{
		{SHA256, "first"},
		{SHA512, "second"},
		{SHA512, "alternative"},
		{SHA384, "last"},
	}
	entries := make([]string, len(want))
	for i, item := range want {
		entries[i] = strings.ToUpper(item.algorithm.String()) + "-" + base64.StdEncoding.EncodeToString(digestBytes(item.algorithm, item.value))
	}

	parsed, err := ParseSRI("  " + entries[0] + "\t" + entries[1] + "\n" + entries[2] + "  " + entries[3] + " ")
	if err != nil {
		t.Fatalf("ParseSRI: %v", err)
	}
	if len(parsed) != len(want) {
		t.Fatalf("len(ParseSRI) = %d, want %d", len(parsed), len(want))
	}

	canonical := make([]string, len(want))
	for i, item := range want {
		if parsed[i].Algorithm() != item.algorithm {
			t.Errorf("digest %d algorithm = %s, want %s", i, parsed[i].Algorithm(), item.algorithm)
		}
		if !reflect.DeepEqual(parsed[i].Bytes(), digestBytes(item.algorithm, item.value)) {
			t.Errorf("digest %d bytes differ", i)
		}
		canonical[i] = sriEntry(item.algorithm, item.value)
	}
	if got, expected := FormatSRI(parsed), strings.Join(canonical, " "); got != expected {
		t.Errorf("FormatSRI = %q, want %q", got, expected)
	}
}

func TestParseSRIBase64EncodingsAndOptions(t *testing.T) {
	raw := digestBytes(SHA256, "hello")
	canonical := sriEntry(SHA256, "hello")
	tests := map[string]string{
		"base64url":     "sha256-" + base64.URLEncoding.EncodeToString(raw),
		"raw base64":    "sha256-" + base64.RawStdEncoding.EncodeToString(raw),
		"raw base64url": "sha256-" + base64.RawURLEncoding.EncodeToString(raw),
		"options":       canonical + "?first?second",
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			parsed, err := ParseSRI(value)
			if err != nil {
				t.Fatalf("ParseSRI(%q): %v", value, err)
			}
			if got := FormatSRI(parsed); got != canonical {
				t.Errorf("FormatSRI = %q, want %q", got, canonical)
			}
		})
	}
}

func TestParseSRIRejectsMalformedValues(t *testing.T) {
	tests := map[string]string{
		"empty":                 "",
		"whitespace":            " \t\n ",
		"missing separator":     "sha256",
		"unsupported algorithm": "md5-1B2M2Y8AsgTpgAmY7PhCfg==",
		"malformed base64":      "sha384-not!base64",
		"short SHA-256":         "sha256-" + base64.StdEncoding.EncodeToString(make([]byte, sha256Size-1)),
		"long SHA-384":          "sha384-" + base64.StdEncoding.EncodeToString(make([]byte, sha384Size+1)),
		"short SHA-512":         "sha512-" + base64.StdEncoding.EncodeToString(make([]byte, sha512Size-1)),
		"one invalid entry":     sriEntry(SHA256, "ok") + " sha384-nope",
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSRI(value); err == nil {
				t.Fatalf("ParseSRI(%q) returned nil error", value)
			}
		})
	}
}

func TestParseSRIRejectsOversizedValuesWithoutEchoingInput(t *testing.T) {
	values := []string{
		"sha256-" + strings.Repeat("A", 64*1024),
		strings.Repeat("A", 64*1024) + "-digest",
	}
	for _, value := range values {
		_, err := ParseSRI(value)
		if err == nil {
			t.Fatalf("ParseSRI accepted an oversized value")
		}
		if len(err.Error()) > 256 {
			t.Errorf("ParseSRI returned a %d-byte error for oversized input", len(err.Error()))
		}
	}
}

func TestParseHexCanonicalAndImmutable(t *testing.T) {
	raw := digestBytes(SHA256, "hello")
	digest, err := ParseHex(SHA256, strings.ToUpper(hex.EncodeToString(raw)))
	if err != nil {
		t.Fatalf("ParseHex: %v", err)
	}
	if got, want := digest.Hex(), hex.EncodeToString(raw); got != want {
		t.Errorf("Hex = %q, want %q", got, want)
	}

	copyOfBytes := digest.Bytes()
	copyOfBytes[0] ^= 0xff
	if reflect.DeepEqual(copyOfBytes, digest.Bytes()) {
		t.Error("Bytes returned mutable digest storage")
	}
}

func TestParseHexRejectsMalformedValues(t *testing.T) {
	tests := []struct {
		algorithm Algorithm
		value     string
	}{
		{SHA256, "not hex"},
		{SHA256, strings.Repeat("00", sha256Size-1)},
		{SHA384, strings.Repeat("00", sha384Size+1)},
		{SHA512, ""},
		{Algorithm(99), strings.Repeat("00", sha256Size)},
		{SHA256, strings.Repeat("00", 64*1024)},
	}
	for _, test := range tests {
		if _, err := ParseHex(test.algorithm, test.value); err == nil {
			t.Errorf("ParseHex(%s, %q) returned nil error", test.algorithm, test.value)
		}
	}
}

func TestDigestEqual(t *testing.T) {
	first, err := ParseHex(SHA256, hex.EncodeToString(digestBytes(SHA256, "same")))
	if err != nil {
		t.Fatal(err)
	}
	second, err := ParseSRI(sriEntry(SHA256, "same"))
	if err != nil {
		t.Fatal(err)
	}
	different, err := ParseSRI(sriEntry(SHA256, "different"))
	if err != nil {
		t.Fatal(err)
	}
	differentAlgorithm, err := ParseSRI(sriEntry(SHA384, "same"))
	if err != nil {
		t.Fatal(err)
	}

	if !first.Equal(second[0]) {
		t.Error("equal digests did not compare equal")
	}
	if first.Equal(different[0]) {
		t.Error("different digest bytes compared equal")
	}
	if first.Equal(differentAlgorithm[0]) {
		t.Error("different algorithms compared equal")
	}
	if (Digest{}).Equal(Digest{}) {
		t.Error("invalid zero-value digests compared equal")
	}
}

func TestSRISemanticRoundTrip(t *testing.T) {
	input := sriEntry(SHA384, "one") + " " + sriEntry(SHA256, "two") + " " + sriEntry(SHA384, "three")
	first, err := ParseSRI(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ParseSRI(FormatSRI(first))
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != len(second) {
		t.Fatalf("round trip length = %d, want %d", len(second), len(first))
	}
	for i := range first {
		if !first[i].Equal(second[i]) {
			t.Errorf("digest %d changed during round trip", i)
		}
	}
}
