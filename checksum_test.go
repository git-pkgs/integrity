package integrity

import (
	"crypto/md5"  //nolint:gosec // MD5 is tested as a compatibility checksum
	"crypto/sha1" //nolint:gosec // SHA-1 is tested as a compatibility checksum
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func weakDigestBytes(algorithm Algorithm, value string) []byte {
	switch algorithm {
	case MD5:
		sum := md5.Sum([]byte(value)) //nolint:gosec // compatibility checksum
		return sum[:]
	case SHA1:
		sum := sha1.Sum([]byte(value)) //nolint:gosec // compatibility checksum
		return sum[:]
	default:
		return digestBytes(algorithm, value)
	}
}

func checksumHex(algorithm Algorithm, value string) string {
	return hex.EncodeToString(weakDigestBytes(algorithm, value))
}

var allAlgorithms = []Algorithm{MD5, SHA1, SHA256, SHA384, SHA512}

func TestAlgorithmNames(t *testing.T) {
	for algorithm, want := range map[Algorithm]string{MD5: "md5", SHA1: "sha1", SHA256: "sha256", SHA384: "sha384", SHA512: "sha512"} {
		if got := algorithm.String(); got != want {
			t.Errorf("String = %q, want %q", got, want)
		}
	}
}

func TestParseHexWeakAlgorithms(t *testing.T) {
	for _, algorithm := range []Algorithm{MD5, SHA1} {
		t.Run(algorithm.String(), func(t *testing.T) {
			value := checksumHex(algorithm, "hello")
			digest, err := ParseHex(algorithm, strings.ToUpper(value))
			if err != nil {
				t.Fatalf("ParseHex: %v", err)
			}
			if digest.Algorithm() != algorithm || digest.Hex() != value {
				t.Errorf("digest = %s %s, want %s %s", digest.Algorithm(), digest.Hex(), algorithm, value)
			}
			if got, want := digest.Checksum(), algorithm.String()+"-"+value; got != want {
				t.Errorf("Checksum = %q, want %q", got, want)
			}
		})
	}
}

func TestParseHexWeakDigestLength(t *testing.T) {
	for algorithm, value := range map[Algorithm]string{
		MD5:  checksumHex(SHA1, "hello"),
		SHA1: checksumHex(MD5, "hello"),
	} {
		if _, err := ParseHex(algorithm, value); err == nil {
			t.Errorf("ParseHex(%s, %d hex characters) succeeded, want a length error", algorithm, len(value))
		}
	}
}

func TestParseChecksum(t *testing.T) {
	for _, algorithm := range allAlgorithms {
		t.Run(algorithm.String(), func(t *testing.T) {
			value := checksumHex(algorithm, "hello")
			canonical := algorithm.String() + "-" + value
			for _, input := range []string{
				canonical,
				algorithm.String() + ":" + value,
				strings.ToUpper(algorithm.String()) + "-" + strings.ToUpper(value),
				" " + canonical + "\n",
			} {
				digest, err := ParseChecksum(input)
				if err != nil {
					t.Fatalf("ParseChecksum(%q): %v", input, err)
				}
				if digest.Algorithm() != algorithm || digest.Checksum() != canonical {
					t.Errorf("ParseChecksum(%q) = %s, want %s", input, digest.Checksum(), canonical)
				}
			}
		})
	}
}

func TestParseChecksumRejectsMalformedValues(t *testing.T) {
	sha1Hex := checksumHex(SHA1, "hello")
	for _, value := range []string{
		"",
		sha1Hex,
		"sha1-",
		"sha1-" + sha1Hex[:len(sha1Hex)-2],
		"sha1-" + sha1Hex + "00",
		"sha1-" + strings.Repeat("zz", len(sha1Hex)/2),
		"sha1-" + base64.StdEncoding.EncodeToString(weakDigestBytes(SHA1, "hello")),
		"crc32-00000000",
		"sha1-" + sha1Hex + " sha1-" + sha1Hex,
	} {
		if _, err := ParseChecksum(value); err == nil {
			t.Errorf("ParseChecksum(%q) succeeded, want an error", value)
		}
	}
}

// TestParseSRIRejectsWeakAlgorithms keeps MD5 and SHA-1 out of SRI, even as
// valid base64 digests of the right length.
func TestParseSRIRejectsWeakAlgorithms(t *testing.T) {
	for _, algorithm := range []Algorithm{MD5, SHA1} {
		entry := algorithm.String() + "-" + base64.StdEncoding.EncodeToString(weakDigestBytes(algorithm, "hello"))
		for _, value := range []string{entry, sriEntry(SHA512, "hello") + " " + entry} {
			if _, err := ParseSRI(value); err == nil {
				t.Errorf("ParseSRI(%q) succeeded, want an error", value)
			}
		}
	}
}

func TestWeakDigestsHaveNoSRIEncoding(t *testing.T) {
	sha1Digest, err := ParseHex(SHA1, checksumHex(SHA1, "hello"))
	if err != nil {
		t.Fatal(err)
	}
	if got := sha1Digest.SRI(); got != "" {
		t.Errorf("SHA-1 SRI = %q, want none", got)
	}
	strong, err := ParseSRI(sriEntry(SHA256, "hello"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := FormatSRI(append(SRI{sha1Digest}, strong...)), sriEntry(SHA256, "hello"); got != want {
		t.Errorf("FormatSRI = %q, want only the SRI entry %q", got, want)
	}
}

func TestReaderCalculatesWeakAlgorithms(t *testing.T) {
	result := readResult(t, "hello", MD5, SHA1, SHA256)
	if len(result.Digests) != 3 {
		t.Fatalf("calculated %d digests, want 3", len(result.Digests))
	}
	for _, digest := range result.Digests {
		if got, want := digest.Hex(), checksumHex(digest.Algorithm(), "hello"); got != want {
			t.Errorf("%s = %s, want %s", digest.Algorithm(), got, want)
		}
	}
}

func TestResultVerifyDigest(t *testing.T) {
	for _, algorithm := range allAlgorithms {
		t.Run(algorithm.String(), func(t *testing.T) {
			matching, err := ParseHex(algorithm, checksumHex(algorithm, "hello"))
			if err != nil {
				t.Fatal(err)
			}
			other, err := ParseHex(algorithm, checksumHex(algorithm, "other"))
			if err != nil {
				t.Fatal(err)
			}

			result := readResult(t, "hello", algorithm)
			if err := result.VerifyDigest(matching); err != nil {
				t.Errorf("matching digest: %v", err)
			}
			if err := result.VerifyDigest(other); err == nil {
				t.Error("mismatched digest verified")
			}
		})
	}
}

func TestResultVerifyDigestRequiresCompleteStream(t *testing.T) {
	for _, algorithm := range []Algorithm{MD5, SHA1} {
		reader, err := NewReader(strings.NewReader("hello"), algorithm)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reader.Read(make([]byte, 2)); err != nil {
			t.Fatal(err)
		}
		expected, err := ParseHex(algorithm, checksumHex(algorithm, "hello"))
		if err != nil {
			t.Fatal(err)
		}
		var incomplete *ErrIncomplete
		if err := reader.Result().VerifyDigest(expected); !errors.As(err, &incomplete) {
			t.Errorf("%s: VerifyDigest after a partial read = %v, want ErrIncomplete", algorithm, err)
		}
	}
}

func TestResultVerifyDigestRequiresCalculatedAlgorithm(t *testing.T) {
	expected, err := ParseHex(SHA1, checksumHex(SHA1, "hello"))
	if err != nil {
		t.Fatal(err)
	}
	if err := readResult(t, "hello", SHA256).VerifyDigest(expected); err == nil {
		t.Error("verified a SHA-1 digest that was not calculated")
	}
	if err := readResult(t, "hello", SHA256).VerifyDigest(Digest{}); err == nil {
		t.Error("verified the zero Digest")
	}
}

// TestResultVerifyRejectsWeakDigests keeps SRI verification to SRI
// algorithms, even when a weak digest is put into an SRI list by hand.
func TestResultVerifyRejectsWeakDigests(t *testing.T) {
	sha1Digest, err := ParseHex(SHA1, checksumHex(SHA1, "hello"))
	if err != nil {
		t.Fatal(err)
	}
	strong, err := ParseSRI(sriEntry(SHA256, "hello"))
	if err != nil {
		t.Fatal(err)
	}
	result := readResult(t, "hello", SHA1, SHA256)
	if err := result.Verify(SRI{sha1Digest}); err == nil {
		t.Error("Verify accepted a SHA-1 digest as SRI")
	}
	if err := result.Verify(append(SRI{sha1Digest}, strong...)); err == nil {
		t.Error("Verify accepted an SRI list holding a SHA-1 digest")
	}
}

// TestAlgorithmStrength checks the ranking SRI verification picks the
// strongest algorithm by, which does not follow the order of the constants.
func TestAlgorithmStrength(t *testing.T) {
	for i := 1; i < len(allAlgorithms); i++ {
		weaker, stronger := allAlgorithms[i-1], allAlgorithms[i]
		if weaker.strength() >= stronger.strength() {
			t.Errorf("%s ranks %d, not below %s at %d", weaker, weaker.strength(), stronger, stronger.strength())
		}
	}
}
