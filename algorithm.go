package integrity

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Algorithm identifies a supported digest algorithm.
type Algorithm uint8

const (
	// SHA256 identifies SHA-256 digests.
	SHA256 Algorithm = iota
	// SHA384 identifies SHA-384 digests.
	SHA384
	// SHA512 identifies SHA-512 digests.
	SHA512
	// MD5 identifies MD5 digests. It is a compatibility check for checksums a
	// publisher already supplied and is not a Subresource Integrity
	// algorithm. Do not choose it for new integrity metadata.
	MD5
	// SHA1 identifies SHA-1 digests. It is a compatibility check for
	// checksums a publisher already supplied and is not a Subresource
	// Integrity algorithm. Do not choose it for new integrity metadata.
	SHA1
)

const (
	md5Size    = 16
	sha1Size   = 20
	sha256Size = 32
	sha384Size = 48
	sha512Size = 64
)

// String returns the lower-case name for the algorithm, as SRI and
// algorithm-prefixed checksums spell it.
func (a Algorithm) String() string {
	switch a {
	case SHA256:
		return "sha256"
	case SHA384:
		return "sha384"
	case SHA512:
		return "sha512"
	case MD5:
		return "md5"
	case SHA1:
		return "sha1"
	default:
		return "Algorithm(" + strconv.FormatUint(uint64(a), 10) + ")"
	}
}

// sri reports whether the algorithm may appear in Subresource Integrity
// metadata.
func (a Algorithm) sri() bool {
	switch a {
	case SHA256, SHA384, SHA512:
		return true
	default:
		return false
	}
}

// byStrength lists the algorithms from weakest to strongest. SRI
// verification ranks by it to pick the strongest algorithm, rather than by
// the order of the constants, which reflects only when each was added.
var byStrength = []Algorithm{MD5, SHA1, SHA256, SHA384, SHA512}

// strength ranks an algorithm by its place in byStrength, from 1 for the
// weakest; it is 0 for an unsupported algorithm.
func (a Algorithm) strength() int {
	return slices.Index(byStrength, a) + 1
}

// parseAlgorithm parses any supported algorithm name.
func parseAlgorithm(value string) (Algorithm, error) {
	if len(value) > len("sha512") {
		return 0, fmt.Errorf("unsupported algorithm")
	}
	switch strings.ToLower(value) {
	case "sha256":
		return SHA256, nil
	case "sha384":
		return SHA384, nil
	case "sha512":
		return SHA512, nil
	case "md5":
		return MD5, nil
	case "sha1":
		return SHA1, nil
	default:
		return 0, fmt.Errorf("unsupported algorithm %q", value)
	}
}

// parseSRIAlgorithm parses the name of an algorithm SRI metadata may use.
func parseSRIAlgorithm(value string) (Algorithm, error) {
	algorithm, err := parseAlgorithm(value)
	if err != nil {
		return 0, err
	}
	if !algorithm.sri() {
		return 0, fmt.Errorf("%s is not a Subresource Integrity algorithm", algorithm)
	}
	return algorithm, nil
}

func digestSize(algorithm Algorithm) (int, error) {
	switch algorithm {
	case MD5:
		return md5Size, nil
	case SHA1:
		return sha1Size, nil
	case SHA256:
		return sha256Size, nil
	case SHA384:
		return sha384Size, nil
	case SHA512:
		return sha512Size, nil
	default:
		return 0, fmt.Errorf("unsupported algorithm %q", algorithm)
	}
}
