package integrity

import (
	"fmt"
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
)

const (
	sha256Size = 32
	sha384Size = 48
	sha512Size = 64
)

// String returns the lower-case SRI name for the algorithm.
func (a Algorithm) String() string {
	switch a {
	case SHA256:
		return "sha256"
	case SHA384:
		return "sha384"
	case SHA512:
		return "sha512"
	default:
		return "Algorithm(" + strconv.FormatUint(uint64(a), 10) + ")"
	}
}

func parseAlgorithm(value string) (Algorithm, error) {
	switch strings.ToLower(value) {
	case "sha256":
		return SHA256, nil
	case "sha384":
		return SHA384, nil
	case "sha512":
		return SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported algorithm %q", value)
	}
}

func digestSize(algorithm Algorithm) (int, error) {
	switch algorithm {
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
