package integrity

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// Digest is an immutable algorithm and digest-byte pair.
//
// Use ParseHex or ParseSRI to construct a Digest. Bytes returns a copy of the
// stored bytes.
type Digest struct {
	algorithm Algorithm
	bytes     []byte
}

func newDigest(algorithm Algorithm, raw []byte) (Digest, error) {
	want, err := digestSize(algorithm)
	if err != nil {
		return Digest{}, err
	}
	if len(raw) != want {
		return Digest{}, fmt.Errorf("%s digest has %d bytes, want %d", algorithm, len(raw), want)
	}
	return Digest{algorithm: algorithm, bytes: append([]byte(nil), raw...)}, nil
}

// ParseHex parses a hexadecimal digest for algorithm.
func ParseHex(algorithm Algorithm, value string) (Digest, error) {
	want, err := digestSize(algorithm)
	if err != nil {
		return Digest{}, fmt.Errorf("parse %s hex digest: %w", algorithm, err)
	}
	if len(value) != hex.EncodedLen(want) {
		return Digest{}, fmt.Errorf("parse %s hex digest: encoding has %d bytes, want %d", algorithm, len(value), hex.EncodedLen(want))
	}

	raw, err := hex.DecodeString(value)
	if err != nil {
		return Digest{}, fmt.Errorf("parse %s hex digest: %w", algorithm, err)
	}
	digest, err := newDigest(algorithm, raw)
	if err != nil {
		return Digest{}, fmt.Errorf("parse %s hex digest: %w", algorithm, err)
	}
	return digest, nil
}

// Algorithm returns the digest algorithm.
func (d Digest) Algorithm() Algorithm {
	return d.algorithm
}

// Bytes returns a copy of the raw digest bytes.
func (d Digest) Bytes() []byte {
	return append([]byte(nil), d.bytes...)
}

// Hex returns the canonical lower-case hexadecimal encoding.
func (d Digest) Hex() string {
	return hex.EncodeToString(d.bytes)
}

// SRI returns the canonical Subresource Integrity encoding.
func (d Digest) SRI() string {
	return d.algorithm.String() + "-" + base64.StdEncoding.EncodeToString(d.bytes)
}

// Equal reports whether two digests use the same algorithm and contain the
// same raw bytes. The byte comparison takes constant time for equal-length
// values.
func (d Digest) Equal(other Digest) bool {
	if d.algorithm != other.algorithm || len(d.bytes) != len(other.bytes) {
		return false
	}
	want, err := digestSize(d.algorithm)
	if err != nil || len(d.bytes) != want {
		return false
	}
	return subtle.ConstantTimeCompare(d.bytes, other.bytes) == 1
}
