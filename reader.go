package integrity

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
)

type hashState struct {
	algorithm Algorithm
	hash      hash.Hash
}

// Reader calculates requested digests as bytes pass through it.
type Reader struct {
	source   io.Reader
	hashes   []hashState
	bytes    int64
	complete bool
}

// Result is a snapshot of a Reader's calculated digests and progress.
type Result struct {
	Digests  []Digest
	Bytes    int64
	Complete bool
}

// ErrIncomplete reports that verification was requested before the reader
// observed EOF.
type ErrIncomplete struct{}

// Error implements error.
func (*ErrIncomplete) Error() string {
	return "integrity verification requires a complete stream"
}

// NewReader returns a reader that calculates each requested algorithm once.
func NewReader(source io.Reader, algorithms ...Algorithm) (*Reader, error) {
	if source == nil {
		return nil, fmt.Errorf("new integrity reader: nil source")
	}

	reader := &Reader{source: source}
	seen := make(map[Algorithm]bool, len(algorithms))
	for _, algorithm := range algorithms {
		if seen[algorithm] {
			continue
		}
		seen[algorithm] = true

		var calculator hash.Hash
		switch algorithm {
		case SHA256:
			calculator = sha256.New()
		case SHA384:
			calculator = sha512.New384()
		case SHA512:
			calculator = sha512.New()
		default:
			return nil, fmt.Errorf("new integrity reader: unsupported algorithm %q", algorithm)
		}
		reader.hashes = append(reader.hashes, hashState{algorithm: algorithm, hash: calculator})
	}
	return reader, nil
}

// Read passes bytes from the source through each requested digest calculator.
func (r *Reader) Read(p []byte) (int, error) {
	if r.complete {
		return 0, io.EOF
	}
	n, err := r.source.Read(p)
	if n > 0 {
		r.bytes += int64(n)
		for i := range r.hashes {
			_, _ = r.hashes[i].hash.Write(p[:n])
		}
	}
	if err == io.EOF {
		r.complete = true
	}
	return n, err
}

// Result returns a snapshot. Calling Result does not finish or reset the
// reader.
func (r *Reader) Result() Result {
	result := Result{
		Digests:  make([]Digest, 0, len(r.hashes)),
		Bytes:    r.bytes,
		Complete: r.complete,
	}
	for _, state := range r.hashes {
		result.Digests = append(result.Digests, Digest{algorithm: state.algorithm, bytes: state.hash.Sum(nil)})
	}
	return result
}

// Verify applies the W3C SRI matching rule to a completed result. Only the
// strongest algorithm in expected is considered, and any digest using that
// algorithm may match.
func (r Result) Verify(expected SRI) error {
	if !r.Complete {
		return &ErrIncomplete{}
	}

	algorithm, err := strongestAlgorithm(expected)
	if err != nil {
		return err
	}

	expectedStrongest := make(SRI, 0, len(expected))
	for _, digest := range expected {
		if digest.Algorithm() == algorithm {
			expectedStrongest = append(expectedStrongest, digest)
		}
	}

	for _, calculated := range r.Digests {
		if calculated.Algorithm() != algorithm {
			continue
		}
		for _, digest := range expectedStrongest {
			if calculated.Equal(digest) {
				return nil
			}
		}
		return fmt.Errorf("integrity mismatch: expected %s, calculated %s", FormatSRI(expectedStrongest), calculated.SRI())
	}

	return fmt.Errorf("integrity mismatch: expected %s, calculated no %s digest", FormatSRI(expectedStrongest), algorithm)
}
