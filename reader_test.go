package integrity

import (
	"errors"
	"io"
	"strings"
	"testing"
)

type chunkReader struct {
	source io.Reader
	max    int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(p) > r.max {
		p = p[:r.max]
	}
	return r.source.Read(p)
}

type finalBytesReader struct {
	done bool
}

func (r *finalBytesReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	return copy(p, "final"), io.EOF
}

var errReadFixture = errors.New("fixture read error")

type errorReader struct {
	done bool
}

func (r *errorReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, errReadFixture
	}
	r.done = true
	return copy(p, "part"), errReadFixture
}

type trackedReadCloser struct {
	reader io.Reader
	closed bool
}

func (r *trackedReadCloser) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func (r *trackedReadCloser) Close() error {
	r.closed = true
	return nil
}

func readResult(t *testing.T, value string, algorithms ...Algorithm) Result {
	t.Helper()
	reader, err := NewReader(strings.NewReader(value), algorithms...)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		t.Fatalf("read stream: %v", err)
	}
	return reader.Result()
}

func TestReaderEmptyStream(t *testing.T) {
	result := readResult(t, "", SHA256, SHA384, SHA512)
	if !result.Complete {
		t.Error("empty stream result is incomplete")
	}
	if result.Bytes != 0 {
		t.Errorf("Bytes = %d, want 0", result.Bytes)
	}
	if len(result.Digests) != 3 {
		t.Fatalf("Digests = %d, want 3", len(result.Digests))
	}
	for _, algorithm := range []Algorithm{SHA256, SHA384, SHA512} {
		expected, err := ParseSRI(sriEntry(algorithm, ""))
		if err != nil {
			t.Fatal(err)
		}
		if err := result.Verify(expected); err != nil {
			t.Errorf("Verify(%s): %v", algorithm, err)
		}
	}
}

func TestReaderChunkedReadsAndRepeatedResults(t *testing.T) {
	const data = "a stream split into small chunks"
	source := &chunkReader{source: strings.NewReader(data), max: 3}
	reader, err := NewReader(source, SHA512, SHA256, SHA512)
	if err != nil {
		t.Fatal(err)
	}

	buffer := make([]byte, 8)
	if _, err := reader.Read(buffer); err != nil {
		t.Fatalf("first Read: %v", err)
	}
	partial := reader.Result()
	if partial.Bytes != 3 || partial.Complete {
		t.Errorf("partial result = %+v, want 3 bytes and incomplete", partial)
	}
	if len(partial.Digests) != 2 {
		t.Errorf("duplicate algorithm was not removed: %d digests", len(partial.Digests))
	}

	if _, err := io.Copy(io.Discard, reader); err != nil {
		t.Fatal(err)
	}
	complete := reader.Result()
	again := reader.Result()
	if complete.Bytes != int64(len(data)) || !complete.Complete {
		t.Errorf("complete result = %+v", complete)
	}
	if len(complete.Digests) != 2 || !complete.Digests[0].Equal(again.Digests[0]) || !complete.Digests[1].Equal(again.Digests[1]) {
		t.Error("repeated Result calls changed the digest snapshot")
	}
}

func TestReaderIncludesFinalBytesReturnedWithEOF(t *testing.T) {
	reader, err := NewReader(&finalBytesReader{}, SHA256)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 16)
	n, err := reader.Read(buffer)
	if n != len("final") || err != io.EOF {
		t.Fatalf("Read = (%d, %v), want (%d, EOF)", n, err, len("final"))
	}
	result := reader.Result()
	if !result.Complete || result.Bytes != int64(len("final")) {
		t.Errorf("Result = %+v", result)
	}
	expected, parseErr := ParseSRI(sriEntry(SHA256, "final"))
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	if err := result.Verify(expected); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestReaderNonEOFErrorLeavesResultIncomplete(t *testing.T) {
	reader, err := NewReader(&errorReader{}, SHA256)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 16)
	n, err := reader.Read(buffer)
	if n != len("part") || !errors.Is(err, errReadFixture) {
		t.Fatalf("Read = (%d, %v), want (%d, fixture error)", n, err, len("part"))
	}
	result := reader.Result()
	if result.Complete || result.Bytes != int64(len("part")) {
		t.Errorf("Result = %+v", result)
	}
	expected, parseErr := ParseSRI(sriEntry(SHA256, "part"))
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	var incomplete *ErrIncomplete
	if err := result.Verify(expected); !errors.As(err, &incomplete) {
		t.Errorf("Verify error = %v, want ErrIncomplete", err)
	}
}

func TestEarlyCloseLeavesResultIncomplete(t *testing.T) {
	source := &trackedReadCloser{reader: strings.NewReader("partial stream")}
	reader, err := NewReader(source, SHA384)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4)
	if _, err := reader.Read(buffer); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if !source.closed {
		t.Error("source was not closed")
	}
	result := reader.Result()
	if result.Complete {
		t.Error("early close marked result complete")
	}
	expected, parseErr := ParseSRI(sriEntry(SHA384, "part"))
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	var incomplete *ErrIncomplete
	if err := result.Verify(expected); !errors.As(err, &incomplete) {
		t.Errorf("Verify error = %v, want ErrIncomplete", err)
	}
}

func TestResultVerifyUsesStrongestAlgorithm(t *testing.T) {
	result := readResult(t, "artifact", SHA256, SHA384, SHA512)
	tests := []struct {
		name    string
		entries string
		wantErr bool
	}{
		{
			name:    "weaker match cannot override stronger mismatch",
			entries: sriEntry(SHA256, "artifact") + " " + sriEntry(SHA512, "other"),
			wantErr: true,
		},
		{
			name:    "stronger match ignores weaker mismatch",
			entries: sriEntry(SHA256, "other") + " " + sriEntry(SHA512, "artifact"),
		},
		{
			name:    "same algorithm alternatives",
			entries: sriEntry(SHA512, "other") + " " + sriEntry(SHA512, "artifact"),
		},
		{
			name:    "mixed alternatives with strongest mismatch",
			entries: sriEntry(SHA384, "artifact") + " " + sriEntry(SHA512, "first") + " " + sriEntry(SHA512, "second"),
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expected, err := ParseSRI(test.entries)
			if err != nil {
				t.Fatal(err)
			}
			err = result.Verify(expected)
			if (err != nil) != test.wantErr {
				t.Fatalf("Verify error = %v, wantErr %v", err, test.wantErr)
			}
			if test.wantErr && (!strings.Contains(err.Error(), "expected sha512-") || !strings.Contains(err.Error(), "calculated sha512-")) {
				t.Errorf("mismatch error does not contain expected and calculated digests: %v", err)
			}
		})
	}
}

func TestReaderCalculatesContentHashWithDifferentNativeAlgorithm(t *testing.T) {
	result := readResult(t, "package bytes", SHA256, SHA512)
	contentHash, err := ParseHex(SHA256, sriHex(SHA256, "package bytes"))
	if err != nil {
		t.Fatal(err)
	}
	native, err := ParseSRI(sriEntry(SHA512, "package bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if err := result.Verify(SRI{contentHash}); err != nil {
		t.Errorf("content hash: %v", err)
	}
	if err := result.Verify(native); err != nil {
		t.Errorf("native integrity: %v", err)
	}
}

func TestResultVerifyRequiresCalculatedStrongestAlgorithm(t *testing.T) {
	result := readResult(t, "artifact", SHA256)
	expected, err := ParseSRI(sriEntry(SHA512, "artifact"))
	if err != nil {
		t.Fatal(err)
	}
	err = result.Verify(expected)
	if err == nil || !strings.Contains(err.Error(), "calculated no sha512 digest") {
		t.Errorf("Verify error = %v", err)
	}
}

func TestResultVerifyRejectsEmptyExpectedSet(t *testing.T) {
	result := readResult(t, "artifact", SHA256)
	if err := result.Verify(nil); err == nil {
		t.Fatal("Verify(nil) returned nil error")
	}
}

func TestNewReaderRejectsInvalidInput(t *testing.T) {
	if _, err := NewReader(nil, SHA256); err == nil {
		t.Error("NewReader(nil) returned nil error")
	}
	if _, err := NewReader(strings.NewReader(""), Algorithm(99)); err == nil {
		t.Error("NewReader with unsupported algorithm returned nil error")
	}
}

func sriHex(algorithm Algorithm, value string) string {
	digest, err := ParseSRI(sriEntry(algorithm, value))
	if err != nil {
		panic(err)
	}
	return digest[0].Hex()
}
