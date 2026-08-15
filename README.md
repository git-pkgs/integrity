# integrity

Parse Subresource Integrity metadata and verify package streams while they are read. The module supports SHA-256, SHA-384, and SHA-512 using only the Go standard library.

## Install

```bash
go get github.com/git-pkgs/integrity
```

## Parse and format SRI metadata

```go
metadata, err := integrity.ParseSRI(
	"sha256-LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=",
)
if err != nil {
	return err
}

fmt.Println(metadata[0].Algorithm())
fmt.Println(metadata[0].Hex())
fmt.Println(integrity.FormatSRI(metadata))
```

`ParseSRI` accepts surrounding whitespace, metadata lists containing more than one hash, and standard or URL-safe base64 with optional padding. It ignores options because SRI does not define any yet. `FormatSRI` emits lower-case algorithm names, padded standard base64, and one space between entries. `ParseHex` constructs a digest from the hexadecimal values commonly stored by package caches and SBOMs.

All constructors check the digest length for its algorithm. `Digest.Bytes` returns a copy, while `Digest.Hex` and `Digest.SRI` return canonical encodings.

## Verify a stream

```go
expected, err := integrity.ParseSRI(
	"sha512-19P5Un6URGs8lrxEAotLVa/3dYfU1acO+ddf//wkvY4vz/SLa8BPaKNTTOYu6gjBR5JW8NwZfAdsBMYNWiS41A==",
)
if err != nil {
	return err
}

defer response.Body.Close()

reader, err := integrity.NewReader(response.Body, integrity.SHA256, integrity.SHA512)
if err != nil {
	return err
}

temporary, err := os.CreateTemp(filepath.Dir(destinationPath), ".package-*")
if err != nil {
	return err
}
temporaryPath := temporary.Name()
defer os.Remove(temporaryPath)
defer temporary.Close()

if _, err := io.Copy(temporary, reader); err != nil {
	return err
}

result := reader.Result()
if err := result.Verify(expected); err != nil {
	return err
}
if err := temporary.Close(); err != nil {
	return err
}
if err := os.Rename(temporaryPath, destinationPath); err != nil {
	return err
}
fmt.Println(result.Bytes)
```

The reader calculates each requested algorithm once and counts every byte returned to the caller. A result becomes complete after the reader observes EOF. Verification before EOF returns `ErrIncomplete`, including when the source was closed after a partial read.

SRI verification uses the strongest supported algorithm in the metadata list. Any digest using that algorithm can match. A matching weaker digest does not replace a mismatch from a stronger algorithm.

The caller must close the source and keep copied bytes private until verification succeeds. Write cache entries to a temporary file or object, then commit them after `Verify` returns nil. Reporting failures and cache policy remain with the caller.

## Development

Run the tests and race detector:

```bash
go test -race ./...
```

Run the linters and vulnerability scan:

```bash
make lint
```

Run each fuzz target:

```bash
go test -fuzz=FuzzParseSRI -fuzztime=30s
go test -fuzz=FuzzSRIRoundTrip -fuzztime=30s
```

Run the benchmarks:

```bash
go test -run '^$' -bench . -benchmem
```

## License

MIT
