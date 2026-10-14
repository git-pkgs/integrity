// Package integrity parses Subresource Integrity metadata and verifies streams
// against cryptographic digests.
//
// It supports SHA-256, SHA-384, and SHA-512 without depending on HTTP,
// storage, or package-manager types. MD5 and SHA-1 are supported for
// verification only, to check checksums that registries already publish in
// those algorithms. They are never valid SRI and must not be chosen for new
// integrity metadata.
package integrity
