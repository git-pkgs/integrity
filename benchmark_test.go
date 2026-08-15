package integrity

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

const benchmarkSRI = "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="

func BenchmarkParseSRI(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_, _ = ParseSRI(benchmarkSRI)
	}
}

func BenchmarkParseSRIOversized(b *testing.B) {
	value := "sha256-" + strings.Repeat("A", 64*1024)
	b.ReportAllocs()
	b.SetBytes(int64(len(value)))
	for b.Loop() {
		_, _ = ParseSRI(value)
	}
}

func BenchmarkFormatSRI(b *testing.B) {
	parsed, err := ParseSRI(benchmarkSRI)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = FormatSRI(parsed)
	}
}

func BenchmarkReader(b *testing.B) {
	data := bytes.Repeat([]byte("package integrity benchmark data\n"), 2048)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		reader, err := NewReader(bytes.NewReader(data), SHA256, SHA384, SHA512)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, reader); err != nil {
			b.Fatal(err)
		}
		_ = reader.Result()
	}
}
