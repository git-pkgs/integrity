package integrity

import "testing"

func FuzzParseSRI(f *testing.F) {
	f.Add("")
	f.Add("-")
	f.Add("sha384")
	f.Add(sriEntry(SHA256, "hello"))
	f.Add(sriEntry(SHA384, "hello"))
	f.Add(sriEntry(SHA512, "hello"))
	f.Add(sriEntry(SHA256, "one") + " " + sriEntry(SHA512, "two"))
	f.Add("SHA384-" + sriEntry(SHA384, "mixed case")[len("sha384-"):])
	f.Add("sha384-!!!!")
	f.Add("md5-1B2M2Y8AsgTpgAmY7PhCfg==")

	f.Fuzz(func(t *testing.T, value string) {
		_, _ = ParseSRI(value)
	})
}

func FuzzSRIRoundTrip(f *testing.F) {
	f.Add(sriEntry(SHA256, "hello"))
	f.Add(sriEntry(SHA384, "hello"))
	f.Add(sriEntry(SHA512, "hello"))
	f.Add(sriEntry(SHA512, "first") + " " + sriEntry(SHA512, "alternative"))
	f.Add(sriEntry(SHA256, "one") + "\t" + sriEntry(SHA384, "two") + "\n" + sriEntry(SHA512, "three"))

	f.Fuzz(func(t *testing.T, value string) {
		first, err := ParseSRI(value)
		if err != nil {
			return
		}
		second, err := ParseSRI(FormatSRI(first))
		if err != nil {
			t.Fatalf("ParseSRI accepted %q but rejected its canonical form: %v", value, err)
		}
		if len(first) != len(second) {
			t.Fatalf("round trip changed digest count from %d to %d", len(first), len(second))
		}
		for i := range first {
			if first[i].Algorithm() != second[i].Algorithm() || !first[i].Equal(second[i]) {
				t.Fatalf("round trip changed digest %d", i)
			}
		}
	})
}

func FuzzParseChecksum(f *testing.F) {
	f.Add("")
	f.Add("sha1-")
	f.Add("md5-" + checksumHex(MD5, "hello"))
	f.Add("sha1:" + checksumHex(SHA1, "hello"))
	f.Add("SHA512-" + checksumHex(SHA512, "hello"))
	f.Add("sha256-" + checksumHex(SHA256, "hello") + " extra")

	f.Fuzz(func(t *testing.T, value string) {
		digest, err := ParseChecksum(value)
		if err != nil {
			return
		}
		again, err := ParseChecksum(digest.Checksum())
		if err != nil {
			t.Fatalf("ParseChecksum accepted %q but rejected its canonical form: %v", value, err)
		}
		if !digest.Equal(again) {
			t.Fatalf("round trip of %q changed the digest", value)
		}
	})
}
