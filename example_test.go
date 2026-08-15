package integrity_test

import (
	"fmt"
	"io"
	"strings"

	"github.com/git-pkgs/integrity"
)

func ExampleParseSRI() {
	metadata, err := integrity.ParseSRI("sha256-LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=")
	if err != nil {
		panic(err)
	}

	fmt.Println(metadata[0].Algorithm())
	fmt.Println(metadata[0].Hex())
	// Output:
	// sha256
	// 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
}

func ExampleReader() {
	expected, err := integrity.ParseSRI("sha256-LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=")
	if err != nil {
		panic(err)
	}
	reader, err := integrity.NewReader(strings.NewReader("hello"), integrity.SHA256)
	if err != nil {
		panic(err)
	}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		panic(err)
	}

	result := reader.Result()
	fmt.Println(result.Bytes, result.Complete)
	fmt.Println(result.Verify(expected) == nil)
	// Output:
	// 5 true
	// true
}
