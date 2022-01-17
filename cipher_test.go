package cipher_test

import (
	"github.com/tvastar/cipher"

	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

type codec interface {
	Encode(dst, src []byte) ([]byte, error)
	Decode(dst, src []byte) ([]byte, error)
}

func ExampleSecretKey() {
	key1 := cipher.SecretKey("Alphonso Morales")
	key2 := cipher.SecretKey("Alphonso \n morales ????!!!!")
	if string(key1) != string(key2) {
		fmt.Println("Unexpected differences")
	}

	// Output:
}

func Example_main() {
	keys := map[string]codec{
		"AES": cipher.AES(hash("foo")),
		"AESStream": cipher.AESStream{
			Key:   randBytes(32),
			Nonce: randBytes(16),
		},
		"AESKeyWrap": &cipher.AESKeyWrap{
			Codec:   cipher.AES(hash("bar")),
			KeySize: 32,
		},
		"AESKeyWrapStream": &cipher.AESKeyWrap{
			Codec: &cipher.AESStream{
				Key:   randBytes(32),
				Nonce: randBytes(16),
			},
			KeySize: 32,
		},
	}

	for keyType, key := range keys {
		for size := 0; size < 3000; size++ {
			input := randBytes(size)
			output := append([]byte(nil), input...)
			encrypted, err := key.Encode(output, output)
			if err != nil {
				fmt.Printf("%s: encode error %v (%d bytes)", keyType, err, size)
				continue
			}
			decrypted, err := key.Decode(encrypted, encrypted)
			if err != nil {
				fmt.Printf("%s: decode error %v (%d bytes)", keyType, err, size)
				continue
			}
			if string(input) != string(decrypted) {
				fmt.Printf("%s: roundtrip failure (%d bytes)", keyType, size)
			}
		}
	}

	// Output:
}

func ExampleFiles() {
	f1, err1 := os.ReadFile("testdata/example.1")
	f2, err2 := os.ReadFile("testdata/example.2")
	defer os.RemoveAll("testdata/run")

	err3 := os.RemoveAll("testdata/run")
	err4 := os.MkdirAll("testdata/run", 0766)

	err5 := os.WriteFile("testdata/run/example.1", f1, 0666)
	err6 := os.WriteFile("testdata/run/example.2", f2, 0666)
	err7 := os.WriteFile("testdata/run/skipped", []byte("skipped"), 0666)

	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil || err6 != nil || err7 != nil {
		fmt.Println("testdata/example.1 error", err1, err2, err3, err4, err5, err6, err7)
		return
	}

	files := cipher.Files{
		Codec: &cipher.AESKeyWrap{
			Codec:   cipher.SecretKey("yo yo ma po"),
			KeySize: 32,
		},
	}
	err1 = files.Encode("testdata/run/*", "testdata/run/skip*")
	err2 = files.Decode("testdata/run/*", "testdata/run/skip*")

	if err1 != nil || err2 != nil {
		fmt.Println("Encode/Decode failure", err1, err2)
	}

	paths, err := filepath.Glob("testdata/run/*")
	if err != nil {
		fmt.Println("Error fetching paths", err)
	}

	sort.Strings(paths)
	for _, path := range paths {
		ff, err := os.ReadFile(path)
		fmt.Println(path, string(ff), err)
	}

	// Output:
	// testdata/run/J9dYcKXD-jHYuIxgjPLr_6dexengCKx51MNNLirbjoU This is example file 2 <nil>
	// testdata/run/rBkIEATg-SOyTzfFo27QWLUcW1Ut-NMp6sVPHJrzFVk This is example file 1 <nil>
	// testdata/run/skipped skipped <nil>
}

func hash(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

func randBytes(size int) []byte {
	if size == 0 {
		return []byte{}
	}
	result := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, result); err != nil {
		panic(err)
	}
	return result
}
