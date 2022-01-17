// Package cipher implements some utilities for encryption at rest.
package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// AES encodes data using AES block cipher.
//
// Block encryption is used for as much data as is available with
// stream encryption used for any left over data.
type AES []byte

// Encode encrypts the data and returns the encrypted data.
//
// If dst is provided and has sufficient space, it is used (src and dst can be
// same but overlaps will cause problems).
//
// This returned result is the same size as the unencrypted data.
func (key AES) Encode(dst, src []byte) ([]byte, error) {
	if len(dst) < len(src) {
		dst = make([]byte, len(src))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	d, s := dst, src
	for len(s) >= blockSize {
		block.Encrypt(d, s)
		d, s = d[blockSize:], s[blockSize:]
	}

	if len(s) > 0 {
		cipher.NewCTR(block, make([]byte, blockSize)).XORKeyStream(d, s)
	}

	return dst, nil
}

// Decode decrypts data.
func (key AES) Decode(dst, src []byte) ([]byte, error) {
	if len(dst) < len(src) {
		dst = make([]byte, len(src))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	d, s := dst, src
	for len(s) >= blockSize {
		block.Decrypt(d, s)
		d, s = d[blockSize:], s[blockSize:]
	}

	if len(s) > 0 {
		cipher.NewCTR(block, make([]byte, blockSize)).XORKeyStream(d, s)
	}

	return dst, nil
}

// AESStream uses AES in counter mode to encode the input.
// If nonce is not provided, a all-zeros byte array is used as the nonce.
type AESStream struct {
	Key   []byte
	Nonce []byte
}

// Encode encrypts the src into dst (if one is provided) and returns the
// encrypted data.
//
// src and dst can be the same (but overlaps are not allowed).  The size of
// encrypted data is same as the size of the input.
func (key AESStream) Encode(dst, src []byte) ([]byte, error) {
	if len(dst) < len(src) {
		dst = make([]byte, len(src))
	}

	block, err := aes.NewCipher(key.Key)
	if err != nil {
		return nil, err
	}

	nonce := key.Nonce
	if len(nonce) == 0 {
		nonce = make([]byte, block.BlockSize())
	}

	cipher.NewCTR(block, nonce).XORKeyStream(dst, src)
	return dst, nil
}

// Decode decrypts the src into dst (if one is provided) and returns
// the decrypted data.
func (key AESStream) Decode(dst, src []byte) ([]byte, error) {
	return key.Encode(dst, src)
}

// AESKeyWrap uses a random key for encoding the payload, with the random key
// itself encoded using the provided codec.
type AESKeyWrap struct {
	Codec interface {
		Encode(dst, src []byte) ([]byte, error)
		Decode(dst, src []byte) ([]byte, error)
	}
	KeySize int
}

// Encode encrypts src into dst (if one is provided) returns the encrypted data.
//
// The encryption process starts with creating a random AES key and encrypting
// the input data with this in counter mode.  The random key is itself encrypted
// using the provided codec.  The result is a concatenation of the encrypted key
// and the encrypted payload.
//
// Note that the encrypted result will include the encrypted key and so will not
// be the same size as the input.
func (wrap *AESKeyWrap) Encode(dst, src []byte) ([]byte, error) {
	key := make([]byte, wrap.KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	if len(dst) < len(src)+wrap.KeySize {
		dst = make([]byte, len(src)+wrap.KeySize)
	}
	dst, err := (&AESStream{Key: key}).Encode(dst, src)
	if err != nil {
		return nil, err
	}

	d2, err := wrap.Codec.Encode(dst[len(src):], key)
	if err != nil {
		return nil, err
	}
	if len(d2) != len(key) {
		return nil, fmt.Errorf("unexpected encrypted key length %d", len(d2))
	}
	return dst, nil
}

// SecretKey takes a text, sanitizes it and constructs an AES key.
//
// This is a deterministic process.
func SecretKey(s string) AES {
	s = regexp.MustCompile("[^a-z0-9]").ReplaceAllString(strings.ToLower(s), "")
	sum := sha256.Sum256([]byte(s))
	return AES(sum[:])
}

// Decode decrypts src into dst (if one is provided), returning the decrypted data.
//
// This reverses the behavior of Encode.
func (wrap *AESKeyWrap) Decode(dst, src []byte) ([]byte, error) {
	srclen := len(src)
	if srclen < wrap.KeySize {
		return nil, errors.New("invalid encrypted payload size")
	}
	key, src := src[srclen-wrap.KeySize:], src[:srclen-wrap.KeySize]
	if len(dst) < len(src) {
		dst = make([]byte, len(src))
	} else {
		dst = dst[:len(src)]
	}

	key, err := wrap.Codec.Decode(key, key)
	if err != nil {
		return nil, err
	}

	return (&AESStream{Key: key}).Decode(dst, src)
}

// Files implements encoding/decoding of files.
//
// It takes the Codec (for encrypting/decrypting) as a parameter.
type Files struct {
	// FileName is an optional paramter that decides the file name
	// to be saved.  This will be the filename that an encrypted file
	// will be restored to.
	// The default is to hash the file contents so that two files with
	// the same content will end up with the same name.
	//
	// Note that the name of the encrypted file is always based on
	// the content and is not configurable.
	FileName func(path string, data []byte) []byte

	// Codec is the encryption/decryption mechanism.
	Codec interface {
		Encode(dst, src []byte) ([]byte, error)
		Decode(dst, src []byte) ([]byte, error)
	}
}

// Encode encrypts the file(s) indicated by the pattern.
//
// The encrypted files are named using the hash of the contents and suffixed
// with .enc.  The raw source files are removed after encryption.
//
// The file name is transformed with the FileName function (if provided) and
// stored.  This is used when restoring.  The default file name is a hash of
// the contents.
//
// This skips over any files matching the skip pattern.
func (f Files) Encode(pattern, skip string) error {
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return err
	}

	var first error
	for _, path := range paths {
		if matched, err := filepath.Match(skip, path); matched || err != nil {
			continue
		}

		if err = f.encodeOne(path); err != nil {
			first = err
		}
	}
	return first
}

// Decode decrypts the files(s) indicated by the pattern.
//
// The decrypted fiels are named based on the name stored in the file during
// the encryption process.  The encrypted file is removed afterwards.
func (f Files) Decode(pattern, skip string) error {
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return err
	}

	var first error
	for _, path := range paths {
		if matched, err := filepath.Match(skip, path); matched || err != nil {
			continue
		}

		if err = f.decodeOne(path); err != nil {
			first = err
		}
	}
	return first
}

func (f Files) fileName(path string, data []byte) []byte {
	if path != "" && f.FileName != nil {
		return f.FileName(path, data)
	}

	sum := sha256.Sum256([]byte(data))
	return sum[:]
}

func (f Files) encodeOne(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	data = append(data, '=')
	data = append(data, []byte(hex.EncodeToString(f.fileName(path, data)))...)
	encrypted, err := f.Codec.Encode(nil, data)
	if err != nil {
		return err
	}

	fName := base64.RawURLEncoding.EncodeToString(f.fileName("", data)) + ".enc"
	fName = filepath.Join(filepath.Dir(path), fName)
	if err = os.WriteFile(fName, encrypted, 0666); err != nil {
		return err
	}

	os.Remove(path)
	return nil
}

func (f Files) decodeOne(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	data, err = f.Codec.Decode(data, data)
	if err != nil {
		return err
	}

	equals := strings.LastIndex(string(data), "=")
	if equals < 0 {
		return errors.New("corrupt data: " + path)
	}

	fNameBytes, err := hex.DecodeString(string(data[equals+1:]))
	if err != nil {
		return err
	}

	fName := filepath.Join(filepath.Dir(path), base64.RawURLEncoding.EncodeToString(fNameBytes))
	if err = os.WriteFile(fName, data[:equals], 0666); err != nil {
		return err
	}

	os.Remove(path)
	return nil
}
