package set2

import (
	"bytes"
	"cryptopals/set1"
	"encoding/base64"
	"math/rand"
	"strings"
)

type ECBEncryption struct {
	key     []byte
	unknown []byte
}

func NewEncryptor() *ECBEncryption {
	// random key
	key := make([]byte, 16)
	rand.Read(key)

	// init unknown string once
	unknown, err := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	if err != nil {
		panic(err)
	}
	return &ECBEncryption{
		key:     key,
		unknown: unknown,
	}
}

func (e *ECBEncryption) Encrypt(input []byte) []byte {
	input = append(input, e.unknown...)
	padded := PKCS7(input, len(e.key))
	return set1.AESECBEncrypt(padded, e.key)
}

func (e *ECBEncryption) KeySize() int {
	baseLength := 0
	sizeChanges := []int{} // we need the ciphertext size to change three times

	for i := 1; i < 100; i++ {
		cipherText := e.Encrypt([]byte(strings.Repeat("A", i)))
		if len(cipherText) != baseLength {
			if len(sizeChanges) == 3 {
				return sizeChanges[2] - sizeChanges[1]
			}
			sizeChanges = append(sizeChanges, i)
			baseLength = len(cipherText)
		}
	}
	return baseLength
}

func (e *ECBEncryption) BruteForceSingleByte() []byte {

	// block length of unknown ciphertext
	unknownSize := len(e.Encrypt([]byte{}))
	blockSize := len(e.key)
	unknowBlockCount := int(unknownSize / blockSize)

	// Placeholder for decrypted unknown value
	unknown := make([]byte, 0, unknownSize)

	for block := 0; block < unknowBlockCount; block++ {

		// Looping over each byte position in the block
		for pos := 0; pos < blockSize; pos++ {
			inputReference := bytes.Repeat([]byte{byte('A')}, blockSize-pos-1)
			cipherTextReference := e.Encrypt(inputReference)

			// Iterate over all posibilities to guess byte value
			for x := byte(0); x <= byte(255); x++ {
				input := append(inputReference, unknown...)
				cipherText := e.Encrypt(append(input, x))

				if bytes.Equal(cipherText[block:blockSize*(block+1)], cipherTextReference[block:blockSize*(block+1)]) {
					unknown = append(unknown, x)
					break
				}

				if x == byte(255) {
					return unknown[:len(unknown)-1]
				}
			}
		}
	}

	return unknown
}
