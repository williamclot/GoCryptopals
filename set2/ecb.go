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

	// block length and unknown size (with padding)
	unknownSize := len(e.Encrypt([]byte{}))
	blockSize := len(e.key)
	unknowBlockCount := int(unknownSize / blockSize)

	// Placeholder for unknown value
	unknown := make([]byte, 0, unknownSize)

	// Looping over each block of unknown
	for block := 0; block < unknowBlockCount; block++ {

		// Looping over each byte position in the block
		for pos := 0; pos < blockSize; pos++ {
			inputReference := bytes.Repeat([]byte{byte('A')}, blockSize-pos-1)
			cipherTextReference := e.Encrypt(inputReference)

			// Iterate over all posibilities to guess byte value
			for x := 0; x <= 255; x++ {
				input := append(inputReference, unknown...)
				cipherText := e.Encrypt(append(input, byte(x)))

				// if we've found a byte so that our block of cipher text matches the cipher text
				// reference than we've found an extra byte of unknown!
				if bytes.Equal(cipherText[block:blockSize*(block+1)], cipherTextReference[block:blockSize*(block+1)]) {
					unknown = append(unknown, byte(x))
					break
				}
			}

			// Our breakpoint: if no suitable byte is found after iterating through all possibilities,
			// then we've reached the padding of unknown and got a first padding value during the previous
			// iteration; we can return unknown and remove the last byte (which was a padding value).
			if len(unknown) != block*blockSize+pos+1 {
				return unknown[:len(unknown)-1]
			}
		}
	}

	return unknown
}
