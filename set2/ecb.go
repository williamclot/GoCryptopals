package set2

import (
	"bytes"
	"cryptopals/set1"
	"cryptopals/utils"
	"encoding/base64"
	"math/rand"
	"strings"
)

// struct used in set2 for ECB encryption with unknown and prefix byte concatenation
type ConcatEncryptor struct {
	key     []byte
	unknown []byte
	prefix  []byte
}

func NewEncryptor() *ConcatEncryptor {
	// random key 256bit key
	key := make([]byte, 32)
	rand.Read(key)

	// init unknown string once
	unknown, err := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	if err != nil {
		panic(err)
	}

	// random prefix of random length
	prefix := make([]byte, rand.Intn(32))
	rand.Read(prefix)

	return &ConcatEncryptor{
		key:     key,
		unknown: unknown,
		prefix:  prefix,
	}
}

// Used in challenge 12
func (e *ConcatEncryptor) Encrypt(input []byte) []byte {
	input = append(input, e.unknown...)
	padded := PKCS7(input, len(e.key))
	return set1.AESECBEncrypt(padded, e.key)
}

// Used in challenge 14
func (e *ConcatEncryptor) EncryptWithPrefix(input []byte) []byte {
	input = append(e.prefix, input...)
	input = append(input, e.unknown...)
	padded := PKCS7(input, len(e.key))
	return set1.AESECBEncrypt(padded, e.key)
}

func (e *ConcatEncryptor) KeySize() int {
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

func (e *ConcatEncryptor) BruteForceSingleByte() []byte {

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
			inputReference := bytes.Repeat([]byte{'A'}, blockSize-pos-1)
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
			// iteration; we can return unknown and remove the last byte (which was a padding value)
			if len(unknown) != block*blockSize+pos+1 {
				return unknown[:len(unknown)-1]
			}
		}
	}

	return unknown
}

func (e *ConcatEncryptor) BruteForceSingleByteHarder() []byte {
	// This time around we've got an added random prefix of random length like so:
	// prefix || controlled || target

	blockSize := len(e.key)
	prefixLength := 0

	// First let's try and find the length of the random prefix
	for i := 0; i < blockSize; i++ {
		input := bytes.Repeat([]byte{'A'}, i)
		input = append(input, bytes.Repeat([]byte{'*'}, blockSize*2)...)

		cipher := e.EncryptWithPrefix(input)
		blocks, err := utils.BytesToBlocks(cipher, blockSize)
		if err != nil {
			panic(err)
		}

		if utils.ConsecutiveEqualBlocks(blocks) {
			prefixLength = blockSize - i
			break
		}
	}

	if prefixLength == 0 {
		panic("no prefix found")
	}

	// Now that we've got the prefix we can fill in the prefix blocks with a filling input prefix and
	// discard any of the prefix cipher blocks
	filler := bytes.Repeat([]byte{'A'}, blockSize-(prefixLength%blockSize))

	// block length and unknown size (with padding)
	unknownSize := len(e.EncryptWithPrefix(filler))
	unknowBlockCount := int(unknownSize / blockSize)

	// Placeholder for unknown value
	unknown := make([]byte, 0, unknownSize)
	unknown = append(unknown, filler...)

	// Looping over each block of unknown
	for block := 1; block < unknowBlockCount; block++ {

		// Looping over each byte position in the block
		for pos := 0; pos < blockSize; pos++ {
			inputReference := append(filler, bytes.Repeat([]byte{'A'}, blockSize-pos-1)...)
			cipherTextReference := e.EncryptWithPrefix(inputReference)

			// Iterate over all posibilities to guess byte value
			for x := 0; x <= 255; x++ {
				input := append(inputReference, unknown...)
				cipherText := e.EncryptWithPrefix(append(input, byte(x)))

				// if we've found a byte so that our block of cipher text matches the cipher text
				// reference than we've found an extra byte of unknown!
				if bytes.Equal(cipherText[block:blockSize*(block+1)], cipherTextReference[block:blockSize*(block+1)]) {
					unknown = append(unknown, byte(x))
					break
				}
			}

			// Our breakpoint: if no suitable byte is found after iterating through all possibilities,
			// then we've reached the padding of unknown and got a first padding value during the previous
			// iteration; we can return unknown and remove the last byte (which was a padding value)
			if len(unknown) != block*blockSize+pos+1 {
				return unknown[:len(unknown)-1]
			}
		}
	}

	return unknown
}
