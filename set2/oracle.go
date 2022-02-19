package set2

import (
	"bytes"
	"cryptopals/set1"
	"math/rand"
)

func OracleEncrypt(input []byte) ([]byte, string) {
	// Random 16 byte key
	key := make([]byte, 16)
	rand.Read(key)

	// Random 5-10 byte padding
	padding := make([]byte, rand.Intn(5)+5)
	rand.Read(padding)
	input = append(padding, input...)
	input = append(input, padding...)

	// ECB or CBC?
	if rand.Intn(2) == 0 {
		padded := PKCS7(input, 16)
		return set1.AESECBEncrypt(padded, key), "ECB"
	} else {
		iv := make([]byte, 16)
		rand.Read(iv)
		return AESCBCEncrypt(input, key, iv), "CBC"
	}
}

func GuessBlockCipher(input []byte) string {
	blocks := make([][]byte, len(input)/16)

	// Dividing ciphertext into blocks of 16 bytes
	for i := 0; i < len(input)/16; i++ {
		blocks[i] = input[i*16 : (i+1)*16]
	}

	for _, block := range blocks {
		// if an identical block can be found more than once
		// within the ciphertext than it's probably ECB
		if bytes.Count(input, block) > 1 {
			return "ECB"
		}
	}

	return "CBC"
}
