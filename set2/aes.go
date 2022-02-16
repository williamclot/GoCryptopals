package set2

import (
	"crypto/aes"
	"cryptopals/set1"
)

// Challenge 2
func AESCBCEncrypt(data, key, iv []byte) []byte {
	keySize := len(key)
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// Encrypting padded data
	padded := PKCS7(data, keySize)

	for i := 0; i < len(padded); i += keySize {
		var previousBlock, currentBlock []byte
		if i == 0 {
			previousBlock = iv // use IV if first block iteration
		} else {
			previousBlock = padded[i-keySize : i] // previous block
		}

		currentBlock = padded[i : i+keySize]

		xored, err := set1.XOR(previousBlock, currentBlock)
		if err != nil {
			panic(err)
		}
		cipher.Encrypt(padded[i:i+keySize], xored)
		if err != nil {
			panic(err)
		}
	}
	return padded
}

func AESCBCDecrypt(data, key, iv []byte) []byte {
	keySize := len(key)
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	for i := len(data); i >= keySize; i -= keySize {
		var previousBlock []byte
		if i == keySize {
			previousBlock = iv // use IV if last block iteration
		} else {
			previousBlock = data[i-2*keySize : i-keySize] // previous block
		}

		cipher.Decrypt(data[i-keySize:i], data[i-keySize:i])

		xored, err := set1.XOR(previousBlock, data[i-keySize:i])
		for k, v := range xored {
			data[i-keySize+k] = v
		}

		if err != nil {
			panic(err)
		}
		if err != nil {
			panic(err)
		}
	}
	return data
}
