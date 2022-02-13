package set1

import (
	"fmt"
)

// Challenge 3
func SingleByteXORDecipher(payload []byte) ([]byte, byte, int) {
	bestScore, bestKey, bestPlainText := 0, byte(0), []byte(nil)
	for key := 0; key < 256; key++ {
		decrypted := SingleByteXOR(byte(key), payload)
		score := ScoreBytes(decrypted)
		if score > bestScore {
			bestScore = score
			bestKey = byte(key)
			bestPlainText = decrypted
		}
	}
	return bestPlainText, bestKey, bestScore
}

// Challenge 6
func RepeatingKeyXORDecipher(cipherText []byte, keySize int) (string, string) {
	masterKey, decryptedText := "", make([]byte, len(cipherText))

	// Building the sub-blocks that will be used to break single-byte XOR
	for i := 0; i < keySize; i++ {
		length := len(cipherText) / keySize
		if i < (len(cipherText) % keySize) {
			length += 1
		}
		subBlocks := make([]byte, length)
		for j := 0; j < length; j++ {
			subBlocks[j] = cipherText[j*keySize+i]
		}
		decryptedBlock, key, _ := SingleByteXORDecipher(subBlocks)
		masterKey += string(key)
		for j := 0; j < length; j++ {
			decryptedText[j*keySize+i] = decryptedBlock[j]
		}
	}
	fmt.Printf("repeating key: %s\n", masterKey)
	fmt.Printf("decrypted message: %s\n", string(decryptedText))

	return masterKey, string(decryptedText)
}
