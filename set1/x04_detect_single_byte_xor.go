package set1

import (
	"encoding/hex"
	"log"
)

// Feed in a list of bytes and it will return the line most likely to have been byte XORed
func DetectSingleByteXOR(lines [][]byte) ([]byte, byte) {
	bestScore, bestKey, bestPlainText := 0, byte(0), []byte(nil)

	for i := 0; i < len(lines); i++ {
		encrypted_data, err := hex.DecodeString(string(lines[i]))
    if err != nil { log.Fatal(err) }
		decrypted_data, key, score := BreakSingleByteXOR(encrypted_data)

		if score > bestScore {
			bestScore = score
			bestKey = key
			bestPlainText = decrypted_data
		}
	}

	return bestPlainText, bestKey
}