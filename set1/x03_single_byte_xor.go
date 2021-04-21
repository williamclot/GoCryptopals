package set1

// Scoring function (could be improved with frequency analysis)
func ScoreBytes(candidate []byte) int {
	score := 0
	frequentLetters := "etaoinhs "
	for i := 0; i < len(candidate); i++ {
		for j := 0; j < len(frequentLetters); j++ {
			if candidate[i] == frequentLetters[j] {
				score++
				break
			}
		}
	}
	return score
}

// XOR payload with byte key
func SingleByteXOR(key byte, payload []byte) []byte {
	result := make([]byte, len(payload))
	for i := 0; i < len(payload); i++ {
		result[i] = payload[i] ^ key
	}
	return result
}

// Find the best byte key to decrypt the payload
func BreakSingleByteXOR(payload []byte) ([]byte, byte, int) {
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