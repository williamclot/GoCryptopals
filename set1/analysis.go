package set1

import (
	"encoding/hex"
	"fmt"
	"log"
	"math"
)

// Challenge 3: scoring function (could be improved with frequency analysis)
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

// Challenge 5: Feed in a list of bytes and it will return the line most likely to have been byte XORed
func DetectSingleByteXOR(lines [][]byte) ([]byte, byte) {
	bestScore, bestKey, bestPlainText := 0, byte(0), []byte(nil)

	for i := 0; i < len(lines); i++ {
		encrypted_data, err := hex.DecodeString(string(lines[i]))
		if err != nil {
			log.Fatal(err)
		}
		decrypted_data, key, score := SingleByteXORDecipher(encrypted_data)

		if score > bestScore {
			bestScore = score
			bestKey = key
			bestPlainText = decrypted_data
		}
	}

	return bestPlainText, bestKey
}

// Challenge 6
func FindKeySize(ciphertext []byte) (int, error) {
	bestKeySize := 0
	bestDistance := math.MaxFloat64
	minSize, maxSize := 2, 40

	blocks := len(ciphertext) / maxSize

	for keySize := minSize; keySize < maxSize; keySize++ {
		distance := 0.0
		for i := 0; i < blocks; i++ {

			firstBytes := ciphertext[i*keySize : (i+1)*keySize]
			secondBytes := ciphertext[(i+1)*keySize : (i+2)*keySize]

			currentDistance, err := HammingDistance(firstBytes, secondBytes)
			if err != nil {
				return 0, err
			}
			distance += float64(currentDistance) / float64(keySize)
		}

		fmt.Printf("size: %2d bits: %4.2f\n", keySize, distance)

		if distance < bestDistance {
			bestDistance = distance
			bestKeySize = keySize
		}
	}
	fmt.Printf("best key size: %2d %4.2f\n", bestKeySize, bestDistance)
	return bestKeySize, nil
}
