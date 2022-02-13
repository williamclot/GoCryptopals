package set1

import (
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"log"
	"math"
)

// Challenge 7
func AESECBDecrypt(data, key []byte) []byte {
	keySize := len(key)
	cipher, _ := aes.NewCipher(key)

	for i := 0; i < len(data); i += keySize {
		cipher.Decrypt(data[i:i+keySize], data[i:i+keySize])
	}

	return data
}

func AESECBEncrypt(data, key []byte) []byte {
	keySize := len(key)
	cipher, _ := aes.NewCipher(key)

	for i := 0; i < len(data); i += keySize {
		cipher.Encrypt(data[i:i+keySize], data[i:i+keySize])
	}

	return data
}

// Challenge 8: Out of a list of bytes, returns the most likely bytes that have been encrypted using AES ECB
func DetectAESECB(lines [][]byte, blockSize int) []byte {
	bestDistance := math.MaxFloat64
	bestMatch := 0

	for l := 0; l < len(lines); l++ {
		data := lines[l]
		distance := 0.0

		for i := 0; i < len(data)/blockSize; i++ {
			for j := 0; j < len(data)/blockSize; j++ {
				if i != j {
					blockLeft := data[i*blockSize : (i+1)*blockSize]
					blockRight := data[j*blockSize : (j+1)*blockSize]

					d, err := HammingDistance(blockLeft, blockRight)
					if err != nil {
						log.Fatal(err)
					}
					distance += float64(d)
				}
			}
		}
		fmt.Printf("%s: %4.2f\n", hex.EncodeToString(lines[l])[0:5], distance)
		if distance < bestDistance {
			bestDistance = distance
			bestMatch = l
		}
	}
	fmt.Printf("best %s: %4.2f\n", hex.EncodeToString(lines[bestMatch])[0:5], bestDistance)
	return lines[bestMatch]
}
