package set1

import (
	"errors"
)

// Challenge 2
func XOR(left, right []byte) ([]byte, error) {
	if len(left) != len(right) {
		return []byte(nil), errors.New("byte slices should have same lenght")
	}

	result := make([]byte, len(left))

	for i := 0; i < len(left); i++ {
		result[i] = left[i] ^ right[i]
	}

	return result, nil
}

// Challenge 3
func SingleByteXOR(key byte, payload []byte) []byte {
	result := make([]byte, len(payload))
	for i := 0; i < len(payload); i++ {
		result[i] = payload[i] ^ key
	}
	return result
}

// Challenge5
func RepeatingKeyXOR(key, payload []byte) []byte {
	output := make([]byte, len(payload))

	for i := 0; i < len(payload); i++ {
		output[i] = payload[i] ^ key[i%len(key)]
	}

	return output
}
