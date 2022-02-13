package set2

import "bytes"

// PKCS#7 padding function
func PKCS7(input []byte, blockLength int) []byte {
	if input == nil {
		return nil
	}

	if blockLength < 1 {
		return input
	}

	paddingLength := blockLength - (len(input) % blockLength)
	padding := bytes.Repeat([]byte{byte(paddingLength)}, paddingLength)

	return append(input, padding...)
}
