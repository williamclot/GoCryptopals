package set2

import (
	"bytes"
	"errors"
)

// Challenge 1 PKCS#7 padding function
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

func RemovePKCS7(padded []byte, blockLength int) ([]byte, error) {

	if len(padded)%blockLength != 0 {
		return nil, errors.New("invalid pkcs7 padding")
	}

	lastByte := padded[len(padded)-1]
	paddingLength := 0

	// make sure the entire block isn't padding
	if bytes.Count(padded[len(padded)-blockLength:], []byte{lastByte}) == blockLength {
		return padded[:blockLength], nil
	}

	for i := len(padded) - 1; i >= 0; i-- {
		if padded[i] == lastByte {
			paddingLength++
		} else {
			break
		}
	}

	// verify padding value
	if int(lastByte) != paddingLength {
		return nil, errors.New("invalid pkcs7 padding")
	}

	return padded[:len(padded)-paddingLength], nil
}
