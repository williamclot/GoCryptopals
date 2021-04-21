package set1

import "errors"

func FixedXOR(left, right []byte) ([]byte, error) {
	if len(left) != len(right) {
		return []byte(nil), errors.New("Byte slices should have same lenght")
	}

	result := make([]byte, len(left))

	for i := 0; i < len(left); i++ {
		result[i] = left[i] ^ right[i]
	}

	return result, nil
}