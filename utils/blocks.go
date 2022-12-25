package utils

import (
	"bytes"
	"errors"
)

// cut a slice of bytes into blocks of bytes (aka returning a slice of slice of bytes)
// an error is returned if b isn't padded
func BytesToBlocks(b []byte, l int) ([][]byte, error) {
	if (len(b) % l) != 0 {
		return nil, errors.New("input isn't properly padded to block size")
	}
	blocks := make([][]byte, len(b)/l)
	for i := 0; i < len(b)/l; i++ {
		blocks[i] = b[i*l : (i+1)*l]
	}
	return blocks, nil
}

// returns true if two consecutive blocks in a cipher text have the same value
// this is particularly useful whenever working on ECB related tasks
func ConsecutiveEqualBlocks(blocks [][]byte) bool {
	for i := 0; i < len(blocks)-1; i++ {
		if bytes.Equal(blocks[i], blocks[i+1]) {
			return true
		}
	}
	return false
}
