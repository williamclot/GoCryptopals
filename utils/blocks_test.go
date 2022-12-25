package utils

import (
	"bytes"
	"testing"
)

func TestByteToBlocks(t *testing.T) {
	t.Run("normal usage", func(t *testing.T) {
		input := bytes.Repeat([]byte{'-'}, 64)
		blocks, err := BytesToBlocks(input, 16)
		expectedBlock := bytes.Repeat([]byte{'-'}, 16)

		if err != nil {
			t.Error(err)
		}
		if len(blocks) != 4 {
			t.Errorf("expected %d block but got %d", 4, len(blocks))
		}
		for _, b := range blocks {
			if !bytes.Equal(b, expectedBlock) {
				t.Errorf("unexpected block %v", b)
			}
		}
	})
}

func TestConsecutiveEqualBlocks(t *testing.T) {
	t.Run("normal usage", func(t *testing.T) {
		input := bytes.Repeat([]byte{'-'}, 64)
		blocks, err := BytesToBlocks(input, 16)

		if err != nil {
			t.Error(err)
		}
		if !ConsecutiveEqualBlocks(blocks) {
			t.Errorf("expected %d block but got %d", 4, len(blocks))
		}
	})
}
