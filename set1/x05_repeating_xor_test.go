package set1

import (
	"bytes"
	"encoding/hex"
	"log"
	"testing"
)

func TestRepeatingXOR(t *testing.T) {
	t.Run("Example check", func(t *testing.T) {
		payload := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
		key := []byte("ICE")

		expected, err := hex.DecodeString(
			"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272" + 
			"a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
    if err != nil { log.Fatal(err) }

		output := RepeatingXOR(key, payload)
		if !bytes.Equal(expected, output) {
			t.Errorf("Got: %s, Expected: %s", hex.EncodeToString(output), hex.EncodeToString(expected))
		}
	})
}