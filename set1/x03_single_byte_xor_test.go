package set1

import (
	"bytes"
	"encoding/hex"
	"log"
	"math/rand"
	"testing"
)

func TestScoreBytes(t *testing.T) {
	t.Run("Score calculation", func(t *testing.T) {
		candidate := []byte("my mummy is cool")
		
		got := ScoreBytes(candidate)
		expected := 7
		
		if got != expected {
			t.Errorf("Got: %d, Expected: %d", got, expected)
		}
	})
	t.Run("Null score calculation", func(t *testing.T) {
		candidate := []byte("mymymymmymy")
		
		got := ScoreBytes(candidate)
		expected := 0
		
		if got != expected {
			t.Errorf("Got: %d, Expected: %d", got, expected)
		}
	})
	t.Run("Score empty bytes", func(t *testing.T) {
		candidate := []byte(nil)
		
		got := ScoreBytes(candidate)
		expected := 0
		
		if got != expected {
			t.Errorf("Got: %d, Expected: %d", got, expected)
		}
	})
}

func TestSingleByteXOR(t *testing.T) {
	t.Run("Using the XOR twice should return input", func(t *testing.T) {
		payload := make([]byte, 16)
		key := byte(rand.Intn(255))

		result := SingleByteXOR(key, payload)
		result = SingleByteXOR(key, result)

		if !bytes.Equal(payload, result) {
			t.Errorf("Got: %s, Expected: %s", result, payload)
		}
	})
}

func TestBreakSingleByteXOR(t *testing.T) {
	t.Run("Breaking example", func(t *testing.T) {
		encrypted_data, err := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    if err != nil { log.Fatal(err) }

		decrypted_data, key, _ := BreakSingleByteXOR(encrypted_data)
		expected, expected_key := "Cooking MC's like a pound of bacon", 0x58

		if string(decrypted_data) != expected || int(key) != expected_key {
			t.Errorf("Got: %s %d, Expected: %s %d", decrypted_data, key, expected, expected_key)
		}
	})
}