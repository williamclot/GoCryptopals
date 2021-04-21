package set1

import "testing"

func TestHexToBase64(t *testing.T) {
	t.Run("Normal usage", func(t *testing.T) {
		got, err := HexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
		expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

		if got != expected || err != nil {
			t.Errorf("Got: %s, Expected: %s", got, expected)
		}
	})
	t.Run("Empty string", func(t *testing.T) {
		got, err := HexToBase64("")
		expected := ""

		if got != expected || err != nil {
			t.Errorf("Got: %s, Expected: %s", got, expected)
		}
	})
	t.Run("Invalid input", func(t *testing.T) {
		_, err := HexToBase64("notahex")

		if err == nil {
			t.Errorf("Expecting an error")
		}
	})
}
