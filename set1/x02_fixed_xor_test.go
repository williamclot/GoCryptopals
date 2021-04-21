package set1

import (
	"bytes"
	"encoding/hex"
	"log"
	"testing"
)

func TestFixedXOR(t *testing.T) {
	t.Run("Normal usage", func(t *testing.T) {

		left, err := hex.DecodeString("1c0111001f010100061a024b53535009181c")
    if err != nil { log.Fatal(err) }

		right, err := hex.DecodeString("686974207468652062756c6c277320657965")
    if err != nil { log.Fatal(err) }
		
		expected, err := hex.DecodeString("746865206b696420646f6e277420706c6179")
		if err != nil { log.Fatal(err) }

		got, err := FixedXOR(left, right)

		if !bytes.Equal(got, expected) || err != nil {
			t.Errorf("Got: %s, Expected: %s", got, expected)
		}
	})
	t.Run("Different slices length", func(t *testing.T) {
		left := []byte("fefefe")
		right := []byte("fefe")
		
		got, err := FixedXOR(left, right)
		
		if !bytes.Equal([]byte(nil), got) || err == nil {
			t.Errorf("Expecting an error")
		}
	})
}