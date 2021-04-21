package set1

import (
	"log"
	"testing"
)

func TestHammingDistance(t *testing.T) {
	t.Run("Example check", func(t *testing.T) {
		byte1 := []byte("this is a test")
		byte2 := []byte("wokka wokka!!!")
	
		output, err := HammingDistance(byte1, byte2)
		if err != nil { log.Fatal(err) }
		expected := 37
		
		if output != expected {
			t.Errorf("Got: %d, Expected: %d", output, expected)
		}
	})
}