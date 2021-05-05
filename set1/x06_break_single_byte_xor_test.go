package set1

import (
	"bytes"
	"io/ioutil"
	"log"
	"path/filepath"
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

func TestFindKeySize(t *testing.T) {
	t.Run("Should find best key size", func(t *testing.T) {
		filePath, err := filepath.Abs("../files/6.txt")
		if err != nil { log.Fatal(err) }
	
		fileBytes, err := ioutil.ReadFile(filePath)
		if err != nil { log.Fatal(err) }
	
		lines := bytes.Split(fileBytes, []byte("\n"))
		output, key := DetectSingleByteXOR(lines)
	})
}