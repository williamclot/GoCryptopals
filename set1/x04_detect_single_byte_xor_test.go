package set1

import (
	"bytes"
	"io/ioutil"
	"log"
	"path/filepath"
	"testing"
)

func TestDetectSingleByteXOR(t *testing.T) {
	t.Run("Breaking example", func(t *testing.T) {
		filePath, err := filepath.Abs("../files/4.txt")
		if err != nil { log.Fatal(err) }
	
		fileBytes, err := ioutil.ReadFile(filePath)
		if err != nil { log.Fatal(err) }
	
		lines := bytes.Split(fileBytes, []byte("\n"))
		output, key := DetectSingleByteXOR(lines)

		expected, expected_key := "Now that the party is jumping\n", 0x35

		if string(output) != expected || int(key) != expected_key {
			t.Errorf("Got: %s %d, Expected: %s %d", output, key, expected, expected_key)
		}
	})
}