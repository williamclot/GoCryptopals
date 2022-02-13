package set2

import (
	"bytes"
	"testing"
)

func TestChallenge1(t *testing.T) {
	t.Run("padding", func(t *testing.T) {
		got := PKCS7([]byte("YELLOW SUBMARINE"), 20)
		expected := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")

		if !bytes.Equal(got, expected) {
			t.Errorf("got: %s, expected: %s", got, expected)
		}
	})
	t.Run("empty input", func(t *testing.T) {
		got := PKCS7(nil, 4)
		if got != nil {
			t.Error("expected an error")
		}
	})
}
