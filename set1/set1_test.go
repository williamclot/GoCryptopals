package set1

import (
	"bytes"
	"cryptopals/utils"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// Convert the given hex string to base64
func TestChallenge1(t *testing.T) {
	t.Run("Hex to base64", func(t *testing.T) {
		decoded, err := hex.DecodeString("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
		if err != nil {
			t.Errorf("expected no error but got: %s", err)
		}

		got := base64.StdEncoding.EncodeToString(decoded)
		expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

		if got != expected {
			t.Errorf("got: %s, expected: %s", got, expected)
		}
	})
}

// Write a function that takes two equal-length buffers and produces their XOR combination.
func TestChallenge2(t *testing.T) {
	t.Run("Normal usage", func(t *testing.T) {

		left, err := hex.DecodeString("1c0111001f010100061a024b53535009181c")
		if err != nil {
			t.Error(err)
		}

		right, err := hex.DecodeString("686974207468652062756c6c277320657965")
		if err != nil {
			t.Error(err)
		}

		expected, err := hex.DecodeString("746865206b696420646f6e277420706c6179")
		if err != nil {
			t.Error(err)
		}

		got, err := XOR(left, right)

		if !bytes.Equal(got, expected) || err != nil {
			t.Errorf("got: %s, expected: %s", got, expected)
		}
	})
	t.Run("Different slices length", func(t *testing.T) {
		left := []byte("fefefe")
		right := []byte("fefe")

		got, err := XOR(left, right)

		if !bytes.Equal([]byte(nil), got) || err == nil {
			t.Errorf("expecting an error")
		}
	})
}

// This hex encoded string has been XOR'd against a single character. Find the key, decrypt the message.
func TestChallenge3(t *testing.T) {
	// TestScoreBytes
	t.Run("Score calculation", func(t *testing.T) {
		candidate := []byte("my mummy is cool")

		got := ScoreBytes(candidate)
		expected := 7

		if got != expected {
			t.Errorf("got: %d, expected: %d", got, expected)
		}
	})
	t.Run("Null score calculation", func(t *testing.T) {
		candidate := []byte("mymymymmymy")

		got := ScoreBytes(candidate)
		expected := 0

		if got != expected {
			t.Errorf("got: %d, expected: %d", got, expected)
		}
	})
	t.Run("Score empty bytes", func(t *testing.T) {
		candidate := []byte(nil)

		got := ScoreBytes(candidate)
		expected := 0

		if got != expected {
			t.Errorf("got: %d, expected: %d", got, expected)
		}
	})

	// TestSingleByteXOR
	t.Run("Using the XOR twice should return input", func(t *testing.T) {
		payload := make([]byte, 16)
		key := byte(rand.Intn(255))

		result := SingleByteXOR(key, payload)
		result = SingleByteXOR(key, result)

		if !bytes.Equal(payload, result) {
			t.Errorf("got: %s, expected: %s", result, payload)
		}
	})

	// TestBreakSingleByteXOR
	t.Run("Breaking example", func(t *testing.T) {
		encrypted_data, err := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
		if err != nil {
			t.Error(err)
		}

		decrypted_data, key, _ := SingleByteXORDecipher(encrypted_data)
		expected, expected_key := "Cooking MC's like a pound of bacon", 0x58

		if string(decrypted_data) != expected || int(key) != expected_key {
			t.Errorf("got: %s %d, expected: %s %d", decrypted_data, key, expected, expected_key)
		}
	})
}

// One of the 60-character strings in this file has been encrypted by single-character XOR. Find it.
func TestChallenge4(t *testing.T) {
	t.Run("Breaking example", func(t *testing.T) {
		file, err := utils.GetFile("https://cryptopals.com/static/challenge-data/4.txt")
		if err != nil {
			t.Error(err)
		}

		lines := bytes.Split(file, []byte("\n"))
		output, key := DetectSingleByteXOR(lines)

		expected, expected_key := "Now that the party is jumping\n", 0x35

		if string(output) != expected || int(key) != expected_key {
			t.Errorf("got: %s %d, expected: %s %d", output, key, expected, expected_key)
		}
	})
}

// Implement repeating-key XOR
func TestChallenge5(t *testing.T) {
	t.Run("Example check", func(t *testing.T) {
		payload := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
		key := []byte("ICE")

		expected, err := hex.DecodeString(
			"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272" +
				"a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
		if err != nil {
			t.Error(err)
		}

		output := RepeatingKeyXOR(key, payload)
		if !bytes.Equal(expected, output) {
			t.Errorf("got: %s, expected: %s", hex.EncodeToString(output), hex.EncodeToString(expected))
		}
	})
}

// There's a file here. It's been base64'd after being encrypted with repeating-key XOR. Decrypt it.
func TestChallenge6(t *testing.T) {
	t.Run("Hamming distance", func(t *testing.T) {
		byte1 := []byte("this is a test")
		byte2 := []byte("wokka wokka!!!")

		output, err := HammingDistance(byte1, byte2)
		if err != nil {
			t.Error(err)
		}
		expected := 37

		if output != expected {
			t.Errorf("got: %d, expected: %d", output, expected)
		}
	})
	t.Run("Key size analysis", func(t *testing.T) {
		file, err := utils.GetFile("https://cryptopals.com/static/challenge-data/6.txt")
		if err != nil {
			t.Error(err)
		}

		encodedCiphertext := strings.Replace(string(file), "\n", "", -1)
		rawCiphertext, err := base64.StdEncoding.DecodeString(encodedCiphertext)
		if err != nil {
			t.Error(err)
		}

		keySize, err := FindKeySize(rawCiphertext)
		if err != nil {
			t.Error(err)
		}

		expected := 29

		if expected != keySize {
			t.Errorf("got: %d, expected: %d", keySize, expected)
		}
	})

	t.Run("Break Repeating key XOR", func(t *testing.T) {
		file, err := utils.GetFile("https://cryptopals.com/static/challenge-data/6.txt")
		if err != nil {
			t.Error(err)
		}

		encodedCiphertext := strings.Replace(string(file), "\n", "", -1)
		rawCiphertext, err := base64.StdEncoding.DecodeString(encodedCiphertext)
		if err != nil {
			t.Error(err)
		}
		keySize, err := FindKeySize(rawCiphertext)
		if err != nil {
			t.Error(err)
		}

		key, decryptedText := RepeatingKeyXORDecipher(rawCiphertext, keySize)
		expectedKey := "Terminator X: Bring the noise"

		if key != expectedKey {
			t.Errorf("got: %s, expected: %s", key, expectedKey)
		}

		if !strings.HasPrefix(decryptedText, "I'm back and I'm ringin' the bell") {
			t.Errorf("wrong decrypted message: %s", decryptedText)
		}
	})
}

// Decrypt the content of the file using AES-128 ECB (knowing the key)
func TestChallenge7(t *testing.T) {
	t.Run("Should decrypt the message normally", func(t *testing.T) {
		file, err := utils.GetFile("https://cryptopals.com/static/challenge-data/7.txt")
		if err != nil {
			t.Error(err)
		}

		encodedCiphertext := strings.Replace(string(file), "\n", "", -1)
		rawCiphertext, err := base64.StdEncoding.DecodeString(encodedCiphertext)
		if err != nil {
			t.Error(err)
		}
		key := []byte("YELLOW SUBMARINE")

		decryptedText := string(AESECBDecrypt(rawCiphertext, key))

		fmt.Println(len(rawCiphertext))

		if !strings.HasPrefix(decryptedText, "I'm back and I'm ringin' the bell") {
			t.Errorf("wrong decrypted message: %s", decryptedText)
		}
	})
	t.Run("Encrypt then decrypt should return original string", func(t *testing.T) {
		data := []byte("My name is william the conqueror")
		key := []byte("YELLOW SUBMARINE")

		encrypted := AESECBEncrypt(data, key)
		decrypted := AESECBDecrypt(encrypted, key)

		if string(data) != string(decrypted) {
			t.Errorf("wrong decrypted message: %s", string(decrypted))
		}
	})
}

func TestChallenge8(t *testing.T) {
	t.Run("Detect AES ECB 128bit from cryptopals", func(t *testing.T) {
		file, err := utils.GetFile("https://cryptopals.com/static/challenge-data/8.txt")
		if err != nil {
			t.Error(err)
		}

		lines := utils.RemoveEmptyStrings(strings.Split(string(file), "\n"))
		rawLines := make([][]byte, len(lines))

		for i := 0; i < len(lines); i++ {
			fmt.Println(lines[i])
			data, err := hex.DecodeString(lines[i])
			if err != nil {
				t.Error(err)
			}
			rawLines[i] = data
			fmt.Println(data)
		}
		output := DetectAESECB(rawLines, 16)
		expectedPrefix := "d880619740a8a"
		if !strings.HasPrefix(fmt.Sprintf("%x", output), expectedPrefix) {
			t.Errorf("wrong guess: %s expected something starting with %s", fmt.Sprintf("%x", output), expectedPrefix)
		}
	})
}
