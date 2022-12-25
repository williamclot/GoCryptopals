package set2

import (
	"bytes"
	"cryptopals/set1"
	"fmt"
	"math/rand"
	"strings"

	"github.com/google/uuid"
)

type Profile struct {
	Email string
	UID   string
	Role  string
}

type ProfileEncryption struct {
	key []byte
}

func URLDecode(cookie string) Profile {
	object := map[string]string{}
	for _, pair := range strings.Split(cookie, "&") {
		values := strings.Split(pair, "=")

		if len(values) < 2 {
			panic("URL decode profile failed")
		}
		object[values[0]] = values[1]
	}
	return Profile{
		Email: object["email"],
		UID:   object["uid"],
		Role:  object["role"],
	}
}

func URLEncode(p Profile) string {
	return fmt.Sprintf("email=%s&uid=%s&role=%s", p.Email, p.UID, p.Role)
}

func ProfileFor(email string) string {
	// a bit of sanitisation
	email = strings.ReplaceAll(email, "&", "")
	email = strings.ReplaceAll(email, "=", "")

	return URLEncode(Profile{
		Email: email,
		UID:   uuid.New().String(),
		Role:  "user",
	})
}

func NewProfileEncryptor() *ProfileEncryption {
	key := make([]byte, 32)
	rand.Read(key)
	return &ProfileEncryption{
		key: key,
	}
}

func (e *ProfileEncryption) Encrypt(email string) []byte {
	profile := ProfileFor(email)
	padded := PKCS7([]byte(profile), len(e.key))
	return set1.AESECBEncrypt(padded, e.key)
}

func (e *ProfileEncryption) Decrypt(c []byte) string {
	padded := set1.AESECBDecrypt(c, e.key)
	data, err := RemovePKCS7(padded, len(e.key))
	if err != nil {
		panic(err)
	}
	return string(data)
}

func (e *ProfileEncryption) Escalate(email string) ([]byte, error) {

	// This will only work with email of specific lengths
	if (len(email)+len("email=&uid=&role=")+36)%len(e.key) != 0 {
		return nil, fmt.Errorf("email wrong size: %s", email)
	}

	// Let's first start by generating our "normal" profile encryption token ciphertext
	// We'll be using this later on by replacing specific cipher text blocks.
	profile := e.Encrypt(email)

	// Next we want to get the ciphertext equivalent of the string "admin" in the last block. To do so,
	// we'll need to craft a special email that happens to build a block with the word admin in the same
	// configuration as if it was placed at the end under the role attribute.
	// We'll have to take into account padding and original email length.
	prefix := strings.Repeat("x", len(e.key)-len("email=")) + "admin"
	craftEmail := []byte(prefix)

	// We now have to guess the PKC7 padding length by looking
	paddingLength := len(e.key) - (len(prefix)+len("email="))%len(e.key)
	craftEmail = append(craftEmail, bytes.Repeat([]byte{byte(paddingLength)}, paddingLength)...)
	craftEmail = append(craftEmail, []byte("@test.com")...)

	// We now should have two cipher texts with the following blocks (UIDs are different)
	// 		| -> block delimitation
	// 		_ -> padding
	// email=me@test.co|m&uid=63d9cfac-4|893-4309-fpwq-8d|gkrj49dk20&role=|user________
	// email=xxxxxxxxxx|admin___________|@test.com&uid=8g|dfpwo9-4gl3-94j2|-983n-3pk49sk34d|xx&role=user____
	craftProfile := e.Encrypt(string(craftEmail))

	// Let's do some byte substitution now so that block number 2 of our craft profile equals the last block of
	// our profile!
	for i := 0; i < len(e.key); i++ {
		profile[len(profile)-len(e.key)+i] = craftProfile[len(e.key)+i]
	}

	return profile, nil
}
