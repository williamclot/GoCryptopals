package set1

import (
	"encoding/base64"
	"encoding/hex"
)

func HexToBase64(data string) (string, error) {
	decoded, err := hex.DecodeString(data)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(decoded), nil
}