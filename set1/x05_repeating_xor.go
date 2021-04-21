package set1

func RepeatingXOR(key, payload []byte) []byte {
	output := make([]byte, len(payload))

	for i := 0; i < len(payload); i++ {
		output[i] = payload[i] ^ key[i % len(key)]
	}

	return output
}