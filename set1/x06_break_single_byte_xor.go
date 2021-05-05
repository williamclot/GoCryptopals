package set1

func HammingDistance(a, b []byte) (int, error) {
	distance := 0
	xor, err := FixedXOR(a, b)
	if err != nil { return 0, err }

	for i:= 0; i < len(xor); i++ { // counting bits set to 1
		for j := 0; j < 8; j++ {
			if xor[i] >> j & 1 == 1 {
				distance++
			}
		}
	}
	
	return distance, nil
}

func FindKeySize(ciphertext []byte) (int, error) {
	bestKeySize, bestDistance := 0, 10000.0
	for keySize := 2; keySize < 40; keySize++ {
		distance := 0
		for i := 0; i < 4; i++ {

			firstBytes := ciphertext[i*keySize:(i+1)*keySize]
			secondBytes := ciphertext[(i+1)*keySize:(i+2)*keySize]

			currentDistance, err := HammingDistance(firstBytes, secondBytes)
			if err != nil { return 0, err }
			distance += currentDistance
		}
		normalizedDistance := float64(distance) / float64(keySize)
		if normalizedDistance < bestDistance {
			bestDistance = normalizedDistance
			bestKeySize = keySize
		}
	}
	return bestKeySize, nil
}