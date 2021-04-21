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

// func FindKeySize(ciphertext []byte) (int, error) {
// 	bestKeySize, bestDistance := 0.0, 10000.0
// 	for keySize := 2; keySize < 40; keySize++ {
// 		firstBytes := ciphertext[:keySize]
// 		secondBytes := ciphertext[keySize:2*keySize]
// 		distance, err := HammingDistance(firstBytes, secondBytes)
// 		if err != nil { return 0, err }

// 		if float64(distance / keySize) < bestDistance {

// 		}
// 	} 
// }