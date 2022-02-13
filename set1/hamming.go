package set1

func HammingDistance(a, b []byte) (int, error) {
	distance := 0
	xor, err := XOR(a, b)
	if err != nil {
		return 0, err
	}

	for i := 0; i < len(xor); i++ { // counting bits set to 1
		for j := 0; j < 8; j++ {
			if xor[i]>>j&1 == 1 {
				distance++
			}
		}
	}

	return distance, nil
}
