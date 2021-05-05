package main

import (
	"fmt"
)

func main() {
	a := [8]string{"a", "b", "c", "d", "e", "f", "g", "h"}
	fmt.Println(a[:2])
	fmt.Println(a[2:2*2])

}

