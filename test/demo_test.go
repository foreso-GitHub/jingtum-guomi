package main

import (
	"fmt"
	"testing"
)

func TestSm2(t *testing.T) {
	sm2Test()
	fmt.Printf("[sm2 test] done!\n")
}

func BenchmarkSm2(t *testing.B) {
	for i := 0; i < t.N; i++ {
		sm3Test()
	}
}
