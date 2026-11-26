// Prints cross-check vectors for akio-crypto's Argon2id, BLAKE2b and XChaCha20-Poly1305 from
// golang.org/x/crypto, the implementations fit uses. Output: tests/data/go_x_crypto.txt.
//
//	go mod init govec && go get golang.org/x/crypto@v0.58.0 && go run . > go_x_crypto.txt
package main

import "fmt"

import (
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

func pat(n int, mul, add byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)*mul + add
	}
	return b
}

func h(b []byte) string {
	if len(b) == 0 {
		return "-"
	}
	return fmt.Sprintf("%x", b)
}

func main() {
	fmt.Println("# golang.org/x/crypto v0.58.0 (Go 1.27), from go_x_crypto.go in this directory.")
	fmt.Println("# argon2id password salt time memory_kib lanes IDKey")
	fmt.Println("# blake2b key message digest (blake2b.New(len(digest), key))")
	fmt.Println("# xchacha key nonce aad plaintext ciphertext||tag (chacha20poly1305.NewX)")
	type a struct {
		pw, salt []byte
		t, m     uint32
		p        uint8
		n        uint32
	}
	for _, c := range []a{
		{[]byte("correct horse battery staple"), pat(16, 1, 0), 3, 64 * 1024, 4, 32}, // fit's setting
		{[]byte("password"), []byte("somesalt"), 1, 8, 1, 32},
		{[]byte("password"), []byte("somesalt"), 2, 64, 2, 64},
		{[]byte(""), pat(8, 7, 3), 1, 32, 4, 4},
		{pat(100, 3, 1), pat(32, 5, 9), 4, 256, 3, 100},
		{[]byte("pw"), pat(16, 1, 1), 1, 1024, 8, 128},
		{[]byte("p"), pat(16, 1, 2), 2, 513, 1, 65},
		{[]byte("fit"), pat(16, 9, 2), 1, 4096, 4, 32},
	} {
		k := argon2.IDKey(c.pw, c.salt, c.t, c.m, c.p, c.n)
		fmt.Printf("argon2id %s %s %d %d %d %s\n", h(c.pw), h(c.salt), c.t, c.m, c.p, h(k))
	}
	for _, n := range []int{0, 1, 3, 127, 128, 129, 255, 256, 257, 1000} {
		for _, sz := range []int{1, 20, 32, 48, 64} {
			for _, key := range [][]byte{nil, pat(sz, 1, 0x30)} {
				d, _ := blake2b.New(sz, key)
				d.Write(pat(n, 1, 0))
				fmt.Printf("blake2b %s %s %s\n", h(key), h(pat(n, 1, 0)), h(d.Sum(nil)))
			}
		}
	}
	for _, n := range []int{0, 1, 15, 16, 17, 63, 64, 65, 300} {
		key := pat(32, byte(n)|1, 0x80)
		aead, _ := chacha20poly1305.NewX(key)
		nonce := pat(24, 3, byte(n))
		ad := pat(n%60, 1, 0x50)
		ct := aead.Seal(nil, nonce, pat(n, 1, 0), ad)
		fmt.Printf("xchacha %s %s %s %s %s\n", h(key), h(nonce), h(ad), h(pat(n, 1, 0)), h(ct))
	}
}
