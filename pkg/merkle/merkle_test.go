package merkle

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
)

func leaves(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte(fmt.Sprintf("leaf-%d", i))
	}
	return out
}

// For every size and every index, the produced proof verifies against the root.
func TestProofRoundTrip(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4, 5, 8, 9, 16, 100} {
		ls := leaves(n)
		root := Root(ls)
		for m := 0; m < n; m++ {
			proof, err := Proof(ls, m)
			if err != nil {
				t.Fatalf("n=%d m=%d proof: %v", n, m, err)
			}
			if !VerifyProof(ls[m], m, n, proof, root) {
				t.Fatalf("n=%d m=%d: valid proof failed to verify", n, m)
			}
		}
	}
}

// Tampering is detected: a flipped leaf, wrong index, or altered proof all fail.
func TestTamperDetected(t *testing.T) {
	ls := leaves(8)
	root := Root(ls)
	proof, _ := Proof(ls, 3)

	if VerifyProof([]byte("not-leaf-3"), 3, 8, proof, root) {
		t.Fatal("a different leaf must not verify")
	}
	if VerifyProof(ls[3], 4, 8, proof, root) {
		t.Fatal("wrong index must not verify")
	}
	if len(proof) > 0 {
		bad := make([][]byte, len(proof))
		copy(bad, proof)
		bad[0] = bytes.Repeat([]byte{0xFF}, 32)
		if VerifyProof(ls[3], 3, 8, bad, root) {
			t.Fatal("altered proof must not verify")
		}
	}
	// A different root must not verify.
	if VerifyProof(ls[3], 3, 8, proof, bytes.Repeat([]byte{0x00}, 32)) {
		t.Fatal("wrong root must not verify")
	}
}

// Known small-tree shape: root of two leaves is nodeHash(leafHash(a),leafHash(b)).
func TestRootShape(t *testing.T) {
	a, b := []byte("a"), []byte("b")
	la := sha256.Sum256(append([]byte{0x00}, a...))
	lb := sha256.Sum256(append([]byte{0x00}, b...))
	want := sha256.New()
	want.Write([]byte{0x01})
	want.Write(la[:])
	want.Write(lb[:])
	if !bytes.Equal(Root([][]byte{a, b}), want.Sum(nil)) {
		t.Fatal("two-leaf root shape mismatch")
	}
	// Single leaf root is just its leaf hash.
	single := sha256.Sum256(append([]byte{0x00}, a...))
	if !bytes.Equal(Root([][]byte{a}), single[:]) {
		t.Fatal("single-leaf root must equal its leaf hash")
	}
}
