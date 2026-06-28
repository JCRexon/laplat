// Package merkle implements an RFC 6962 (Certificate Transparency) Merkle tree
// hash and inclusion proofs over a list of leaves. It is standard-library only.
//
// Domain separation prevents second-preimage attacks: leaves are hashed with a
// 0x00 prefix and internal nodes with 0x01, so a leaf can never be reinterpreted
// as an internal node. This is the construction ADR-010 anchors presence
// checkpoints with — a signed tree head over the presence rows in a range.
package merkle

import (
	"bytes"
	"crypto/sha256"
	"errors"
)

// leafHash is H(0x00 || data).
func leafHash(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

// nodeHash is H(0x01 || left || right).
func nodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// largestPow2LessThan returns the largest power of two strictly less than n
// (defined for n >= 2).
func largestPow2LessThan(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// Root computes the Merkle Tree Hash (MTH) over the given leaf data. The empty
// tree hashes to SHA-256 of the empty string, per RFC 6962.
func Root(leaves [][]byte) []byte {
	switch len(leaves) {
	case 0:
		s := sha256.Sum256(nil)
		return s[:]
	case 1:
		return leafHash(leaves[0])
	default:
		k := largestPow2LessThan(len(leaves))
		return nodeHash(Root(leaves[:k]), Root(leaves[k:]))
	}
}

// Proof returns the inclusion (audit) path for the leaf at index m: the sibling
// subtree hashes from the leaf's level up to the root. Ordered deepest-first,
// matching VerifyProof's consumption from the end.
func Proof(leaves [][]byte, m int) ([][]byte, error) {
	if m < 0 || m >= len(leaves) {
		return nil, errors.New("merkle: index out of range")
	}
	return path(m, leaves), nil
}

func path(m int, d [][]byte) [][]byte {
	if len(d) == 1 {
		return nil
	}
	k := largestPow2LessThan(len(d))
	if m < k {
		return append(path(m, d[:k]), Root(d[k:]))
	}
	return append(path(m-k, d[k:]), Root(d[:k]))
}

// VerifyProof recomputes the root from a leaf, its index m, the tree size n, and
// the inclusion proof, and reports whether it equals root.
func VerifyProof(leaf []byte, m, n int, proof [][]byte, root []byte) bool {
	if m < 0 || m >= n {
		return false
	}
	got := rootFromProof(leafHash(leaf), m, n, proof)
	return got != nil && bytes.Equal(got, root)
}

func rootFromProof(leafH []byte, m, n int, proof [][]byte) []byte {
	if n == 1 {
		if len(proof) != 0 {
			return nil
		}
		return leafH
	}
	if len(proof) == 0 {
		return nil
	}
	sib := proof[len(proof)-1]
	rest := proof[:len(proof)-1]
	k := largestPow2LessThan(n)
	if m < k {
		left := rootFromProof(leafH, m, k, rest)
		if left == nil {
			return nil
		}
		return nodeHash(left, sib)
	}
	right := rootFromProof(leafH, m-k, n-k, rest)
	if right == nil {
		return nil
	}
	return nodeHash(sib, right)
}
