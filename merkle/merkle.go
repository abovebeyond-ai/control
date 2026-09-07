// Package merkle is the append-only tree of RFC 6962 section 2, hash for hash
// the tree the Proof-of-Control reference implementation keeps beside its
// chain: a verifier checks one record among a million with a dozen hashes
// (inclusion), and that a newer root extends an older one without rewriting
// anything (consistency).
//
//	leaf hash     = SHA-256(0x00 || record)
//	interior node = SHA-256(0x01 || left || right)
package merkle

import (
	"bytes"
	"crypto/sha256"
	"errors"
)

// EmptyRoot is the root of a tree with no leaves.
func EmptyRoot() []byte {
	s := sha256.Sum256(nil)
	return s[:]
}

// LeafHash of a record, domain-separated from interior nodes.
func LeafHash(record []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(record)
	return h.Sum(nil)
}

// NodeHash of two children.
func NodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// lpo2 is the largest power of two strictly less than n, for n >= 2.
func lpo2(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

// Tree is an append-only Merkle tree over leaf hashes.
type Tree struct {
	leaves [][]byte
	stack  []level // the perfect subtrees tiling the leaves, heights descending
}

type level struct {
	height int
	hash   []byte
}

// New returns an empty tree.
func New() *Tree { return &Tree{} }

// Append adds a record and returns its leaf index.
func (t *Tree) Append(record []byte) int {
	h := LeafHash(record)
	t.leaves = append(t.leaves, h)
	t.stack = append(t.stack, level{0, h})
	for len(t.stack) >= 2 && t.stack[len(t.stack)-1].height == t.stack[len(t.stack)-2].height {
		right := t.stack[len(t.stack)-1]
		left := t.stack[len(t.stack)-2]
		t.stack = t.stack[:len(t.stack)-2]
		t.stack = append(t.stack, level{right.height + 1, NodeHash(left.hash, right.hash)})
	}
	return len(t.leaves) - 1
}

// AppendLeafHash adds an already-hashed leaf (for rebuilding a tree from another).
func (t *Tree) AppendLeafHash(h []byte) int {
	t.leaves = append(t.leaves, h)
	t.stack = append(t.stack, level{0, h})
	for len(t.stack) >= 2 && t.stack[len(t.stack)-1].height == t.stack[len(t.stack)-2].height {
		right := t.stack[len(t.stack)-1]
		left := t.stack[len(t.stack)-2]
		t.stack = t.stack[:len(t.stack)-2]
		t.stack = append(t.stack, level{right.height + 1, NodeHash(left.hash, right.hash)})
	}
	return len(t.leaves) - 1
}

// LeafHash at an index.
func (t *Tree) LeafHash(i int) []byte { return t.leaves[i] }

// Size is the number of leaves.
func (t *Tree) Size() int { return len(t.leaves) }

// Root of the whole tree.
func (t *Tree) Root() []byte {
	if len(t.stack) == 0 {
		return EmptyRoot()
	}
	r := t.stack[len(t.stack)-1].hash
	for i := len(t.stack) - 2; i >= 0; i-- {
		r = NodeHash(t.stack[i].hash, r)
	}
	return r
}

// RootAt is the root as the tree stood at size leaves.
func (t *Tree) RootAt(size int) []byte {
	if size == 0 {
		return EmptyRoot()
	}
	return t.rangeRoot(0, size)
}

func (t *Tree) rangeRoot(lo, hi int) []byte {
	n := hi - lo
	if n == 1 {
		return t.leaves[lo]
	}
	k := lpo2(n)
	return NodeHash(t.rangeRoot(lo, lo+k), t.rangeRoot(lo+k, hi))
}

// InclusionProof is PATH(index, D[size]) of RFC 6962; size lets an auditor
// ask for a proof against a root published earlier than now.
func (t *Tree) InclusionProof(index, size int) ([][]byte, error) {
	if index < 0 || index >= size || size > len(t.leaves) {
		return nil, errors.New("index not in tree of that size")
	}
	return t.path(index, 0, size), nil
}

func (t *Tree) path(m, lo, hi int) [][]byte {
	n := hi - lo
	if n == 1 {
		return nil
	}
	k := lpo2(n)
	if m < k {
		return append(t.path(m, lo, lo+k), t.rangeRoot(lo+k, hi))
	}
	return append(t.path(m-k, lo+k, hi), t.rangeRoot(lo, lo+k))
}

// ConsistencyProof is PROOF(m, D[n]): evidence that the size-n tree extends the size-m one.
func (t *Tree) ConsistencyProof(m, n int) ([][]byte, error) {
	if m <= 0 || m > n || n > len(t.leaves) {
		return nil, errors.New("cannot prove consistency of those sizes")
	}
	if m == n {
		return nil, nil
	}
	return t.subproof(m, 0, n, true), nil
}

func (t *Tree) subproof(m, lo, hi int, b bool) [][]byte {
	n := hi - lo
	if m == n {
		if b {
			return nil
		}
		return [][]byte{t.rangeRoot(lo, hi)}
	}
	k := lpo2(n)
	if m <= k {
		return append(t.subproof(m, lo, lo+k, b), t.rangeRoot(lo+k, hi))
	}
	return append(t.subproof(m-k, lo+k, hi, false), t.rangeRoot(lo, lo+k))
}

// ReferenceRoot is the recursive definition straight from the RFC: slow and
// obviously correct, what the incremental tree is tested against.
func ReferenceRoot(leaves [][]byte) []byte {
	n := len(leaves)
	if n == 0 {
		return EmptyRoot()
	}
	if n == 1 {
		return leaves[0]
	}
	k := lpo2(n)
	return NodeHash(ReferenceRoot(leaves[:k]), ReferenceRoot(leaves[k:]))
}

// VerifyInclusion: does leaf sit at index of the tree of size with head root?
// Touches only the proof, never the log.
func VerifyInclusion(index, size int, leaf []byte, proof [][]byte, root []byte) bool {
	if index >= size || size == 0 {
		return false
	}
	fn, sn, r := index, size-1, leaf
	for _, p := range proof {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = NodeHash(p, r)
			for fn != 0 && fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytes.Equal(r, root)
}

// VerifyConsistency: is the size-n tree with root rootN an append-only
// extension of the size-m tree with root rootM? False means history was
// rewritten.
func VerifyConsistency(m, n int, rootM, rootN []byte, proof [][]byte) bool {
	if m > n || m == 0 {
		return false
	}
	if m == n {
		return len(proof) == 0 && bytes.Equal(rootM, rootN)
	}
	path := append([][]byte{}, proof...)
	if m&(m-1) == 0 { // m is a power of two: rootM is an implicit node
		path = append([][]byte{rootM}, path...)
	}
	if len(path) == 0 {
		return false
	}
	fn, sn := m-1, n-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := path[0], path[0]
	for _, c := range path[1:] {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			fr = NodeHash(c, fr)
			sr = NodeHash(c, sr)
			for fn != 0 && fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = NodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytes.Equal(fr, rootM) && bytes.Equal(sr, rootN)
}
