package merkle

import (
	"bytes"
	"fmt"
	"testing"
)

func TestIncrementalTreeMatchesTheReferenceDefinition(t *testing.T) {
	tree := New()
	var leaves [][]byte
	if !bytes.Equal(tree.Root(), EmptyRoot()) {
		t.Fatal("empty root")
	}
	for i := 0; i < 40; i++ {
		rec := []byte(fmt.Sprintf("record-%d", i))
		tree.Append(rec)
		leaves = append(leaves, LeafHash(rec))
		if !bytes.Equal(tree.Root(), ReferenceRoot(leaves)) {
			t.Fatalf("root differs after %d leaves", i+1)
		}
		if !bytes.Equal(tree.Root(), tree.RootAt(i+1)) {
			t.Fatalf("RootAt differs at %d", i+1)
		}
	}
	for _, idx := range []int{0, 1, 7, 8, 15, 31, 39} {
		proof, err := tree.InclusionProof(idx, 40)
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyInclusion(idx, 40, leaves[idx], proof, tree.Root()) {
			t.Errorf("inclusion of %d", idx)
		}
		if VerifyInclusion(idx, 40, LeafHash([]byte("other")), proof, tree.Root()) {
			t.Errorf("a foreign leaf passed at %d", idx)
		}
	}
	proof, _ := tree.InclusionProof(3, 10)
	if !VerifyInclusion(3, 10, leaves[3], proof, tree.RootAt(10)) || VerifyInclusion(3, 10, leaves[3], proof, tree.Root()) {
		t.Error("inclusion against an earlier root")
	}
	for _, pair := range [][2]int{{1, 40}, {8, 40}, {13, 40}, {16, 17}, {40, 40}, {7, 8}} {
		m, n := pair[0], pair[1]
		cp, err := tree.ConsistencyProof(m, n)
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyConsistency(m, n, tree.RootAt(m), tree.RootAt(n), cp) {
			t.Errorf("consistency %d -> %d", m, n)
		}
		if m < n && VerifyConsistency(m, n, ReferenceRoot(leaves[1:m+1]), tree.RootAt(n), cp) {
			t.Errorf("a rewritten prefix passed %d -> %d", m, n)
		}
	}
}
