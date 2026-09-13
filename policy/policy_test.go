package policy

import "testing"

// A grant names a resource exactly or by prefix; a prefix covers what lies under it and
// nothing beside it.
func TestAResourcePrefixCoversWhatLiesUnderItOnly(t *testing.T) {
	list := []string{"x/y", "vera/hoet/*"}
	for _, ok := range []string{"x/y", "vera/hoet/paper1", "vera/hoet/a/b"} {
		if !ResourceCovered(list, ok) {
			t.Errorf("%s must be covered", ok)
		}
	}
	for _, no := range []string{"x/z", "vera/hoet", "vera/hoet/", "vera/hoetx/paper1", "vera/cabrio/paper1", "vera"} {
		if ResourceCovered(list, no) {
			t.Errorf("%s must not be covered", no)
		}
	}
}
