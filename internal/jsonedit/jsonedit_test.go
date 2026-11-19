package jsonedit

import "testing"

func TestRoundTripPreservesOrderAndNumbers(t *testing.T) {
	in := "{\n  \"zeta\": 1.50,\n  \"alpha\": [\n    true,\n    null,\n    \"<&>\"\n  ],\n  \"empty\": {},\n  \"list\": []\n}\n"
	v, err := Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := Marshal(v)
	if string(out) != in {
		t.Fatalf("got\n%s", out)
	}
	for _, bad := range []string{"{", "{} {}", "[1,]"} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
