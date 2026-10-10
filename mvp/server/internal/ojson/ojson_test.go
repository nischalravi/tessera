package ojson

import (
	"testing"
)

func TestPyRepr(t *testing.T) {
	tests := []struct {
		in   float64
		want string
	}{
		{0, "0.0"}, {4, "4.0"}, {1.5, "1.5"}, {36.0, "36.0"}, {0.35, "0.35"}, {-2, "-2.0"},
		{1e16, "1e+16"}, {1.5e16, "1.5e+16"}, {123456789012345.0, "123456789012345.0"},
		{0.0001, "0.0001"}, {0.00001, "1e-05"}, {1.25e-7, "1.25e-07"}, {0.30000000000000004, "0.30000000000000004"},
	}
	for _, tc := range tests {
		if got := PyRepr(tc.in); got != tc.want {
			t.Errorf("PyRepr(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestObjectRoundTripKeepsOrder(t *testing.T) {
	in := `{"z":1,"a":{"y":[1,2.0,"x"],"b":null},"m":true}`
	v, err := Decode([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != in {
		t.Errorf("round trip = %s", out)
	}
	if got, _ := Marshal(Object{{Key: "html", Value: "<a&b>"}, {Key: "f", Value: Float(2)}}); string(got) != `{"html":"<a&b>","f":2.0}` {
		t.Errorf("marshal = %s", got)
	}
}
