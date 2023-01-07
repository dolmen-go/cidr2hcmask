package cidr2hcmask_test

import (
	"testing"

	"github.com/dolmen-go/cidr2hcmask"
)

func FuzzParseCIDR(f *testing.F) {
	for _, tc := range []string{
		"0.0.0.0/0",
		"192.168.0.0/24",
		"10.0.0.0/8",
	} {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, s string) {
		net, err := cidr2hcmask.ParseCIDR(s)
		if err != nil {
			return
		}
		if net.String() != s {
			t.Fatalf("%q: got %q", s, net.String())
		}
	})
}

func checkCIDR(t *testing.T, cidr string, masks ...string) {
	t.Log("--[", cidr, "]--")
	net, err := cidr2hcmask.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	cidr2hcmask.CIDR2HCMaskFunc(net, func(mask string) {
		if mask != masks[0] {
			t.Error("got:", mask, "expected:", masks[0])
		}
		masks = masks[1:]
	})
	if len(masks) > 0 {
		t.Error("expected", len(masks), "more masks")
	}
}

func TestCIDR2HCMask(t *testing.T) {
	net, err := cidr2hcmask.ParseCIDR("192.168.1.0/28")
	if err != nil {
		panic(err)
	}
	cidr2hcmask.CIDR2HCMaskFunc(net, func(mask string) {
		t.Log(mask)
	})
}

func TestCIDR2HCMaskGroupTens(t *testing.T) {
	checkCIDR(t, "0.0.0.32/27",
		`01234,012345,123456789,23456789,0.0.0.3?4`,
		`01234,012345,123456789,45,0.0.0.?4?d`,
		`01234,012345,123456789,0123,0.0.0.6?4`,
	)
	checkCIDR(t, "0.0.0.128/26",
		`01234,012345,123456789,89,0.0.0.12?4`,
		`01234,012345,123456789,345678,0.0.0.1?4?d`,
		`01234,012345,123456789,01,0.0.0.19?4`,
	)
}
