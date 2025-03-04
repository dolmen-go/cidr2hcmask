package cidr2hcmask_test

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/dolmen-go/cidr2hcmask"
)

func FuzzParseCIDR(f *testing.F) {
	for _, tc := range []string{
		// Valid
		"0.0.0.0/0",
		"192.168.0.0/24",
		"10.0.0.0/8",
		// Invalid
		"00.0.0.0/0",
		"0.0.0.00/0",
		"0.0.0.0/00",
		"1.2.3.4.5/0",
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

func TestParseCIDRErrSyntax(t *testing.T) {
	for _, tc := range []string{
		"1111111111111111111/32",
		"1.2.3.4",
		"1.2.3.4/",
		"1.2.3.4/a",
		"1.2.3.4/33",
		"1.2.3./32",
		".../32",
		"1.2.3.256/0",
		"1.2.3.04/32",
		"1.2.3.4/032",
	} {
		_, err := cidr2hcmask.ParseCIDR(tc)
		if err == nil {
			t.Errorf("%q: error expected", tc)
		} else if !errors.Is(err, cidr2hcmask.ErrSyntax) {
			t.Errorf("%q: ErrSyntax expected, got %q", tc, err)
		}
	}
}

func TestParseCIDRErrNonZeroBits(t *testing.T) {
	for _, tc := range []string{
		"192.168.0.1/16",
		"192.168.0.1/31",
		"0.0.0.1/0",
		"128.0.0.0/0",
	} {
		_, err := cidr2hcmask.ParseCIDR(tc)
		if err == nil {
			t.Errorf("%q: error expected", tc)
		} else if !errors.Is(err, cidr2hcmask.ErrNonZeroBits) {
			t.Errorf("%q: ErrNonZeroBits expected, got %q", tc, err)
		}
	}
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

func ExampleCIDR2HCMaskFunc() {
	net, err := cidr2hcmask.ParseCIDR("192.168.1.0/28")
	if err != nil {
		panic(err)
	}

	cidr2hcmask.CIDR2HCMaskFunc(net, func(mask string) {
		fmt.Println(mask)
	})

	// Output:
	// 01234,012345,123456789,192.168.1.?d
	// 01234,012345,123456789,192.168.1.1?2
}

func ExampleCIDR2HCMaskWrite() {
	net, err := cidr2hcmask.ParseCIDR("192.168.1.0/28")
	if err != nil {
		panic(err)
	}

	cidr2hcmask.CIDR2HCMaskWrite(net, os.Stdout)

	// Output:
	// 01234,012345,123456789,192.168.1.?d
	// 01234,012345,123456789,192.168.1.1?2
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

func checkCIDRExpand(t *testing.T, cidr string, visit func([]byte)) {
	t.Log("==[", cidr, "]==")
	net, err := cidr2hcmask.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	// cidr2hcmask.CIDR2HCMaskFunc(net, cidr2hcmask.CompactMaskFunc(func(mask string) {
	cidr2hcmask.CIDR2HCMaskFunc(net, func(mask string) {
		t.Log("[", mask, "]")
		HCMaskExpand(mask, visit)
	})
}

func TestCIDR2HCMask32(t *testing.T) {
	const ip = "192.168.1.1"
	done := false
	checkCIDRExpand(t, ip+"/32", func(b []byte) {
		if done {
			t.Error("single result expected")
		}
		if string(b) != ip {
			t.Errorf("got %q, expected %q", b, ip)
		}
		done = true
	})
}

func TestCIDR2HCMask27(t *testing.T) {
	const ip = "192.168.1.224"
	checkCIDRExpand(t, ip+"/27", func(b []byte) {
		t.Log(string(b))
	})
}

func TestCIDR2HCMaskAll(t *testing.T) {
	const prefix = "192.168."

	re := regexp.MustCompile("^" + regexp.QuoteMeta(prefix) + "([0-9]+)\\.([0-9]+)\\z")
	t.Log(re)

	patternsCount := 0
	for bits := 16; bits < 24; bits++ {
		w := 1 << (24 - bits)

		var found [256 * 256]bool
		var foundCount int

		for s := int(0); s < 256; s += w {

			cidr := fmt.Sprintf(prefix+"%d.0/%d", s, bits)

			net, _ := cidr2hcmask.ParseCIDR(cidr)
			cidr2hcmask.CIDR2HCMaskFunc(net, func(string) {
				patternsCount++
			})

			count := 0
			checkCIDRExpand(t, cidr, func(b []byte) {
				// t.Logf("%s", b)
				matches := re.FindStringSubmatch(string(b))
				// FIXME check also for leading zeroes (which are not an error for ParseUint)
				p, err := strconv.ParseUint(matches[1], 10, 8)
				if err != nil {
					t.Errorf("%q: %v", b, err)
				}
				q, err := strconv.ParseUint(matches[2], 10, 8)
				if err != nil {
					t.Errorf("%q: %v", b, err)
				}
				pq := p<<8 + q
				if found[pq] {
					t.Errorf("duplicate %q", b)
				} else {
					count++
					foundCount++
					found[pq] = true
				}
			})
			if count != w*256 {
				t.Errorf("%d ip expected, got %d", w*256, count)
			}
		}
		if foundCount != 65536 {
			t.Errorf("%d ip expected, got %d", 65536, foundCount)
		}
	}

	t.Log(patternsCount, "patterns.")
	const patternsCountExpected = 1710
	if patternsCount > patternsCountExpected {
		t.Errorf("Regression in the count of patterns produced: got %d, expected %d", patternsCount, patternsCountExpected)
	} else if patternsCount < patternsCountExpected {
		t.Logf("Unexpected low count of patterns produced: got %d, expected %d", patternsCount, patternsCountExpected)
	}
}
