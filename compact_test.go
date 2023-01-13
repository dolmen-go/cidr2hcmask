package cidr2hcmask

import (
	"fmt"
	"testing"
)

var compactMaskTests = [][2]string{
	{`abc`, `abc`},
	{`abc,def`, `def`},
	{`abc,def,ghi`, `ghi`},
	{`abc,def,ghi,jkl`, `jkl`},
	{`abc,def,ghi,jkl,mno`, `mno`},
	{`abc,def,ghi,jkl,mno,pqr`, `mno,pqr`},

	{`abc\,def`, `abc\,def`},
	{`abc\,def\,ghi`, `abc\,def\,ghi`},
	{`abc\,def,ghi`, `ghi`},

	{`abc?d`, `abc?d`},
	{`def,abc?d`, `abc?d`},
	{`def,abc?1`, `def,abc?1`},
	{`def,ghi,abc?1?2`, `def,ghi,abc?1?2`},
	{`def,ghi,abc?1?2?1`, `def,ghi,abc?1?2?1`},

	// Shift
	{`def,ghi,abc?2`, `ghi,abc?1`},
	{`def,ghi,jkl,abc?3`, `jkl,abc?1`},
	{`def,ghi,jkl,abc?2?3`, `ghi,jkl,abc?1?2`},
	{`def,ghi,jkl,abc?3?2`, `ghi,jkl,abc?2?1`},
}

func TestCompactMask(t *testing.T) {
	for _, tc := range compactMaskTests {
		got := CompactMask(tc[0])
		t.Logf("%q => %q", tc[0], got)
		if got != tc[1] {
			t.Errorf("%q: got %q, expected %q", tc[0], got, tc[1])
		}
	}
}

func FuzzCompactMask(f *testing.F) {
	for i := range compactMaskTests {
		f.Add(compactMaskTests[i][0])
	}
	f.Fuzz(func(t *testing.T, hcmask string) {
		newHcmask := CompactMask(hcmask)
		if newHcmask == hcmask {
			return
		}
		if len(newHcmask) > len(hcmask) {
			t.Fatalf("%q: output longer than input", hcmask)
		}
	})
}

func ExampleCompactMaskFunc() {
	net, err := ParseCIDR("192.168.0.0/24")
	if err != nil {
		panic(err)
	}

	CIDR2HCMaskFunc(net, func(hcmask string) {
		fmt.Println(hcmask)
	})
	fmt.Println()
	CIDR2HCMaskFunc(net, CompactMaskFunc(func(hcmask string) {
		fmt.Println(hcmask)
	}))

	// Output:
	// 01234,012345,123456789,192.168.0.1?d?d
	// 01234,012345,123456789,192.168.0.2?1?d
	// 01234,012345,123456789,192.168.0.25?2
	// 01234,012345,123456789,192.168.0.?3?d
	// 01234,012345,123456789,192.168.0.?d
	//
	// 192.168.0.1?d?d
	// 01234,192.168.0.2?1?d
	// 012345,192.168.0.25?1
	// 123456789,192.168.0.?1?d
	// 192.168.0.?d
}
