package cidr2hcmask

import (
	"fmt"
	"strconv"
	"testing"
)

func TestByte1(t *testing.T) {
	for i := 0; i < 255; i++ {
		masks := lookup(uint8(i), uint8(i))
		if len(masks) != 1 {
			t.Errorf("%d: %v", i, masks)
			continue
		}
		if masks[0] != strconv.Itoa(i) {
			t.Errorf("%d: %v", i, masks)
		}
		t.Logf("%d: OK", i)
	}
}

func TestByte2Odd(t *testing.T) {
	for i := 0; i < 255; i += 2 {
		masks := lookup(uint8(i), uint8(i+1))
		t.Logf("[%d, %d]: %v", i, i+1, masks)
		if len(masks) != 1 {
			t.Errorf("[%d, %d]: len 1 expected", i, i+1)
			continue
		}
		if i < 10 {
			if masks[0] != fmt.Sprintf("%02d,?4", i*11+1) {
				t.Errorf("[%d, %d]: unexpected format", i, i+1)
			}
		} else {
			if masks[0] != fmt.Sprintf("%02d,%d?4", (i%10)*11+1, i/10) {
				t.Errorf("[%d, %d]: unexpected format", i, i+1)
			}
		}
	}
}

func TestByte4Odd(t *testing.T) {
	for i := 0; i+3 <= 255; i += 2 {
		masks := lookup(uint8(i), uint8(i+3))
		t.Logf("[%d, %d]: %v", i, i+3, masks)
		switch i % 10 {
		case 0, 2, 4, 6:
			if len(masks) != 1 {
				t.Errorf("[%d, %d]: len 1 expected", i, i+3)
				continue
			}
			if i < 10 {
				if masks[0] != fmt.Sprintf("%.4s,?4", "0123456789"[i:]) {
					t.Errorf("[%d, %d]: unexpected format", i, i+3)
				}
			} else {
				if masks[0] != fmt.Sprintf("%.4s,%d?4", "0123456789"[i%10:], i/10) {
					t.Errorf("[%d, %d]: unexpected format", i, i+3)
				}
			}
		case 8:
			if len(masks) != 2 {
				t.Errorf("[%d, %d]: len 2 expected", i, i+3)
				continue
			}
			if i == 8 {
				if masks[0] != "89,?4" || masks[1] != "01,1?4" {
					t.Errorf("[%d, %d]: unexpected format", i, i+3)
				}
			} else {
				if masks[0] != fmt.Sprintf("89,%d?4", i/10) {
					t.Errorf("[%d, %d]: unexpected format", i, i+3)
				}
			}
			if masks[1] != fmt.Sprintf("01,%d?4", (i+2)/10) {
				t.Errorf("[%d, %d]: unexpected format", i, i+3)
			}
		default:
			panic("unexpected")
		}
	}
	t.Logf("%v", byteHCMasks)
}
