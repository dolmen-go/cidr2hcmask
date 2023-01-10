package cidr2hcmask

import (
	"fmt"
	"sort"
	"strconv"
)

type charset string

const (
	cs04 = charset("01234")
	cs05 = charset("012345")
	cs19 = charset("123456789")
)

const (
	mask0to4 = "?1"
	mask0to5 = "?2"
	mask1to9 = "?3"

	mask0to9     = "?d"
	mask10to99   = "?3?d"
	mask100to199 = "1?d?d"
	mask200to249 = "2?1?d"
	mask250to255 = "25?2"
)

var masks0to255 = []string{
	mask100to199,
	mask200to249,
	mask250to255,
	mask10to99,
	mask0to9,
}

type rangeMask struct {
	E    uint8 // end of range
	Mask string
}

// rangesMask are lists of masks by end of range boundary for a common start boundary.
//
// ranges are sorted by descending order (see [rangesMasks.Less]).
type rangesMask []rangeMask

func (rr rangesMask) index(E uint8) int {
	for i := 0; i < len(rr) && rr[i].E >= E; i++ {
		if rr[i].E == E {
			return i
		}
	}
	return -1
}

func (rr rangesMask) lookup(E uint8) string {
	for i := 0; i < len(rr) && rr[i].E >= E; i++ {
		if rr[i].E == E {
			return rr[i].Mask
		}
	}
	return ""
}

func (rr *rangesMask) insert(end uint8, mask string) {
	if end&1 == 0 {
		panic("end must be even")
	}
	if *rr == nil {
		*rr = rangesMask{{E: end, Mask: mask}}
		return
	}
	if rr.index(end) != -1 {
		panic(fmt.Errorf("duplicate insert: %d %v", end, mask))
		// return
	}
	(*rr) = append(*rr, rangeMask{E: end, Mask: mask})
	sort.Sort(*rr)
}

// Len implements [sort.Interface].
func (rr rangesMask) Len() int {
	return len(rr)
}

// Less implements [sort.Interface].
func (rr rangesMask) Less(i, j int) bool {
	// Ranges are sorted in descending order of end
	return rr[i].E > rr[j].E
}

// Swap implements [sort.Interface].
func (rr rangesMask) Swap(i, j int) {
	rr[i], rr[j] = rr[j], rr[i]
}

var byteHCMasks [256]rangesMask

func insertRange(start uint8, end uint8, mask string) {
	if end <= start {
		panic("end must be above start")
	}
	byteHCMasks[start].insert(end, mask)
}

// insertRangesTen handles special grouping cases for tens:
//
//	[10, 29] => 12,?4?d
//	[10, 39] => 123,?4?d
//	[150, 189] => 5678,1?4?d
func insertRangesTen(start uint8, end uint8, mask string) {
	var b [20]byte
	s := start / 10 % 10
	e := end / 10 % 10
	for i := s; i <= e; i++ {
		var prefix string
		if start > 0 {
			prefix = strconv.Itoa(int(start) / 10)
		}
		// This a special case where we use the ?d charset
		insertRange(start, start+9, prefix+mask0to9)

		insertRange(start, start+7, "01234567,"+prefix+"?4")

		// This a special case where we reuse the 012345 charset (?2)
		insertRange(start, start+5, prefix+mask0to5)

		insertRange(start, start+3, "0123,"+prefix+"?4")
		insertRange(start, start+1, "01,"+prefix+"?4")

		for j := uint8(2); j <= 8; j += 2 {
			b := make([]byte, 0, 20)

			for k := j + 1; k <= 9; k += 2 {
				b = append(b, '0'+k-1, '0'+k)
				insertRange(start+j, start+k, string(append(append(append(b, ','), prefix...), "?4"...)))
			}
		}

		b[0] = '0' + i
		charset := b[:1]
		for j := i + 1; j <= e; j++ {
			charset = append(charset, '0'+j)
			insertRange(start, start+(j-i)*10+9, string(append(append(charset, ','), mask...)))
		}
		start += 10
	}
}

func init() {
	insertRangesTen(0, 0, "?d")
	insertRangesTen(10, 90, "?4?d")
	insertRangesTen(100, 190, "1?4?d")
	insertRangesTen(200, 240, "2?4?d")

	// Special cases to handle [250, 255]
	insertRange(250, 251, "01,25?4")
	insertRange(250, 253, "0123,25?4")
	insertRange(250, 255, mask250to255)
	insertRange(252, 253, "23,25?4")
	insertRange(252, 255, "2345,25?4")
	insertRange(254, 255, "45,25?4")
}

func lookup(start uint8, end uint8) []string {
	var masks []string
	s := start

nextRange:
	for s <= end {
		if s == end {
			masks = append(masks, strconv.Itoa(int(start)))
			break
		}
		masksByEnd := byteHCMasks[s]
		for i := 0; i < len(masksByEnd); i++ {
			if masksByEnd[i].E == end {
				masks = append(masks, masksByEnd[i].Mask)
				// s = end+1
				break nextRange
			}
			if masksByEnd[i].E < end {
				masks = append(masks, masksByEnd[i].Mask)
				s = masksByEnd[i].E + 1
				continue nextRange
			}
		}

		panic("unhandled case: we have a hole in the byte ranges table")
	}

	return masks
}
