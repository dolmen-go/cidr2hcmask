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

type rangeMasks struct {
	E     uint8 // end of range
	Masks []string
}

// rangesMasks are lists of masks by end of range boundary for a common start boundary.
//
// ranges are sorted by descending order (see [rangesMasks.Less]).
type rangesMasks []rangeMasks

func (rr rangesMasks) index(E uint8) int {
	for i := 0; i < len(rr) && rr[i].E >= E; i++ {
		if rr[i].E == E {
			return i
		}
	}
	return -1
}

func (rr rangesMasks) lookup(E uint8) []string {
	for i := 0; i < len(rr) && rr[i].E >= E; i++ {
		if rr[i].E == E {
			return rr[i].Masks
		}
	}
	return nil
}

func (rr *rangesMasks) insert(end uint8, masks []string) {
	if *rr == nil {
		*rr = rangesMasks{{E: end, Masks: masks}}
		return
	}
	if rr.index(end) != -1 {
		panic(fmt.Errorf("duplicate insert: %d %v", end, masks))
		// return
	}
	(*rr) = append(*rr, rangeMasks{E: end, Masks: masks})
	sort.Sort(*rr)
}

// Len implements [sort.Interface].
func (rr rangesMasks) Len() int {
	return len(rr)
}

// Less implements [sort.Interface].
func (rr rangesMasks) Less(i, j int) bool {
	// Ranges are sorted in descending order of end
	return rr[i].E > rr[j].E
}

// Swap implements [sort.Interface].
func (rr rangesMasks) Swap(i, j int) {
	rr[i], rr[j] = rr[j], rr[i]
}

var byteHCMasks [256]rangesMasks

func insertRange(start uint8, end uint8, masks ...string) {
	byteHCMasks[start].insert(end, masks)
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
		insertRange(start, start+9, prefix+mask0to9)
		/*
			// The dynamic code gives more compact output
			insertRange(start, start+4, prefix+mask0to4)
			insertRange(start, start+5, prefix+mask0to5)
			insertRange(start+1, start+9, prefix+mask1to9)
		*/

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

	insertRange(250, 255, mask250to255)

	insertRange(0, 255, masks0to255...)
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
				masks = append(masks, masksByEnd[i].Masks...)
				// s = end+1
				break nextRange
			}
			if masksByEnd[i].E < end {
				masks = append(masks, masksByEnd[i].Masks...)
				s = masksByEnd[i].E + 1
				continue nextRange
			}
		}

		sC, eC := s/100, end/100
		if sC < eC { // are we crossing a hundreds boundary?
			next := (sC + 1) * 100
			masks = append(masks, lookup(s, next-1)...)
			s = next
			continue nextRange
		}

		sD, eD := s/10, end/10
		if sD < eD { // are we crossing a tens boundary?
			next := (sD + 1) * 10
			masks = append(masks, lookup(s, next-1)...)
			s = next
			continue nextRange
		}

		var prefix string
		if sD > 0 {
			prefix = strconv.Itoa(int(sD))
		}
		sU, eU := s%10, end%10 // units
		switch sU {
		case 0:
			switch eU {
			case 9:
				masks = append(masks, prefix+mask0to9)
				break nextRange
			case 5:
				masks = append(masks, prefix+mask0to5)
				break nextRange
			case 4:
				masks = append(masks, prefix+mask0to4)
				break nextRange
			}
		case 1:
			if eU == 9 {
				masks = append(masks, prefix+mask1to9)
				break nextRange
			}
		}

		b := make([]byte, 0, int(eU-sU+1)+1+len(prefix)+2)
		for sU <= eU {
			b = append(b, byte('0'+sU))
			sU++
		}
		b = append(append(append(b, ','), prefix...), "?4"...)
		masks = append(masks, string(b))
		break
	}

	/*
		// The rule for altering our dictionnary still have to be tweaked to avoid too much slicing
		if len(masks) > 1 {
			insertRange(start, end, masks...)
		}
	*/

	return masks
}
