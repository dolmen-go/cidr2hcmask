package cidr2hcmask

import "strings"

// CompactMask removes unused charsets.
//
// Note that it might be more efficient (more shrinking) to apply compressors like gzip, bzip2 directly
// instead of applying CompactMask and then the compressor.
func CompactMask(hcmask string) string {
	var charsets [][2]int
	// var charsetHasEscapes [4]bool
	start := 0
	hasEscapedChars := false
	i := 0
extractCharsets:
	for i < len(hcmask) {
		switch hcmask[i] {
		case ',':
			// charsetHasEscapes[len(charsets)] = hasEscapedChars
			charsets = append(charsets, [2]int{start, i})
			// FIXME handle case where hasEscapedChars

			start = i + 1
			if len(charsets) == 4 {
				hasEscapedChars = strings.IndexByte(hcmask[i:], '\\') >= 0
				break extractCharsets
			}
			hasEscapedChars = false
		case '\\':
			hasEscapedChars = true
			i++
			// FIXME check hcmask[i] if ',' or '#' or '\\' and nothing else
		}
		i++
	}

	pattern := hcmask[start:]
	// FIXME handle case where hasEscapedChars
	_ = hasEscapedChars

	usedCharset := 0
	var charsetRefs []int
	for i := 0; i < len(pattern); i++ {
		if pattern[i] != '?' || i == len(pattern)-1 {
			continue
		}
		i++
		c := pattern[i]
		if c >= '1' && c <= '4' && c <= byte('0'+len(charsets)) {
			usedCharset |= 1 << (c - '1')
			if usedCharset == (1<<len(charsets))-1 { // All charsets used? => no compression
				return hcmask
			}
			charsetRefs = append(charsetRefs, i)
		}
	}
	if usedCharset == 0 {
		// FIXME ensure commas and # are escaped
		return pattern
	}
	charsetIndex := [...]byte{'1', '2', '3', '4'}
	newMask := make([]byte, 0, len(hcmask))
	i = 0
	for usedCharset > 0 {
		if usedCharset&1 == 0 {
			for j := i + 1; j < 4; j++ {
				charsetIndex[j]--
			}
		} else {
			newMask = append(append(newMask, hcmask[charsets[i][0]:charsets[i][1]]...), ',')
		}
		usedCharset >>= 1
		i++
	}
	start = len(newMask)
	newMask = append(newMask, pattern...)
	pat := newMask[start:]
	// FIXME Escape commas
	for _, r := range charsetRefs {
		n := int(pat[r] - '1')
		pat[r] = charsetIndex[n]
	}
	return string(newMask)
}

func CompactMaskFunc(cb func(mask string)) func(string) {
	return func(mask string) {
		cb(CompactMask(mask))
	}
}
