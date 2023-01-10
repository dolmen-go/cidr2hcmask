package cidr2hcmask_test

import "strings"

// HCMaskExpand is an expander for a HCMask limited to the subset useed in the cidr2hcmask project.
func HCMaskExpand(mask string, visit func([]byte)) {
	parts := strings.Split(mask, ",")
	pattern := parts[len(parts)-1]

	var charsets [5]string
	charsets[0] = "0123456789" // ?d
	for i := 0; i < len(parts)-1; i++ {
		charsets[i+1] = parts[i]
	}
	parts = nil

	buf := make([]byte, 0, len(pattern))
	var vars []hcmaskVar
	for i := 0; i < len(pattern); i++ {
		buf = append(buf, pattern[i])
		if pattern[i] == '?' {
			i++
			var charset int
			if pattern[i] != 'd' {
				charset = int(pattern[i] - '0')
			} // else charset = 0
			vars = append(vars, hcmaskVar{Index: len(buf) - 1, Charset: charset})
		}
	}

	if vars == nil {
		visit(buf)
		return
	}

	hcmaskExpandRec(buf, visit, charsets[:], vars)
}

type hcmask struct {
	work     []byte
	charsets [5]string
	vars     []hcmaskVar
}

type hcmaskVar struct {
	Index   int
	Charset int
}

func hcmaskExpandRec(buf []byte, visit func([]byte), charsets []string, vars []hcmaskVar) {
	if len(vars) == 0 {
		visit(buf)
		return
	}
	idx := vars[0].Index
	buf[idx] = '?' // Force bound check out of the loop
	charset := charsets[vars[0].Charset]
	nextVars := vars[1:]

	for i := 0; i < len(charset); i++ {
		buf[idx] = charset[i]
		hcmaskExpandRec(buf, visit, charsets, nextVars)
	}
}
