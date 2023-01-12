// Package cidr2hcmask provides utilities to convert a network address in CIDR notation
// into a [Hashcat mask file].
//
// [Hashcat mask file]: https://hashcat.net/wiki/doku.php?id=mask_attack#hashcat_mask_files
package cidr2hcmask

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// IPv4Net represents a block of IPv4 addresses using a base IP address and a count of bits.
type IPv4Net struct {
	IP   [4]byte
	Bits int
}

// String uses the CIDR format <ip>/<bits>.
//
// String implements interface [fmt.Stringer].
func (net IPv4Net) String() string {
	return fmt.Sprintf("%d.%d.%d.%d/%d", net.IP[0], net.IP[1], net.IP[2], net.IP[3], net.Bits)
}

var (
	ErrSyntax      = errors.New("syntax error")  // CDIR format error
	ErrNonZeroBits = errors.New("non-zero bits") // CDIR format error: the IP part is not canonical
)

// ParseCIDR parses an IPv4 network address in CIDR notation.
// See https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#CIDR_notation.
//
// Exemple value: 192.168.2.0/24.
//
// Errors returned (check with [errors.Is]): [ErrSyntax], [ErrNonZeroBits]
func ParseCIDR(s string) (IPv4Net, error) {
	if len(s) > (3+1+3+1+3+1+3)+1+(2) {
		return IPv4Net{}, ErrSyntax
	}
	ipStr, bitsStr, found := strings.Cut(s, "/")
	if !found {
		return IPv4Net{}, ErrSyntax
	}
	if len(bitsStr) > 1 && bitsStr[0] == '0' { // Disallow leading zero
		return IPv4Net{}, ErrSyntax
	}
	var net IPv4Net
	n, err := strconv.ParseUint(bitsStr, 10, 8)
	if err != nil {
		return IPv4Net{}, ErrSyntax
	}
	if n > 32 { // FIXME check spec
		return IPv4Net{}, ErrSyntax
	}
	net.Bits = int(n)

	ipParts := strings.SplitN(ipStr, ".", 5)
	if len(ipParts) != 4 {
		return IPv4Net{}, ErrSyntax
	}

	bits := net.Bits
	errBits := false
	for i := 0; i < 4; i++ {
		if len(ipParts[i]) > 1 && ipParts[i][0] == '0' { // Disallow leading zero
			return IPv4Net{}, ErrSyntax
		}
		if bits == 0 {
			if ipParts[i] != "0" {
				if _, err = strconv.ParseUint(ipParts[i], 10, 8); err != nil {
					return IPv4Net{}, ErrSyntax
				}
				errBits = true
			}
		} else {
			n, err = strconv.ParseUint(ipParts[i], 10, 8)
			if err != nil {
				return IPv4Net{}, ErrSyntax
			}
			if bits >= 8 {
				net.IP[i] = byte(n)
				bits -= 8
			} else { // 1 to 7 bits
				mask := (uint64(1) << (8 - bits)) - 1
				if n&mask != 0 {
					errBits = true
					n = n &^ mask
				}
				net.IP[i] = byte(n)
				bits = 0
			}
		}
	}

	if errBits { // Error is delayed until full syntax has been checked
		return IPv4Net{}, fmt.Errorf("%s: %w (%s expected)", s, ErrNonZeroBits, net)
	}

	return net, nil
}

func cidr2hcmask(net IPv4Net) [4][]string {
	bits := net.Bits
	var masks [4][]string
	i := 0
	for i < 4 && bits >= 8 {
		masks[i] = []string{strconv.Itoa(int(net.IP[i]))}
		bits -= 8
		i++
	}
	if bits > 0 {
		start := net.IP[i]
		masks[i] = lookup(start, start+uint8(1<<(8-bits)-1))
		i++
	}
	for i < 4 {
		masks[i] = masks0to255
		i++
	}
	return masks
}

func expand(ipmask [4][]string, cb func(mask string)) {
	var bufferPattern [len(mask200to249)*4 + 3 + len("10?4")]byte
	const defaultCharsets = cs04 + "," + cs05 + "," + cs19 + ","
	var bufferCharsets [len(defaultCharsets) + 9 /* mask for ?4 with up to 9 digits */ + 1 + cap(bufferPattern)]byte
	charsets := append(bufferCharsets[:0], defaultCharsets...)

	expandRec(charsets, bufferPattern[:0], ipmask[:], cb)
}

func expandRec(charsets []byte, pattern []byte, ipmask [][]string, cb func(mask string)) {
	if len(ipmask) == 0 {
		return
	}
	if len(pattern) > 0 {
		pattern = append(pattern, '.')
	}
	last := len(ipmask) == 1
	masks := ipmask[0]
	for i := 0; i < len(masks); i++ {
		charsets := charsets
		pattern := pattern

		mask := masks[i]
		if p := strings.IndexByte(mask, ','); p > 0 {
			charsets = append(charsets, mask[:p+1]...)
			mask = mask[p+1:]
		}
		pattern = append(pattern, mask...)
		if last {
			cb(string(append(charsets, pattern...)))
		} else {
			expandRec(charsets, pattern, ipmask[1:], cb)
		}
	}
}

func CIDR2HCMaskFunc(net IPv4Net, cb func(mask string)) {
	expand(cidr2hcmask(net), cb)
}

func CIDR2HCMask(net IPv4Net) []string {
	var masks []string
	CIDR2HCMaskFunc(net, func(mask string) {
		masks = append(masks, mask)
	})
	return masks
}

func CIDR2HCMaskWrite(net IPv4Net, w io.Writer) (err error) {
	defer func() {
		if r := recover(); r != nil {
			switch r := r.(type) {
			case error:
				err = r
			default:
				panic(r)
			}
		}
	}()
	CIDR2HCMaskFunc(net, func(mask string) {
		_, err := w.Write([]byte(mask + "\n"))
		if err != nil {
			panic(err)
		}
	})
	return
}
