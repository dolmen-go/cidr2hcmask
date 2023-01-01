package cidr2hcmask_test

import (
	"testing"

	"github.com/dolmen-go/cidr2hcmask"
)

func TestCIDR2HCMask(t *testing.T) {
	net, err := cidr2hcmask.ParseCIDR("192.168.1.0/28")
	if err != nil {
		panic(err)
	}
	cidr2hcmask.CIDR2HCMaskFunc(net, func(mask string) {
		t.Log(mask)
	})
}
