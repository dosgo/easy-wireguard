package tool

import (
	"encoding/hex"
	"log"
	"net"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// MustHexKey decodes a hex string s as a key or panics.
func MustHexKey(s string) wgtypes.Key {
	b, err := hex.DecodeString(s)
	if err != nil {
		log.Printf("wgtest: failed to decode hex key: %v", err)
	}

	k, err := wgtypes.NewKey(b)
	if err != nil {
		log.Printf("wgtest: failed to create key: %v", err)
	}

	return k
}

func MustUDPAddr(s string) *net.UDPAddr {
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		log.Printf("wgtest: failed to resolve UDP address: %v", err)
	}

	return a
}

func MustCIDR(s string) net.IPNet {
	_, cidr, err := net.ParseCIDR(s)
	if err != nil {
		log.Printf("wgtest: failed to parse CIDR: %v", err)
	}

	return *cidr
}

func KeyPtr(k wgtypes.Key) *wgtypes.Key { return &k }
func IntPtr(v int) *int                 { return &v }
