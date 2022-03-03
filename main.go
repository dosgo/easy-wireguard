package main

import (
	"net"
	"time"
	"easy-wireguard/tool"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func main() {
	client, _ := wgctrl.New()
	defer client.Close()
	var conf = wgtypes.Config{
		PrivateKey:   keyPtr(tool.MustHexKey("e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a")),
		ListenPort:   intPtr(12912),
		FirewallMark: intPtr(0),
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:         tool.MustHexKey("b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33"),
				PresharedKey:      keyPtr(tool.MustHexKey("188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52")),
				Endpoint:          tool.MustUDPAddr("[abcd:23::33%2]:51820"),
				ReplaceAllowedIPs: true,
				AllowedIPs: []net.IPNet{
					tool.MustCIDR("192.168.4.4/32"),
				},
			},
			{
				PublicKey:                   tool.MustHexKey("58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376"),
				UpdateOnly:                  true,
				Endpoint:                    tool.MustUDPAddr("182.122.22.19:3233"),
				PersistentKeepaliveInterval: durPtr(111 * time.Second),
				ReplaceAllowedIPs:           true,
				AllowedIPs: []net.IPNet{
					tool.MustCIDR("192.168.4.6/32"),
				},
			},
			{
				PublicKey:         tool.MustHexKey("662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58"),
				Endpoint:          tool.MustUDPAddr("5.152.198.39:51820"),
				ReplaceAllowedIPs: true,
				AllowedIPs: []net.IPNet{
					tool.MustCIDR("192.168.4.10/32"),
					tool.MustCIDR("192.168.4.11/32"),
				},
			},
			{
				PublicKey: tool.MustHexKey("e818b58db5274087fcc1be5dc728cf53d3b5726b4cef6b9bab8f8f8c2452c25c"),
				Remove:    true,
			},
		},
	};
	client.ConfigureDevice("ddd",conf)
	select{}
}

func durPtr(d time.Duration) *time.Duration { return &d }
func keyPtr(k wgtypes.Key) *wgtypes.Key     { return &k }
func intPtr(v int) *int                     { return &v }
