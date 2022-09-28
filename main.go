package main

import (
	"easy-wireguard/tool"
	"fmt"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func main() {
	var name = "wg0"
	client, _ := wgctrl.New()
	defer client.Close()
	serverKey, _ := wgtypes.GeneratePrivateKey()
	peers, _ := wgtypes.GeneratePrivateKey()
	var conf = wgtypes.Config{
		PrivateKey:   tool.KeyPtr(serverKey),
		ListenPort:   tool.IntPtr(12912),
		FirewallMark: tool.IntPtr(0),
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: peers.PublicKey(),
				Endpoint:  tool.MustUDPAddr("[abcd:23::33%2]:51820"),
				AllowedIPs: []net.IPNet{
					tool.MustCIDR("192.168.4.4/32"),
				},
			},
		},
	}
	go tool.WgUp(name)
	time.Sleep(time.Second * 35)
	err := client.ConfigureDevice(name, conf)
	fmt.Printf("err:%v\r\n", err)
}
