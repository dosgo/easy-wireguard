package main

import (
	"easy-wireguard/tool"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func main() {
	var name = "wg0"
	fName := filepath.Base(os.Args[0])
	if len(os.Args) < 2 {
		help(fName)
		return
	}
	if len(os.Args) >= 3 {
		name = os.Args[2]
	}
	/*启动*/
	if os.Args[1] == "start" {
		start(name)
	} else if os.Args[1] == "genServerConf" {
		//生成配置文件
		genServerConf(name)
	} else if os.Args[1] == "addPeer" {
		//添加addPeer节点
		addPeer(name)
	} else {
		help(fName)
	}
}

func help(fName string) {
	fmt.Println(fName + " start  [name]")
	fmt.Println(fName + " genServerConf  [name]")
	fmt.Println(fName + " addPeer  [name]")
}

func start(name string) {
	_, err := os.Stat(name + ".conf")
	if err != nil {
		genServerConf(name)
	}
	conf := tool.FileToConf(name)
	client, _ := wgctrl.New()
	defer client.Close()
	go tool.WgUp(name)
	time.Sleep(time.Second * 35)
	client.ConfigureDevice(name, conf)
}
func genServerConf(name string) {
	_, err := os.Stat(name + ".conf")
	if err == nil {
		fmt.Println("Configuration file " + name + ".conf already exists")
		return
	}
	serverKey, _ := wgtypes.GeneratePrivateKey()
	var conf = wgtypes.Config{
		PrivateKey:   tool.KeyPtr(serverKey),
		ListenPort:   tool.IntPtr(51820),
		ReplacePeers: true,
	}
	tool.ConfToFile(name, conf)
}
func addPeer(name string) {
	peerKey, _ := wgtypes.GeneratePrivateKey()
	//读取服务器配置文件
	ServerConf := tool.FileToConf(name)
	//生成peer配置文件
	var allowedIPs = []net.IPNet{
		tool.MustCIDR("192.168.6.1/32"),
	}
	ip, _ := tool.GetPublicIP()
	var endpoint = tool.MustUDPAddr(ip + ":" + strconv.Itoa(*ServerConf.ListenPort))
	var peerConf = wgtypes.Config{
		PrivateKey: tool.KeyPtr(peerKey),
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:  ServerConf.PrivateKey.PublicKey(),
				Endpoint:   endpoint,
				AllowedIPs: allowedIPs,
			},
		},
	}
	//添加到服务器peer节点
	peerInfo := wgtypes.PeerConfig{
		PublicKey:  peerKey.PublicKey(),
		AllowedIPs: allowedIPs,
	}
	ServerConf.Peers = append(ServerConf.Peers, peerInfo)
	//生成server配置文件
	tool.ConfToFile(name, ServerConf)
	//生成peer配置文件
	pubKeyByte := peerKey.PublicKey()
	tool.ConfToFile(name+"_peer_"+hex.EncodeToString(pubKeyByte[:]), peerConf)
}

func delPeer(name string, pubKey string) {
	//读取服务器配置文件
	ServerConf := tool.FileToConf(name)
	publicKey, _ := wgtypes.ParseKey(pubKey)

	for i := 0; i < len(ServerConf.Peers); i++ {
		if ServerConf.Peers[i].PublicKey == publicKey {
			ServerConf.Peers = append(ServerConf.Peers[:i], ServerConf.Peers[i+1:]...)
			i--
		}
	}

	//修改server配置文件
	tool.ConfToFile(name, ServerConf)
	os.Remove(name + "_peer_" + hex.EncodeToString(publicKey[:]) + ".conf")
}
