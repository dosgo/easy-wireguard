package main

import (
	"crypto/md5"
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
	} else if os.Args[1] == "delPeer" {
		//添加addPeer节点
		delPeer(name, os.Args[3])
	} else {
		help(fName)
	}
}

func help(fName string) {
	fmt.Println(fName + " start  [name]")
	fmt.Println(fName + " genServerConf  [name]")
	fmt.Println(fName + " addPeer  [name]")
	fmt.Println(fName + " delPeer  name pubkey")
}

func start(name string) {
	_, err := os.Stat(name + ".conf")
	if err != nil {
		genServerConf(name)
	}
	conf, _ := tool.FileToConf(name)
	go tool.WgUp(name)
	time.Sleep(time.Second * 10)
	client, _ := wgctrl.New()
	xx, err := client.Devices()
	fmt.Printf("Devices:%+v err:%+v\r\n", xx, err)
	defer client.Close()
	err = client.ConfigureDevice(name, conf)
	select {}
}
func genServerConf(name string) {
	_, err := os.Stat(name + ".conf")
	if err == nil {
		fmt.Println("Configuration file " + name + ".conf already exists")
		return
	}
	serverKey, _ := wgtypes.GeneratePrivateKey()
	var conf = wgtypes.Config{
		PrivateKey: tool.KeyPtr(serverKey),
		ListenPort: tool.IntPtr(51820),
		//ReplacePeers: true,
	}
	var allowedIP = tool.MustCIDR("192.168.6.1/32")
	tool.ConfToFile(name, conf, &allowedIP)
}
func addPeer(name string) {
	peerKey, _ := wgtypes.GeneratePrivateKey()
	//读取服务器配置文件
	ServerConf, address := tool.FileToConf(name)
	//生成peer配置文件
	var allowedIP = tool.MustCIDR("0.0.0.0/0")
	var allowedIPs = []net.IPNet{
		allowedIP,
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
	tool.ConfToFile(name, ServerConf, &address)
	address.IP[3] = address.IP[3] + 1
	//生成peer配置文件
	pubKeyByte := peerKey.PublicKey()
	var h = md5.New()
	h.Write(pubKeyByte[:])
	md5Str := hex.EncodeToString(h.Sum(nil))
	tool.ConfToFile(name+"_peer_"+md5Str[:5], peerConf, &address)
}

func delPeer(name string, pubKey string) {
	//读取服务器配置文件
	ServerConf, address := tool.FileToConf(name)
	publicKey, _ := wgtypes.ParseKey(pubKey)

	for i := 0; i < len(ServerConf.Peers); i++ {
		if ServerConf.Peers[i].PublicKey == publicKey {
			ServerConf.Peers = append(ServerConf.Peers[:i], ServerConf.Peers[i+1:]...)
			i--
		}
	}
	//修改server配置文件
	tool.ConfToFile(name, ServerConf, &address)
	os.Remove(name + "_peer_" + hex.EncodeToString(publicKey[:]) + ".conf")
}
