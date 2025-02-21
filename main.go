package main

import (
	"easy-wireguard/tool"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func init() {
	os.Mkdir("./conf", 0755)
}

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
	} else if os.Args[1] == "install" {
		//添加addPeer节点
		install(name)
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

func install(name string) {
	tool.WgUp(name)
}

func start(name string) {
	confFile := getConfPath(name)
	_, err := os.Stat(confFile)
	if err != nil {
		genServerConf(confFile)
	}
	conf, _ := tool.FileToConf(confFile)
	//runFlag := make(chan error)
	//tool.WinWgUp(name, runFlag)
	tool.WgUp(name)
	time.Sleep(time.Second * 10)
	client, _ := wgctrl.New()
	defer client.Close()
	err = client.ConfigureDevice(name, conf)
	// 捕获系统信号
	quit := make(chan os.Signal)
	// 前台时，按 ^C 时触发
	signal.Notify(quit, syscall.SIGINT)
	// 后台时，kill 时触发。kill -9 时的信号 SIGKILL 不能捕捉，所以不用添加
	signal.Notify(quit, syscall.SIGTERM)
	<-quit
}
func genServerConf(confFile string) {
	_, err := os.Stat(confFile)
	if err == nil {
		fmt.Println("Configuration file " + confFile + " already exists")
		return
	}
	serverKey, _ := wgtypes.GeneratePrivateKey()
	var conf = wgtypes.Config{
		PrivateKey: tool.KeyPtr(serverKey),
		ListenPort: tool.IntPtr(51820),
		//ReplacePeers: true,
	}
	tool.ConfToFile(confFile, conf, "192.168.6.1/24", true)
}
func addPeer(name string) {
	confFile := getConfPath(name)
	peerKey, _ := wgtypes.GeneratePrivateKey()
	//读取服务器配置文件
	ServerConf, address := tool.FileToConf(confFile)

	//生成peer配置文件
	var allowedIP = tool.MustCIDR(address)
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

	peerAddrs := []string{}
	for i := 0; i < len(ServerConf.Peers); i++ {
		for j := 0; j < len(ServerConf.Peers[i].AllowedIPs); j++ {
			peerAddrs = append(peerAddrs, ServerConf.Peers[i].AllowedIPs[j].IP.String())
		}
	}

	//添加到服务器peer节点

	_clientAddress, _ := tool.GetNextAvailableIP(address, peerAddrs)
	clientAddress := _clientAddress + "/32"
	_, clientMask, _ := net.ParseCIDR(clientAddress)

	peerInfo := wgtypes.PeerConfig{
		PublicKey: peerKey.PublicKey(),
		AllowedIPs: []net.IPNet{
			*clientMask,
		},
	}
	ServerConf.Peers = append(ServerConf.Peers, peerInfo)
	//生成server配置文件
	tool.ConfToFile(confFile, ServerConf, address, true)

	//生成peer配置文件
	tool.ConfToFile(getConfPath(name+"_peer_"+_clientAddress), peerConf, clientAddress, false)
}

func delPeer(name string, pubKey string) {
	confFile := getConfPath(name)
	//读取服务器配置文件
	ServerConf, address := tool.FileToConf(confFile)
	publicKey, _ := wgtypes.ParseKey(pubKey)

	var clientAddr = ""
	for i := 0; i < len(ServerConf.Peers); i++ {
		if ServerConf.Peers[i].PublicKey == publicKey {
			if len(ServerConf.Peers[i].AllowedIPs) > 0 {
				clientAddr = ServerConf.Peers[i].AllowedIPs[0].IP.String()
			}
			ServerConf.Peers = append(ServerConf.Peers[:i], ServerConf.Peers[i+1:]...)
			i--
		}
	}
	//修改server配置文件
	tool.ConfToFile(confFile, ServerConf, address, true)
	os.Remove(getConfPath(name + "_peer_" + clientAddr))
}

func getConfPath(name string) string {
	return "./conf" + "/" + name + ".conf"
}
