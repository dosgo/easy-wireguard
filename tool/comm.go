package tool

import (
	"encoding/hex"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/ini.v1"
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
	if strings.Count(s, ":") > 3 {
		pos := strings.LastIndex(s, ":")
		port := s[pos+1:]
		s = "[" + s[:pos] + "]" + ":" + port
	}
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

func ConfToFile(name string, conf wgtypes.Config) {

	cfg := ini.Empty(ini.LoadOptions{AllowNonUniqueSections: true})
	section, _ := cfg.NewSection("Interface")
	section.NewKey("PrivateKey", conf.PrivateKey.String())
	if conf.ListenPort != nil {
		section.NewKey("ListenPort", strconv.Itoa(*conf.ListenPort))
	}
	//section.NewKey("ReplacePeers", strconv.FormatBool(conf.ReplacePeers))
	for _, value := range conf.Peers {
		section, err := cfg.NewSection("Peer")
		if err == nil {
			section.NewKey("PublicKey", value.PublicKey.String())
			var allowedIPs []string
			for _, allowedIP := range value.AllowedIPs {
				allowedIPs = append(allowedIPs, allowedIP.String())
			}
			section.NewKey("AllowedIPs", strings.Join(allowedIPs, " "))
			if value.Endpoint != nil {
				section.NewKey("Endpoint", value.Endpoint.String())
			}
			if value.PersistentKeepaliveInterval != nil {
				section.NewKey("PersistentKeepalive", value.PersistentKeepaliveInterval.String())
			}
			if value.PresharedKey != nil {
				section.NewKey("PresharedKey", value.PresharedKey.String())
			}
		}

	}
	cfg.SaveTo(name + ".conf")
}

func FileToConf(name string) wgtypes.Config {
	var conf = wgtypes.Config{}
	cfg, err := ini.LoadSources(ini.LoadOptions{AllowNonUniqueSections: true}, name+".conf")
	if err == nil {
		sections := cfg.Sections()
		for _, section := range sections {
			if section.Name() == "Interface" {
				privateKey, _ := wgtypes.ParseKey(section.Key("PrivateKey").String())
				conf.PrivateKey = KeyPtr(privateKey)
				listenPort := section.Key("ListenPort").MustInt()
				conf.ListenPort = &listenPort
				//replacePeers, _ := section.Key("ReplacePeers").Bool()
				conf.ReplacePeers = true // replacePeers
			}
			if section.Name() == "Peer" {
				var peerItem = wgtypes.PeerConfig{}
				publicKey, _ := wgtypes.ParseKey(section.Key("PublicKey").String())
				peerItem.PublicKey = publicKey
				var allowedIPs []net.IPNet

				allowedIPsStrs := strings.Split(section.Key("AllowedIPs").String(), " ")
				for _, allowedIPsStr := range allowedIPsStrs {
					allowedIPs = append(allowedIPs, MustCIDR(allowedIPsStr))
				}
				peerItem.AllowedIPs = allowedIPs
				if section.Haskey("Endpoint") {
					peerItem.Endpoint = MustUDPAddr(section.Key("Endpoint").String())
				}
				if section.Haskey("PersistentKeepalive") {
					persistentKeepalive := time.Duration(section.Key("PersistentKeepalive").MustInt64() * int64(time.Second))
					peerItem.PersistentKeepaliveInterval = &persistentKeepalive
				}

				if section.Haskey("PresharedKey") {
					presharedKey, _ := wgtypes.ParseKey(section.Key("PresharedKey").String())
					peerItem.PresharedKey = &presharedKey
				}
				conf.Peers = append(conf.Peers, peerItem)
			}
		}
	}
	return conf
}

func IsPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
		return false
	}
	// IPv4私有地址空间
	// A类：10.0.0.0到10.255.255.255
	// B类：172.16.0.0到172.31.255.255
	// C类：192.168.0.0到192.168.255.255
	if ip4 := ip.To4(); ip4 != nil {
		switch true {
		case ip4[0] == 10:
			return false
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return false
		case ip4[0] == 192 && ip4[1] == 168:
			return false
		case ip4[0] == 169 && ip4[1] == 254:
			return false
		default:
			return true
		}
	}
	// IPv6私有地址空间：以前缀FEC0::/10开头
	if ip6 := ip.To16(); ip6 != nil {
		if ip6[0] == 15 && ip6[1] == 14 && ip6[2] <= 12 {
			return false
		}
		return true
	}
	return false
}

/*获取公网ip(如果没有就随便一个ip)*/
func GetPublicIP() (ip string, err error) {
	var (
		addrs   []net.Addr
		addr    net.Addr
		ipNet   *net.IPNet // IP地址
		isIpNet bool
	)
	// 获取所有网卡
	if addrs, err = net.InterfaceAddrs(); err == nil {
		//取公网IP
		for _, addr = range addrs {
			// 这个网络地址是IP地址: ipv4, ipv6
			if ipNet, isIpNet = addr.(*net.IPNet); isIpNet && !ipNet.IP.IsLoopback() {
				if IsPublicIP(ipNet.IP) {
					ip = ipNet.IP.String()
					return
				}
			}
		}
		//如果没有就直接取一个随便的ip
		for _, addr = range addrs {
			// 这个网络地址是IP地址: ipv4, ipv6
			if ipNet, isIpNet = addr.(*net.IPNet); isIpNet && !ipNet.IP.IsLoopback() {
				if ipNet.IP.To4() != nil {
					ip = ipNet.IP.String()
					return
				}
			}
		}
	}
	return
}
