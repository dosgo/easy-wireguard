package tool

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

func WinWgUp(interfaceName string, errs chan error) error {
	tun, err := tun.CreateTUN(interfaceName, 0)
	if err == nil {
		realInterfaceName, err2 := tun.Name()
		if err2 == nil {
			interfaceName = realInterfaceName
		}
	} else {
		return err
	}
	logger := device.NewLogger(
		device.LogLevelError,
		fmt.Sprintf("(%s) ", interfaceName),
	)
	device := device.NewDevice(tun, conn.NewDefaultBind(), logger)
	err = device.Up()
	if err != nil {
		fmt.Printf("device err:%+v\r\n", err)
		return err
	}

	uapi, err := ipc.UAPIListen(interfaceName)
	if err != nil {
		fmt.Printf("uapi err:%+v\r\n", err)
		return err
	}

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go device.IpcHandle(conn)
		}
	}()

	// wait for program to terminate
	select {
	case <-errs:
	case <-device.Wait():
	}

	// clean up
	uapi.Close()
	device.Close()

	return nil
}

func WgUp(interfaceName string) error {
	srcFile := "wgdrive.dll"
	cfgFile := GetConfPath(interfaceName)
	exepath := "C:\\Program Files\\WgDrive\\wgservice.exe"
	cfgFilePath := "C:\\Program Files\\WgDrive\\" + interfaceName + ".conf"
	input, err := os.ReadFile(srcFile)
	if err != nil {
		fmt.Printf("%+v\r\n", err)
		return err
	}

	_, err = os.Stat(exepath)
	if err != nil {

		dir := filepath.Dir(exepath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
		err = os.WriteFile(exepath, input, 0644)
		if err != nil {
			fmt.Printf("%+v\r\n", err)
			return err
		}
	}

	_, err = os.Stat(cfgFilePath)
	if err != nil {
		conf, err := os.ReadFile(cfgFile)
		if err == nil {
			os.WriteFile(cfgFilePath, conf, 0644)
		}
	}

	//instart
	const serviceName = "WireGuard Service"
	const serviceDescription = "WireGuard service"
	m, err := mgr.Connect()
	if err != nil {
		fmt.Printf("%+v\r\n", err)
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err == nil {
		err = errors.New("service " + serviceName + " already exists")
		fmt.Printf("%+v\r\n", err)
		s.Start()
		s.Close()
		return err
	}
	s, err = m.CreateService(serviceName, exepath, mgr.Config{DisplayName: serviceName,
		StartType:   mgr.StartAutomatic,
		Description: serviceDescription}, interfaceName)
	if err != nil {
		fmt.Printf("%+v\r\n", err)
		return err
	}
	defer s.Close()
	s.Start()
	return nil
}

const (
	_NCBCONFIG = 0x00000000
)

func SetupWindowsNetwork(ifaceName, serverIP string, subnetMask string) error {

	// 加载 iphlpapi.dll
	dll := windows.NewLazyDLL("iphlpapi.dll")
	proc := dll.NewProc("SetAdapterIpAddress")
	fmt.Printf("serverIP:%s\r\n", serverIP)
	fmt.Printf("subnetMask:%s\r\n", subnetMask)
	// 调用 API（需根据实际参数调整）
	ret, _, err := proc.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(ifaceName))),
		uintptr(_NCBCONFIG),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(serverIP))),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(subnetMask))),
	)

	if ret != 0 {
		fmt.Printf("API 调用失败: %v\n", err)
	}
	return nil
}
