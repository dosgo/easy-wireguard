package tool

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/svc/eventlog"
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
	exepath := "C:\\Program Files\\WgDrive\\wgservice.exe"
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
		err = ioutil.WriteFile(exepath, input, 0644)
		if err != nil {
			fmt.Printf("%+v\r\n", err)
			return err
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
		s.Close()
		err = errors.New("service " + serviceName + " already exists")
		fmt.Printf("%+v\r\n", err)
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
	err = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		s.Delete()
		fmt.Printf("%+v\r\n", err)
		return fmt.Errorf("SetupEventLogSource() failed: %s", err)
	}
	s.Start()
	return nil
}
