package main

import (
	"easy-wireguard/tool"
	"errors"
	"fmt"
	"os"

	"github.com/kardianos/service"
)

const serviceName = "WireGuard Service"
const serviceDescription = "WireGuard service"

var devName = "wg0"

type program struct{ runFlag chan error }

func (p program) Start(s service.Service) error {
	go p.run()
	return nil
}

func (p program) Stop(s service.Service) error {
	p.runFlag <- errors.New("service stop")
	return nil
}

func (p program) run() {
	tool.WinWgUp(devName, p.runFlag)
}

func main() {
	if len(os.Args) >= 2 {
		devName = os.Args[1]
		return
	}
	serviceConfig := &service.Config{
		Name:        serviceName,
		DisplayName: serviceName,
		Description: serviceDescription,
	}
	prg := &program{}
	prg.runFlag = make(chan error)
	s, err := service.New(prg, serviceConfig)
	if err != nil {
		fmt.Println("Cannot create the service: " + err.Error())
	}
	err = s.Run()
	if err != nil {
		fmt.Println("Cannot start the service: " + err.Error())
	}
}
