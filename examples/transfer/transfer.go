/*
send/recieve broadcast message by udp raw socket
*/

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/fnv"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/droundy/goopt"
	"github.com/wheelcomplex/gorawpacket"
)

//
var bindInterface = goopt.String([]string{"-I", "--interface"}, "ALL", "name of network interface, default: eth0, ALL for all interfaces")
var opMode = goopt.String([]string{"-m", "--mode"}, "recv", "operating mode, send/recv, default: send")
var targetMac = goopt.String([]string{"-M", "--MAC"}, "FF:FF:FF:FF:FF:FF", "sending to mac, default: FF:FF:FF:FF:FF:FF")
var targetIpPort = goopt.String([]string{"-t", "--target"}, "255.255.255.255:19818", "sending to host port, default: 255.255.255.255:19818")
var magicCode = goopt.String([]string{"-g", "--magic"}, "0002", "packet magic code, default: 0002, raw socket discovery, without crypt")

//0c:72:2c:1f:70:09

func main() {

	goopt.Description = func() string {
		return "read/write udp message from special network interface by raw socket."
	}
	goopt.Version = "1.0"
	goopt.Summary = "read/write udp raw packet"
	goopt.Parse(nil)
	//
	setGOMAXPROCS(2)
	//
	fmt.Printf("using %d CPU(s), magic code %s, %s on interface: %s\n\n", runtime.GOMAXPROCS(1), *magicCode, *opMode, *bindInterface)
	var err error
	interfaceList := make(map[string]*net.Interface)
	if *bindInterface == "ALL" {
		interFacelist, err := net.Interfaces()
		if err != nil {
			fmt.Printf("Interfaces %s failed: %v\n", *bindInterface, err)
			os.Exit(1)
		}
		for ethname, iface := range interFacelist {
			interfaceList[iface.Name], err = net.InterfaceByName(iface.Name)
			if err != nil {
				fmt.Printf("InterfaceByName #%d/%v failed: %v\n", ethname, iface.Name, err)
				os.Exit(1)
			}
		}
	} else {
		interfaceList[*bindInterface], err = net.InterfaceByName(*bindInterface)
		if err != nil {
			fmt.Printf("InterfaceByName %s failed: %v\n", *bindInterface, err)
			os.Exit(1)
		}

	}
	if len(interfaceList) == 0 {
		fmt.Printf("network interface no exist\n")
		os.Exit(1)
	}
	//clean up list
	var rmkey bool = true
	var cleaned int = 0
	for ethname, iface := range interfaceList {
		rmkey = true
		switch {
		case iface.Flags&net.FlagUp == 0:
			fmt.Printf("Down#%v, %v\r\n", ethname, iface)
		case iface.Flags&net.FlagLoopback != 0:
			fmt.Printf("Loopback#%v, %v\r\n", ethname, iface)
		case iface.Flags&net.FlagBroadcast == 0:
			fmt.Printf("NoBroadcast#%v, %v\r\n", ethname, iface)
		case iface.Flags&net.FlagMulticast == 0:
			fmt.Printf("NoMulticast#%v, %v\r\n", ethname, iface)
		case iface.Flags&net.FlagPointToPoint != 0:
			fmt.Printf("PointToPoint#%v, %v\r\n", ethname, iface)
		case iface.HardwareAddr.String() == "":
			fmt.Printf("NoETH#%v, %v\r\n", ethname, iface)
		default:
			rmkey = false
		}
		if rmkey {
			cleaned++
			delete(interfaceList, ethname)
		}
	}
	if cleaned > 0 {
		fmt.Printf("\n")
	}
	//initial transfer list

	fmt.Printf("%s from interface: \n", *opMode)
	for ethname, transfer := range interfaceList {
		if strings.Contains(ethname, ":") {
			fmt.Printf("              IPV6#%s#%d => %s %s\n", ethname, *targetMac, *targetIpPort)
		} else {
			fmt.Printf("              IPV4#%s#%d => %s %s\n", ethname, *targetMac, *targetIpPort)
		}
	}

	doneNotify := make(chan string, 1024)
	ctlNotify := make(chan string, 1024)
	runCount := 0

	//lauch goroutine
	for ethname, _ := range interfaceList {
		runCount++
		if *opMode == "send" {
			go broadcasting(ethname, *targetIpPort, *targetMac, *magicCode, doneNotify, ctlNotify)
		} else {
			go recieving(ethname, *targetIpPort, *targetMac, *magicCode, doneNotify, ctlNotify)
		}

	}
	interfaceList = nil

	for doneMsg := range doneNotify {
		fmt.Printf("exit Msg: %v\n", doneMsg)
		runCount--
		if runCount <= 0 {
			break
		}
	}
}

// end of main

//
func setGOMAXPROCS(use_cpu_num int) (rcpu int) {
	//
	rcpu = use_cpu_num
	switch {
	case use_cpu_num <= -1:
		rcpu = runtime.NumCPU()
	case use_cpu_num == 0 && runtime.NumCPU() > 1:
		rcpu = runtime.NumCPU() - 1
	case runtime.NumCPU() >= use_cpu_num:
		rcpu = use_cpu_num
	case runtime.NumCPU() < use_cpu_num:
		//rcpu = runtime.NumCPU()
		fmt.Fprintf(os.Stderr, "WARNING: execpt %d CPU to run, but onely %d CPU present.\n", use_cpu_num, runtime.NumCPU())
	}
	runtime.GOMAXPROCS(rcpu)
	return rcpu
}

//
func broadcasting(nic, ipport, mac, code string, resultChan chan string, ctlChan chan string) {
	transfer := NewRawSocketIO()
	transfer.SetSendTPL()
	//
	defer transfer.Reset()
	//
	ioTk := time.NewTicker(1e9 * 5)
	defer func() {
		ioTk.Stop()
	}()
	ts := time.Now()
	var ioBytes int
	var err error
	var ctlMSG string
	var data []byte
	for {
		select {
		case ctlMSG = <-ctlChan:
			resultChan <- WriteTo + " exit by control MSG: " + ctlMSG
			return
		default:
		}
		data = transfer.tmpBuf[:transfer.tmpLen]
		data = append(data, []byte(" ")...)
		data = append(data, ts.String()...)
		data = append(data, []byte("\n")...)
		//ioBytes, err = transfer.cast(data)
		ioBytes, err = transfer.Sendto(nic, ipport, mac, data)
		if err != nil {
			// error handling
			showerr(err, WriteTo+" transfer.cast")
			resultChan <- WriteTo + " exit with error: " + err.Error()
			break
		}
		fmt.Printf("%s out Msg(%d/%d): %s", WriteTo, ioBytes, len(data), data)
		data = nil
		ts = <-ioTk.C
	}
}

//

//
func recieving(nic, ipport, mac, code string, resultChan chan string, ctlChan chan string) {
	transfer := NewRawSocketIO()
	defer transfer.Reset()
	//
	var ctlMSG string
	var onePkt RawPacket

	err := transfer.SetReceiveFilter(nic, ipport, mac)
	if err != nil {
		resultChan <- WriteTo + " exit for SetReceiveFilter: " + err.Error()
		return
	}
	//
	_, err = transfer.startReceiveChannel()
	if err != nil {
		resultChan <- WriteTo + " exit for startReceiveChannel: " + err.Error()
		return
	}
	//

	for {
		select {
		case ctlMSG = <-ctlChan:
			resultChan <- WriteTo + " exit by control MSG: " + ctlMSG
			return
		case onePkt = <-transfer.recvPktChan:
			if onePkt.IoErr != nil {
				// error handling
				showerr(onePkt.IoErr, WriteTo+" transfer.recvPktChan")
				resultChan <- WriteTo + " exit with error: " + onePkt.IoErr.Error()
				break
			}
			//
			//TODO: filter no discovery packet
			//
			//ts := time.Now()
			//fmt.Printf("\n------\n%s, %s out Msg(%d): %s", ts.String(), WriteTo, len(onePkt.payLoad), onePkt.payLoad)
		}
	}
}

//
