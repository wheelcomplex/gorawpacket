/*

writting udp broadcast message by rawsocket

*/

/*
REF:
	//https://github.com/skyportsystems/gopacket
	//https://github.com/skyportsystems/gopacket/blob/master/examples/synscan/main.go
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

	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"github.com/droundy/goopt"
)

//
var bindInterface = goopt.String([]string{"-I", "--interface"}, "ALL", "name of network interface, default: eth0, ALL for all interfaces")
var opMode = goopt.String([]string{"-m", "--mode"}, "recv", "operating mode, send/recv, default: send")
var targetMac = goopt.String([]string{"-M", "--MAC"}, "FF:FF:FF:FF:FF:FF", "sending to mac, default: FF:FF:FF:FF:FF:FF")
var targetIpPort = goopt.String([]string{"-t", "--target"}, "255.255.255.255:19818", "sending to host port, default: 255.255.255.255:19818")

//0c:72:2c:1f:70:09

func main() {

	goopt.Description = func() string {
		return "write udp message from special network interface."
	}
	goopt.Version = "1.0"
	goopt.Summary = "udp write interface"
	goopt.Parse(nil)
	//
	cpus := runtime.NumCPU()
	if cpus <= 1 {
		runtime.GOMAXPROCS(cpus)
	} else {
		runtime.GOMAXPROCS(cpus - 1)
	}
	//
	fmt.Printf("using %d CPU(s), %s on interface: %s\n\n", runtime.GOMAXPROCS(1), *opMode, *bindInterface)
	var err error
	interfaceList := make(map[string]*net.Interface)
	if *bindInterface == "ALL" {
		interFaceList, err := net.Interfaces()
		if err != nil {
			fmt.Printf("Interfaces %s failed: %v\n", *bindInterface, err)
			os.Exit(1)
		}
		for ethname, iface := range interFaceList {
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

	//lauch read goroutine
	for ethname, _ := range interfaceList {
		runCount++
		if *opMode == "send" {
			go broadcasting(ethname, *targetIpPort, *targetMac, doneNotify, ctlNotify)
		} else {
			go recieving(ethname, *targetIpPort, *targetMac, doneNotify, ctlNotify)
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

//
type RawSocketIO struct {
	index int    //index in group
	name  string // e.g., "udptransfer#en0", "udptransfer#eth0.100"

	iface     *net.Interface // network adapter for this unit
	opIfName  string         //dst nic name, eg., eth0
	opIpPort  string         //dst Ip:Port, eg., 255.255.255.255:19818
	opMacAddr string         //dst hardware address, eg., FF:FF:FF:FF:FF:FF

	maxPayload      int    // MTU - headerSize
	magicHeaderSize int    //
	netHeaderSize   int    // headerlen: eth 14, ip 20, udp 8 = 42
	magicHeader     []byte //magic header buffer

	handle *pcap.Handle //pcap handle for network io
	digest hash.Hash    //hash writer for payload checksum(by key=iface mac), BlockSize = 128

	//TODO: struct for send
	packetOpts     gopacket.SerializeOptions //opts for eth serialize
	packetLayerBuf gopacket.SerializeBuffer  //buff for layer Serialize
	packetBuf      []byte                    //buff for full packet

	//TODO: io filter struct
	remoteHwAddr net.HardwareAddr //dst mac address of broadcast
	remoteIP     net.IP           //sending broadcast to this IP, 255.255.255.255 or xxx.xxx.xxx.255
	remotePort   layers.UDPPort   //udp port of dst broadcast
	localHwAddr  net.HardwareAddr //dst mac address of broadcast
	localIP      net.IP           //src of broadcast packet
	localPort    layers.UDPPort   //src port of udp broadcast

	tmpBuf []byte //buffer for sending
	tmpLen int    //data length of tmpBuf

	//TODO: struct for recv
	outPacketChan chan RawPacket //for packet recv output
}

//
func (transfer *RawSocketIO) Reset() {
	transfer.index = -1
	transfer.socketID = ""

	transfer.iface = nil
	transfer.magicHeaderSize = 16
	transfer.netHeaderSize = 42
	transfer.maxPayload = 1500 - transfer.magicHeaderSize
	//
	transfer.magicHeader = make([]byte, transfer.magicHeaderSize)
	//
	transfer.magicHeader = transfer.magicHeader[:0]
	//
	//
	/*
		msg format:
		magiccode(4 bytes) + payloadLen(4 bytes) + sigText(8 bytes) = 16 bytes
		0         4                     8                  16
		+ payload
		---------
		magic code: 0002, raw socket discovery, without crypt
	*/
	//magiccode: 0x0002
	//payloadLen: len(data) //padding: 0000
	//sigText(8 bytes): transfer.digestSum(data) //padding: 00000000
	transfer.magicHeader = append(transfer.magicHeader, []byte("0002000000000000")...)

	transfer.opIfName = ""  //dst nic name, eg., eth0
	transfer.opIpPort = ""  //dst Ip:Port, eg., 255.255.255.255:19818
	transfer.opMacAddr = "" //dst hardware address, eg., FF:FF:FF:FF:FF:FF

	transfer.remoteHwAddr, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
	transfer.remoteIP = net.IPv4bcast
	transfer.remotePort = 19818
	transfer.localIP = net.IPv4zero
	transfer.localPort = 19819

	transfer.recvDST = net.IPv4zero
	transfer.recvDSTPort = 19818
	transfer.recvSRC = net.IPv4zero
	transfer.recvSRCPort = 0

	if transfer.outPacketChan != nil {
		close(transfer.outPacketChan)
		transfer.outPacketChan = nil
	}

	if transfer.tmpBuf != nil {
		transfer.tmpBuf = transfer.tmpBuf[:0]
	} else {
		transfer.tmpBuf = make([]byte, 0, 1024)
	}
	transfer.tmpLen = 0

	if transfer.recvBuf != nil {
		transfer.recvBuf = transfer.recvBuf[:0]
	} else {
		transfer.recvBuf = make([]byte, 0, 1024)
	}
	transfer.recvLen = 0
	transfer.packetOpts = gopacket.SerializeOptions{
		FixLengths:       false,
		ComputeChecksums: false,
	}

	// headerlen: eth 14, ip 20, udp 8 = 42

	if transfer.digest != nil {
		transfer.digest.Reset()
	}
	transfer.digest = nil //initial when nic selected
}

//
func NewRawSocketIO() (transfer *RawSocketIO) {
	transfer = new(RawSocketIO)
	transfer.Reset()
	return transfer
}

// WriteTo send data to target spical by nic, dstipport, dstMac
// return sent bytes or error
func (transfer *RawSocketIO) WriteTo(nic, dstipport, dstMac string, data []byte) (ioBytes int, err error) {
	//
	if transfer.handle == nil {
		if err := transfer.Dial(nic, dstipport, dstMac); err != nil {
			return 0, err
		}
		/*
			transfer.opIfName = strings.ToLower(nic)
			transfer.opIpPort = strings.ToLower(dstipport)
			transfer.opMacAddr = strings.ToLower(dstMac)
		*/
	} else if transfer.opIfName != strings.ToLower(nic) || transfer.opIpPort != strings.ToLower(dstipport) || transfer.opMacAddr != strings.ToLower(dstMac) {
		transfer.Reset()
		if err := transfer.Dial(nic, dstipport, dstMac); err != nil {
			return 0, err
		}
	} //this is the same target
	fmt.Printf("WriteTo: %s, %s, %s\n", transfer.opIfName, transfer.opIpPort, transfer.opMacAddr)
	return transfer.WriteToUDP(data)
}

//
func (transfer *RawSocketIO) Dial(nic, dstipport, dstMac string) (err error) {
	fmt.Printf("dial: %s#-1#%s\n", nic, dstipport)
	err = nil
	transfer.iface, err = net.InterfaceByName(nic)
	if err != nil {
		// error handling
		return showerr(err, "get index of "+nic)
	}
	transfer.maxPayload = transfer.iface.MTU - transfer.magicHeaderSize
	dstAddr, err := net.ResolveUDPAddr("udp4", dstipport)
	if err != nil {
		// error handling
		return showerr(err, "ResolveUDPAddr "+dstipport)
	}
	transfer.remoteIP = dstAddr.IP
	transfer.remotePort = layers.UDPPort(dstAddr.Port)
	if transfer.remoteIP == nil {
		return showerr(errors.New("invalid ip address "+dstipport), "ParseIP")
	}
	if transfer.digest != nil {
		transfer.digest.Reset()
	}
	if len(dstMac) == 0 {
		transfer.remoteHwAddr, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
	} else {
		transfer.remoteHwAddr, err = net.ParseMAC(dstMac)
		if err != nil {
			// error handling
			return showerr(err, "ParseMAC "+dstMac)
		}
	}
	var ifaddrs net.Addr
	var ifip net.IP
	ip4.SrcIP = net.IPv4zero
	ifaddrs, err = transfer.iface.Addrs()
	if err != nil {
		showerr(err, transfer.iface.Name+" iface.Addrs")
	} else if len(ifaddrs) > 0 {
		ifip, err = net.ParseIP(ifaddrs[0].String())
		if err != nil {
			showerr(err, transfer.iface.Name+" net.ParseIP "+ifaddrs[0].String())
		} else {
			ip4.SrcIP = ifip
		}
	}
	transfer.socketID = fmt.Sprintf("%s#%d=>%s#%s#%d", transfer.iface.Name, transfer.iface.Index, transfer.remoteHwAddr.String(), transfer.remoteIP.String(), transfer.remotePort)
	//fmt.Printf("sending: %s\n", transfer.socketID)
	transfer.opIfName = strings.ToLower(nic)
	transfer.opIpPort = strings.ToLower(dstipport)
	transfer.opMacAddr = strings.ToLower(dstMac)

	//create pcap handle
	// Open the handle for reading/writing.
	// Note we could very easily add some BPF filtering here to greatly
	// decrease the number of packets we have to look at when getting back
	// scan results.
	transfer.handle, err = pcap.OpenLive(transfer.iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		transfer.handle = nil
		return showerr(err, transfer.socketID+": pcap.OpenLive")
	}
	return err
}

func (transfer *RawSocketIO) createMsgBody(data []byte) int {
	/*
		msg format:
		magiccode(4 bytes) + payloadLen(4 bytes) + sigText(8 bytes) = 16 bytes
		0         4                     8                  16
		+ payload
		---------
		magic code: 0002, raw socket discovery, without crypt
	*/
	transfer.packetBuf = append(transfer.packetBuf, data...)
	return len(data)
}

// cast send payload data in udp packet

// readNextPacket try to read a udp packet match transfer.listenAddr
// send decoded data to RawPacket channel
// loop read, send back error and close the channel on read error
func (transfer *RawSocketIO) readNextPacket() RawPacket {
	return <-transfer.outPacketChan
}

// readPacketToChannel try to read a udp packet match transfer.listenAddr
// send decoded data to RawPacket channel
// loop read, send back error and close the channel on read error
func (transfer *RawSocketIO) readPacketToChannel() {

	var onePkt RawPacket

	var err error
	for {

	}
}

// startReceiveChannel return a pktChan for packet output
// the same channel returned for multi-call
// pktChan block until it got a packet or run into error
func (transfer *RawSocketIO) startReceiveChannel() (chan RawPacket, error) {

	if transfer.handle == nil {
		return nil, errors.New("raw socket handle no initialed")
	}
	if transfer.outPacketChan == nil {
		transfer.outPacketChan = make(chan RawPacket, 128)
		//background reading
		go transfer.readPacketToChannel()
		//fmt.Printf("read packet to channel started\n")
	}
	return transfer.outPacketChan, nil
}

// receivePacket try to read a udp packet match transfer.listenAddr
// block until it got a packet or run into error
// return RawPacket
func (transfer *RawSocketIO) receivePacket() RawPacket {
	if transfer.outPacketChan == nil {
		if _, err := transfer.startReceiveChannel(); err != nil {
			return RawPacket{
				IoErr: err,
			}
		}
	}
	return <-transfer.outPacketChan
}

func (transfer *RawSocketIO) SetReceiveFilter(nic, dstipport, dstMac string) (err error) {
	fmt.Printf("Receive: %s#-1#%s#%s\n", nic, dstipport, dstMac)
	err = nil
	transfer.iface, err = net.InterfaceByName(nic)
	if err != nil {
		// error handling
		return showerr(err, "get index of "+nic)
	}
	transfer.maxPayload = transfer.iface.MTU - transfer.magicHeaderSize
	dstAddr, err := net.ResolveUDPAddr("udp4", dstipport)
	if err != nil {
		// error handling
		return showerr(err, "ResolveUDPAddr "+dstipport)
	}
	transfer.remoteIP = dstAddr.IP
	transfer.remotePort = layers.UDPPort(dstAddr.Port)
	if transfer.remoteIP == nil {
		return showerr(errors.New("invalid ip address "+dstipport), "ParseIP")
	}
	if transfer.digest != nil {
		transfer.digest.Reset()
	}
	if len(dstMac) == 0 {
		transfer.remoteHwAddr, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
	} else {
		transfer.remoteHwAddr, err = net.ParseMAC(dstMac)
		if err != nil {
			// error handling
			return showerr(err, "ParseMAC "+dstMac)
		}
	}
	transfer.socketID = fmt.Sprintf("%s#%d=>%s#%s#%d", transfer.iface.Name, transfer.iface.Index, transfer.remoteHwAddr.String(), transfer.remoteIP.String(), transfer.remotePort)
	//fmt.Printf("sending: %s\n", transfer.socketID)
	transfer.opIfName = strings.ToLower(nic)
	transfer.opIpPort = strings.ToLower(dstipport)
	transfer.opMacAddr = strings.ToLower(dstMac)
}

//
func broadcasting(nic, ipport, mac string, resultChan chan string, ctlChan chan string) {
	transfer := NewRawSocketIO()
	transfer.SetSendTPL()
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
			resultChan <- transfer.socketID + " exit by control MSG: " + ctlMSG
			return
		default:
		}
		data = transfer.tmpBuf[:transfer.tmpLen]
		data = append(data, []byte(" ")...)
		data = append(data, ts.String()...)
		data = append(data, []byte("\n")...)
		//ioBytes, err = transfer.WriteToUDP(data)
		ioBytes, err = transfer.WriteTo(nic, ipport, mac, data)
		if err != nil {
			// error handling
			showerr(err, transfer.socketID+" transfer.WriteToUDP")
			resultChan <- transfer.socketID + " exit with error: " + err.Error()
			break
		}
		fmt.Printf("%s out Msg(%d/%d): %s", transfer.socketID, ioBytes, len(data), data)
		data = nil
		ts = <-ioTk.C
	}
}

//

//
func recieving(nic, ipport, mac string, resultChan chan string, ctlChan chan string) {
	transfer := NewRawSocketIO()
	defer transfer.Reset()
	//
	var ctlMSG string
	var onePkt RawPacket

	err := transfer.SetReceiveFilter(nic, ipport, mac)
	if err != nil {
		resultChan <- transfer.socketID + " exit for SetReceiveFilter: " + err.Error()
		return
	}
	//
	_, err = transfer.startReceiveChannel()
	if err != nil {
		resultChan <- transfer.socketID + " exit for startReceiveChannel: " + err.Error()
		return
	}
	//

	for {
		select {
		case ctlMSG = <-ctlChan:
			resultChan <- transfer.socketID + " exit by control MSG: " + ctlMSG
			return
		case onePkt = <-transfer.outPacketChan:
			if onePkt.IoErr != nil {
				// error handling
				showerr(onePkt.IoErr, transfer.socketID+" transfer.outPacketChan")
				resultChan <- transfer.socketID + " exit with error: " + onePkt.IoErr.Error()
				break
			}
			//
			//TODO: filter no discovery packet
			//
			//ts := time.Now()
			//fmt.Printf("\n------\n%s, %s out Msg(%d): %s", ts.String(), transfer.socketID, len(onePkt.payLoad), onePkt.payLoad)
		}
	}
}
