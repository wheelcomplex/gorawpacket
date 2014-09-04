/*

gorawpacket send/recieve udp/tcp/arp message by raw socket

usage:
func mode: using RawPktConn struct direct, call Read/Write func
broker mode: run RawPktConn standalone udp broker(by root), other proc send rawPktFrame to broker and read response

*/

package gorawpacket

import (
	"bytes" // Package bytes implements functions for the manipulation of byte slices. It is analogous to the facilities of the strings package.
	"encoding/binary"
	"errors"
	"fmt"
	//"hash"
	//"hash/fnv"
	"net"
	//"os"
	//"runtime"
	//"strings"
	"strconv"
	"sync"
	"syscall"
	"time"

	//"code.google.com/p/gopacket"
	//"code.google.com/p/gopacket/layers"
	//"code.google.com/p/gopacket/pcap"
)

//
// TODO: add more protocol, eg., arp/icmp
// TODO: magic transport
// TODO: turbidity transport protocol
//

//
/*
	raw packet format:
	eth-hdr(14 bytes)+ip-hdr(20 bytes)+udp-hdr(8 bytes)+raw packet payload
	header len: eth 14, ip 20, udp 8 = 42 bytes
*/
//

// start of copy code.google.com/p/gopacket/layers/enums.go

// EthernetType is an enumeration of ethernet type values, and acts as a decoder
// for any type it supports.
type EthernetType uint16

const (
	// EthernetTypeLLC is not an actual ethernet type.  It is instead a
	// placeholder we use in Ethernet frames that use the 802.3 standard of
	// srcmac|dstmac|length|LLC instead of srcmac|dstmac|ethertype.
	EthernetTypeLLC                EthernetType = 0
	EthernetTypeIPv4               EthernetType = 0x0800
	EthernetTypeARP                EthernetType = 0x0806
	EthernetTypeIPv6               EthernetType = 0x86DD
	EthernetTypeCiscoDiscovery     EthernetType = 0x2000
	EthernetTypeNortelDiscovery    EthernetType = 0x01a2
	EthernetTypeDot1Q              EthernetType = 0x8100
	EthernetTypePPPoEDiscovery     EthernetType = 0x8863
	EthernetTypePPPoESession       EthernetType = 0x8864
	EthernetTypeMPLSUnicast        EthernetType = 0x8847
	EthernetTypeMPLSMulticast      EthernetType = 0x8848
	EthernetTypeEAPOL              EthernetType = 0x888e
	EthernetTypeLinkLayerDiscovery EthernetType = 0x88cc
	EthernetTypeEthernetCTP        EthernetType = 0x9000
)

// IPProtocol is an enumeration of IP protocol values, and acts as a decoder
// for any type it supports.
type IPProtocol uint8

const (
	IPProtocolIPv6HopByHop IPProtocol = 0
	IPProtocolICMPv4       IPProtocol = 1
	IPProtocolIGMP         IPProtocol = 2
	IPProtocolTCP          IPProtocol = 6
	IPProtocolUDP          IPProtocol = 17
	IPProtocolRUDP         IPProtocol = 27
	IPProtocolIPv6         IPProtocol = 41
	IPProtocolIPv6Routing  IPProtocol = 43
	IPProtocolIPv6Fragment IPProtocol = 44
	IPProtocolGRE          IPProtocol = 47
	IPProtocolESP          IPProtocol = 50
	IPProtocolAH           IPProtocol = 51
	IPProtocolICMPv6       IPProtocol = 58
	IPProtocolNoNextHeader IPProtocol = 59
	IPProtocolIPIP         IPProtocol = 94
	IPProtocolEtherIP      IPProtocol = 97
	IPProtocolSCTP         IPProtocol = 132
	IPProtocolUDPLite      IPProtocol = 136
	IPProtocolMPLSInIP     IPProtocol = 137
)

// LinkType is an enumeration of link types, and acts as a decoder for any
// link type it supports.
type LinkType uint8

const (
	// According to pcap-linktype(7).
	LinkTypeNull           LinkType = 0
	LinkTypeEthernet       LinkType = 1
	LinkTypeTokenRing      LinkType = 6
	LinkTypeArcNet         LinkType = 7
	LinkTypeSLIP           LinkType = 8
	LinkTypePPP            LinkType = 9
	LinkTypeFDDI           LinkType = 10
	LinkTypeATM_RFC1483    LinkType = 100
	LinkTypeRaw            LinkType = 101
	LinkTypePPP_HDLC       LinkType = 50
	LinkTypePPPEthernet    LinkType = 51
	LinkTypeC_HDLC         LinkType = 104
	LinkTypeIEEE802_11     LinkType = 105
	LinkTypeFRelay         LinkType = 107
	LinkTypeLoop           LinkType = 108
	LinkTypeLinuxSLL       LinkType = 113
	LinkTypeLTalk          LinkType = 104
	LinkTypePFLog          LinkType = 117
	LinkTypePrismHeader    LinkType = 119
	LinkTypeIPOverFC       LinkType = 122
	LinkTypeSunATM         LinkType = 123
	LinkTypeIEEE80211Radio LinkType = 127
	LinkTypeARCNetLinux    LinkType = 129
	LinkTypeLinuxIRDA      LinkType = 144
	LinkTypeLinuxLAPD      LinkType = 177
)

// end of copy code.google.com/p/gopacket/layers/enums.go

//
const UDP_HDR_SIZE = 42
const DEFAULT_MTU = 1500
const defaultSocketTimeOut = 30

var HwAddrBroadcast net.HardwareAddr
var HwAddrZero net.HardwareAddr
var RawPktAddrZero *RawPktAddr
var RawPktAddrBroadcast *RawPktAddr

//
func init() {
	//
	HwAddrBroadcast, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
	HwAddrZero, _ = net.ParseMAC("00:00:00:00:00:00")
	//
	RawPktAddrZero = &RawPktAddr{
		HardwareAddr: HwAddrZero,
		IPAddr:       net.IPv4zero,
		IPPort:       0,
	}
	RawPktAddrBroadcast = &RawPktAddr{
		HardwareAddr: HwAddrBroadcast,
		IPAddr:       net.IPv4bcast,
		IPPort:       19818,
	}
}

// RawPktAddr
//
//
type RawPktAddr struct {
	HardwareAddr net.HardwareAddr // mac address of packet, eg., ff:ff:ff:ff:ff:ff / 00:e0:4c:68:04:1d
	IPAddr       net.IP           // ip of packet, eg., 255.255.255.255 / 8.8.8.8
	IPPort       int              // port of packet, eg., 19818 / 53
}

//
//
func NewPktAddr() *RawPktAddr {
	return &RawPktAddr{
		HardwareAddr: HwAddrZero,
		IPAddr:       net.IPv4zero,
		IPPort:       0,
	}
}

// ResolveRawPktAddr parse strings
//
func ResolveRawPktAddr(mac, addr, port string) (pktAddr *RawPktAddr, err error) {
	var hwaddr net.HardwareAddr
	var ipaddr net.IP
	var ipport int
	hwaddr, err = net.ParseMAC(mac)
	if err != nil {
		return nil, err
	}
	ipaddr = net.ParseIP(addr)
	ipport, err = strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	pktAddr = &RawPktAddr{
		HardwareAddr: hwaddr,
		IPAddr:       ipaddr,
		IPPort:       ipport,
	}
	return
}

// Reset
//
func (pktAddr *RawPktAddr) Reset() {
	copy(pktAddr.HardwareAddr, HwAddrZero)
	copy(pktAddr.IPAddr, net.IPv4zero)
	pktAddr.IPPort = 0
	return
}

// Copy
//
func (pktAddr *RawPktAddr) Copy(src *RawPktAddr) {
	if src == nil {
		return
	}
	copy(pktAddr.HardwareAddr, src.HardwareAddr)
	copy(pktAddr.IPAddr, src.IPAddr)
	pktAddr.IPPort = src.IPPort
	return
}

// Clone
//
func (pktAddr *RawPktAddr) Clone() *RawPktAddr {
	naddr := NewPktAddr()
	naddr.Copy(pktAddr)
	return naddr
}

// String
//
func (pktAddr *RawPktAddr) String() (str string) {
	//
	return pktAddr.HardwareAddr.String() + "#" + pktAddr.IPAddr.String() + "#" + strconv.Itoa(pktAddr.IPPort)
}

// Match compare two RawPktAddr, check on no-zero local/remote HwAddr/IP/Port
// return true for all match
// nil match to all
func (pktAddr *RawPktAddr) Match(addr *RawPktAddr) bool {
	if addr == nil {
		return true
	}
	if bytes.Equal(addr.HardwareAddr, HwAddrZero) == false && bytes.Equal(pktAddr.HardwareAddr, addr.HardwareAddr) == false {
		//
		fmt.Printf("RawPktAddr HardwareAddr %s mis-match, got %s\n", pktAddr.HardwareAddr.String(), addr.HardwareAddr.String())
		return false
	}
	if bytes.Equal(addr.IPAddr, net.IPv4zero) == false && bytes.Equal(pktAddr.IPAddr, addr.IPAddr) == false {
		//
		fmt.Printf("RawPktAddr IPAddr %s mis-match, got %s\n", pktAddr.IPAddr.String(), addr.IPAddr.String())
		return false
	}
	if addr.IPPort > 0 && pktAddr.IPPort != addr.IPPort {
		fmt.Printf("RawPktAddr IPPort %d mis-match, got %d\n", pktAddr.IPPort, addr.IPPort)
		return false
	}
	return true
}

// ethernet raw frame buffer
// rawPktFrame is 2:1 bound to RawPktConn, read+write
type rawPktFrame struct {
	remote       *RawPktAddr // remote addr filter
	local        *RawPktAddr // local addr filter
	timeout      int         // timeout in seconds
	frameBuf     []byte      // frame buf for io
	frameIp      []byte      // frame buf for io
	frameUdp     []byte      // frame buf for io
	framePayload []byte      // frame buf for io
}

// newrawPktFrame create new rawPktFrame
//
func newRawPktFrame() (pktFrame *rawPktFrame) {
	pktFrame = new(rawPktFrame)
	pktFrame.reset()
	return
}

// reset rawPktFrame
//
func (pktFrame *rawPktFrame) reset() {
	if pktFrame.remote != nil {
		pktFrame.remote.Reset()
	} else {
		pktFrame.remote = RawPktAddrZero.Clone()
	}
	if pktFrame.local != nil {
		pktFrame.local.Reset()
	} else {
		pktFrame.local = RawPktAddrZero.Clone()
	}
	pktFrame.timeout = defaultSocketTimeOut
	if pktFrame.frameBuf != nil {
		pktFrame.frameBuf = pktFrame.frameBuf[:cap(pktFrame.frameBuf)]
	} else {
		//MTU 1500 + UDP_HDR_SIZE
		pktFrame.frameBuf = make([]byte, DEFAULT_MTU+UDP_HDR_SIZE)
	}
	pktFrame.frameIp = nil
	pktFrame.frameUdp = nil
	return
}

// frameEncodeETH generate ethernet header for rawPktFrame
//
func (pktFrame *rawPktFrame) frameEncodeETH() {
	//
	// TODO: struct to  bytes.Buffer/binary.Write http://my.oschina.net/ybusad/blog/300155
	//
	// pktFrame.frameBuf initialed to 1542 bytes
	//
	fmt.Printf("befor frameEncodeETH(%03d/%03d): %x\n", len(pktFrame.frameBuf), cap(pktFrame.frameBuf), pktFrame.frameBuf)
	copy(pktFrame.frameBuf, pktFrame.remote.HardwareAddr)
	copy(pktFrame.frameBuf[6:], pktFrame.local.HardwareAddr)
	// type EthernetType uint16
	// EthernetTypeIPv4               EthernetType = 0x0800
	binary.BigEndian.PutUint16(pktFrame.frameBuf[12:], uint16(0x0800))
	fmt.Printf("after frameEncodeETH(%03d/%03d): %x\n", len(pktFrame.frameBuf), cap(pktFrame.frameBuf), pktFrame.frameBuf)
	return
}

// frameEncodeIP generate IP header for rawPktFrame
//
func (pktFrame *rawPktFrame) frameEncodeIP(payload []byte) {
	//
	// pktFrame.frameBuf initial to 512 bytes
	// header len: eth 14, ip 20, udp 8 = 42 bytes
	// UDP HDR size: 8 bytes
	fmt.Printf("befor frameEncodeIP(%03d/%03d): %x\n", len(pktFrame.frameBuf), cap(pktFrame.frameBuf), pktFrame.frameBuf)
	// TODO: const ipVersion, ipIHL etc
	ipVersion := 4
	ipIHL := 5
	ipTOS := 0
	ipLength := uint16(len(payload)) + 20 + 8
	ipId := uint16(time.Now().UnixNano())
	ipTTL := 8
	ipProtocol := uint8(17) // IPProtocol uint8, IPProtocolUDP IPProtocol = 17
	pktFrame.frameBuf[14:][0] = byte((ipVersion << 4) | ipIHL)
	//binary.BigEndian.PutUint16(pktFrame.frameBuf[14:], uint16((ipVersion<<4)|ipIHL))
	pktFrame.frameBuf[14:][1] = byte(ipTOS)
	//binary.BigEndian.PutUint16(pktFrame.frameBuf[15:], uint16(ipTOS))
	binary.BigEndian.PutUint16(pktFrame.frameBuf[16:], uint16(ipLength))
	binary.BigEndian.PutUint16(pktFrame.frameBuf[18:], uint16(ipId))
	//pktFrame.frameBuf[14:][8] = ipTTL
	binary.BigEndian.PutUint16(pktFrame.frameBuf[22:], uint16(ipTTL))
	pktFrame.frameBuf[14:][9] = byte(ipProtocol)
	//binary.BigEndian.PutUint16(pktFrame.frameBuf[23:], uint16(ipProtocol))
	// 4 bytes IP addr
	copy(pktFrame.frameBuf[26:30], pktFrame.local.IPAddr)
	copy(pktFrame.frameBuf[30:34], pktFrame.remote.IPAddr)
	// no check sum
	binary.BigEndian.PutUint16(pktFrame.frameBuf[24:], 0)
	fmt.Printf("after frameEncodeIP(%03d/%03d): %x\n", len(pktFrame.frameBuf), cap(pktFrame.frameBuf), pktFrame.frameBuf)
	return
}

// frameEncodeUDP generate UDP header for rawPktFrame
//
func (pktFrame *rawPktFrame) frameEncodeUDP(payload []byte) {
	//
	// pktFrame.frameBuf initial to 512 bytes
	// header len: eth 14, ip 20, udp 8 = 42 bytes
	// UDP HDR size: 8 bytes
	fmt.Printf("befor frameEncodeUDP(%03d/%03d): %x\n", len(pktFrame.frameBuf), cap(pktFrame.frameBuf), pktFrame.frameBuf)
	binary.BigEndian.PutUint16(pktFrame.frameBuf[34:], uint16(pktFrame.local.IPPort))
	binary.BigEndian.PutUint16(pktFrame.frameBuf[36:], uint16(pktFrame.remote.IPPort))
	binary.BigEndian.PutUint16(pktFrame.frameBuf[38:], uint16(len(payload))+8)
	//no checksum
	binary.BigEndian.PutUint16(pktFrame.frameBuf[40:], 0)
	fmt.Printf("after frameEncodeUDP(%03d/%03d): %x\n", len(pktFrame.frameBuf), cap(pktFrame.frameBuf), pktFrame.frameBuf)
	return
}

// frameEncodePayload copy payload to pktFrame.frameBuf
//
func (pktFrame *rawPktFrame) frameEncodePayload(payload []byte) {
	// Use package bytes ?
	// pktFrame.frameBuf initial to 512 bytes
	// header len: eth 14, ip 20, udp 8 = 42 bytes
	// UDP HDR size: 8 bytes
	sph := make([]byte, UDP_HDR_SIZE)
	fmt.Printf("befor frameEncodePayload(%03d/%03d): %x%x\n", len(payload)+UDP_HDR_SIZE, cap(payload), sph, payload)
	fmt.Printf("befor frameEncodePayload(%03d/%03d): %x\n", len(pktFrame.frameBuf), cap(pktFrame.frameBuf), pktFrame.frameBuf)
	// expand FrameBuf befor copy
	expLen := len(payload) - len(pktFrame.frameBuf) - UDP_HDR_SIZE
	if expLen > 0 {
		pktFrame.frameBuf = append(pktFrame.frameBuf, make([]byte, expLen)...)
	}
	// TODO: zero copy ?
	copy(pktFrame.frameBuf[UDP_HDR_SIZE:], payload)
	fmt.Printf("after frameEncodePayload(%03d/%03d): %x%x\n", len(payload)+UDP_HDR_SIZE, cap(payload), sph, payload)
	fmt.Printf("after frameEncodePayload(%03d/%03d): %x\n", len(pktFrame.frameBuf), cap(pktFrame.frameBuf), pktFrame.frameBuf)
	return
}

// frameEncodeAll generate full ethernet frame for rawPktFrame
//
func (pktFrame *rawPktFrame) frameEncodeAll(payload []byte) {
	// reset buff
	pktFrame.frameBuf = pktFrame.frameBuf[:0]
	//
	fmt.Printf("befor frameEncodeAll(%03d/%03d): %x\n", len(pktFrame.frameBuf), cap(pktFrame.frameBuf), pktFrame.frameBuf)
	// encode ethernet header
	pktFrame.frameEncodeETH()
	// encode IP header
	pktFrame.frameEncodeIP(payload)
	// encode UDP header
	pktFrame.frameEncodeUDP(payload)
	// append payload
	pktFrame.frameEncodePayload(payload)
	fmt.Printf("after frameEncodeAll(%03d/%03d): %x\n", len(pktFrame.frameBuf), cap(pktFrame.frameBuf), pktFrame.frameBuf)
	return
}

// writePkt write pktFrame.frameBuf to iface
// write to socketfd, timeout=pktFrame.timeout
//
func (pktFrame *rawPktFrame) writePkt(socketfd int) (int, error) {
	//
	var ioBytes int
	var timeout syscall.Timeval
	var err error
	// set read pktFrame.timeout
	if pktFrame.timeout > 0 && pktFrame.timeout < defaultSocketTimeOut {
		timeout.Sec = int64(pktFrame.timeout)
		timeout.Usec = 0
	} else {
		timeout.Sec = int64(defaultSocketTimeOut)
		timeout.Usec = 0
	}
	//
	fmt.Printf("pktFrame#%d write SetsockoptTimeval timeout %d\n", socketfd, timeout.Sec)
	//
	// http://stackoverflow.com/questions/11186035/raw-socket-send-not-working
	//
	// golang func SetsockoptTimeval(fd, level, opt int, tv *Timeval) (err error)
	// C setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout))
	// C setsockopt (sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout))
	if err = syscall.SetsockoptTimeval(socketfd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &timeout); err != nil {
		// TODO: return error with errcode
		err = fmt.Errorf("pktFrame#%d write SetsockoptTimeval: %s", socketfd, err.Error())
		fmt.Printf("%s\n", err.Error())
		return 0, err
	}
	//
	// write
	//
	// https://gist.github.com/austinmarton/1922600
	//
	// go func syscall.Write(fd int, p []byte) (n int, err error)
	//
	ioBytes, err = syscall.Write(socketfd, pktFrame.frameBuf)
	if err != nil {
		// TODO: return error with errcode
		err = fmt.Errorf("pktFrame#%d reawrited: %s", socketfd, err.Error())
		fmt.Printf("%s\n", err.Error())
		ioBytes = 0
		pktFrame.frameBuf = pktFrame.frameBuf[:ioBytes]
	} else if ioBytes < len(pktFrame.frameBuf) {
		// check truncat
		// TODO: return error with errcode
		err = fmt.Errorf("pktFrame#%d write truncated: %d - %d = %d", socketfd, len(pktFrame.frameBuf), ioBytes, len(pktFrame.frameBuf)-ioBytes)
		fmt.Printf("%s\n", err.Error())
		pktFrame.frameBuf = pktFrame.frameBuf[:ioBytes]
	}
	return ioBytes, err
}

// writePktFrame encode and write rawPktFrame full ethernet frame
// return bytes out and error
//
func (pktFrame *rawPktFrame) writePktFrame(socketfd int, laddr *RawPktAddr, raddr *RawPktAddr, payload []byte) (int, error) {
	//
	pktFrame.local.Copy(laddr)
	pktFrame.remote.Copy(raddr)
	pktFrame.frameEncodeAll(payload)
	return pktFrame.writePkt(socketfd)
}

// readPkt read one packet to pktFrame.frameBuf
// read from socketfd, timeout=pktFrame.timeout
// save to pktFrame.frameBuf
//
func (pktFrame *rawPktFrame) readPkt(socketfd int) (int, error) {
	//
	var ioBytes int
	var timeout syscall.Timeval
	var err error
	// set read pktFrame.timeout
	if pktFrame.timeout > 0 && pktFrame.timeout < defaultSocketTimeOut {
		timeout.Sec = int64(pktFrame.timeout)
		timeout.Usec = 0
	} else {
		timeout.Sec = int64(defaultSocketTimeOut)
		timeout.Usec = 0
	}
	//
	fmt.Printf("pktFrame#%d read SetsockoptTimeval timeout %d\n", socketfd, timeout.Sec)
	//
	// http://stackoverflow.com/questions/11186035/raw-socket-send-not-working
	//
	// golang func SetsockoptTimeval(fd, level, opt int, tv *Timeval) (err error)
	// C setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout))
	// C setsockopt (sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout))
	if err = syscall.SetsockoptTimeval(socketfd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout); err != nil {
		// TODO: return error with errcode
		err = fmt.Errorf("pktFrame#%d read SetsockoptTimeval: %s", socketfd, err.Error())
		fmt.Printf("%s\n", err.Error())
		return 0, err
	}
	//
	// read
	//
	// https://gist.github.com/austinmarton/1922600
	//
	// go func syscall.Read(fd int, p []byte) (n int, err error)
	//
	pktFrame.frameBuf = pktFrame.frameBuf[:cap(pktFrame.frameBuf)]
	ioBytes, err = syscall.Read(socketfd, pktFrame.frameBuf)
	if err != nil {
		// TODO: return error with errcode
		err = fmt.Errorf("pktFrame#%d read: %s", socketfd, err.Error())
		fmt.Printf("%s\n", err.Error())
		ioBytes = 0
	}
	pktFrame.frameBuf = pktFrame.frameBuf[:ioBytes]
	return ioBytes, err
}

// frameDecodeETH parse pktFrame.frameBuf
// fill remote/local hardware address
// copy from gopacket: ethernet: DecodeFromBytes
// return error code and error
// code: 0 for ok, 1 for no fault error, > 1 for fault error
//
func (pktFrame *rawPktFrame) frameDecodeETH() (int, error) {
	if len(pktFrame.frameBuf) < 14 {
		return 254, errors.New("Ethernet packet too small")
	}
	copy(pktFrame.remote.HardwareAddr, net.HardwareAddr(pktFrame.frameBuf[0:6]))
	copy(pktFrame.local.HardwareAddr, net.HardwareAddr(pktFrame.frameBuf[6:12]))
	// payload of ethernet frame: pktFrame.frameBuf[14:]
	pktFrame.frameIp = pktFrame.frameBuf[14:]
	return 0, nil
}

// frameDecodeIP parse pktFrame.frameIp
// fill remote/local ip address
// copy from gopacket: ip4: DecodeFromBytes
// WARNING: ip flags/options no supported
// return error code and error
// code: 0 for ok, 1 for no fault error, > 1 for fault error
//
func (pktFrame *rawPktFrame) frameDecodeIP() (int, error) {
	if pktFrame.frameIp == nil {
		return 254, errors.New("IP packet no initialed, decode ethernet first")
	}
	if len(pktFrame.frameIp) < 20 {
		return 255, errors.New("IP packet too small")
	}
	ip_Version := uint8(pktFrame.frameIp[0]) >> 4
	fmt.Printf("ip_Version: %v\n", ip_Version)
	ip_IHL := uint8(pktFrame.frameIp[0]) & 0x0F
	fmt.Printf("ip_IHL: %v\n", ip_IHL)
	ip_TOS := pktFrame.frameIp[1]
	fmt.Printf("ip_TOS: %v\n", ip_TOS)
	ip_Length := binary.BigEndian.Uint16(pktFrame.frameIp[2:4])
	fmt.Printf("ip_Length: %v\n", ip_Length)
	ip_Id := binary.BigEndian.Uint16(pktFrame.frameIp[4:6])
	fmt.Printf("ip_Id: %v\n", ip_Id)
	ip_TTL := pktFrame.frameIp[8]
	fmt.Printf("ip_TTL: %v\n", ip_TTL)
	ip_Protocol := IPProtocol(pktFrame.frameIp[9])
	fmt.Printf("ip_Protocol: %v\n", ip_Protocol)
	ip_Checksum := binary.BigEndian.Uint16(pktFrame.frameIp[10:12])
	fmt.Printf("ip_Checksum: %v\n", ip_Checksum)
	pktFrame.local.IPAddr = pktFrame.frameIp[12:16]
	fmt.Printf("pktFrame.local.IPAddr: %v\n", pktFrame.local.IPAddr)
	pktFrame.remote.IPAddr = pktFrame.frameIp[16:20]
	fmt.Printf("pktFrame.remote.IPAddr: %v\n", pktFrame.remote.IPAddr)
	if ip_Length < 20 {
		return 253, fmt.Errorf("Invalid (too small) IP length (%d < 20)", ip_Length)
	} else if ip_IHL < 5 {
		return 252, fmt.Errorf("Invalid (too small) IP header length (%d < 5)", ip_IHL)
	} else if int(ip_IHL*4) > int(ip_Length) {
		return 251, fmt.Errorf("Invalid IP header length > IP length (%d > %d)", ip_IHL, ip_Length)
	}
	cmp := len(pktFrame.frameIp) - int(ip_Length)
	if cmp > 0 {
		pktFrame.frameIp = pktFrame.frameIp[:ip_Length]
	} else if cmp < 0 {
		if int(ip_IHL)*4 > len(pktFrame.frameIp) {
			return 250, fmt.Errorf("Not all IP header bytes available")
		}
	}
	pktFrame.frameUdp = pktFrame.frameIp[ip_IHL*4:]
	fmt.Printf("pktFrame.frameUdp: %v\n", pktFrame.frameUdp)
	// IP options no supported
	return 0, nil
}

// frameDecodeUDP parse pktFrame.frameUdp
// fill remote/local ip port
// copy from gopacket: udp: DecodeFromBytes
// return error code and error
// code: 0 for ok, 1 for no fault error, > 1 for fault error
//
func (pktFrame *rawPktFrame) frameDecodeUDP() (int, error) {
	if pktFrame.frameUdp == nil {
		return 254, errors.New("UDP packet no initialed, decode ethernet first")
	}
	if len(pktFrame.frameUdp) < 8 {
		return 255, errors.New("UDP packet too small")
	}
	pktFrame.remote.IPPort = int(binary.BigEndian.Uint16(pktFrame.frameUdp[0:2]))
	fmt.Printf("pktFrame.remote.IPPort: %v\n", pktFrame.remote.IPPort)
	pktFrame.local.IPPort = int(binary.BigEndian.Uint16(pktFrame.frameUdp[2:4]))
	fmt.Printf("pktFrame.local.IPPort: %v\n", pktFrame.local.IPPort)
	udp_Length := binary.BigEndian.Uint16(pktFrame.frameUdp[4:6])
	fmt.Printf("udp_Length: %v\n", udp_Length)
	udp_Checksum := binary.BigEndian.Uint16(pktFrame.frameUdp[6:8])
	fmt.Printf("udp_Checksum: %v\n", udp_Checksum)
	switch {
	case udp_Length >= 8:
		hlen := int(udp_Length)
		if hlen > len(pktFrame.frameUdp) {
			hlen = len(pktFrame.frameUdp)
		}
		pktFrame.framePayload = pktFrame.frameUdp[8:hlen]
	default:
		return 255, fmt.Errorf("UDP packet too small: %d bytes", udp_Length)
	}
	return 0, nil
}

// frameDecodePayload copy pktFrame.framePayload to payload
// return error code and error
// code: 0 for ok, 1 for no fault error, > 1 for fault error
//
func (pktFrame *rawPktFrame) frameDecodePayload(payload []byte) (int, error) {
	if pktFrame.framePayload == nil {
		return 254, errors.New("Payload no initialed, decode ethernet first")
	}
	copylen := len(pktFrame.framePayload)
	if copylen > cap(payload) {
		copylen = cap(payload)
	}
	payload = payload[:copylen]
	copy(payload, pktFrame.framePayload[:copylen])
	return 0, nil
}

// readPktFrame decode full ethernet frame to rawPktFrame
// return payload length and error
//
func (pktFrame *rawPktFrame) readPktFrame(socketfd int, laddr *RawPktAddr, raddr *RawPktAddr, payload []byte) (int, error) {
	//
	fmt.Printf("befor frameDecodeAll(%03d/%03d): %x\n", len(pktFrame.frameBuf), cap(pktFrame.frameBuf), pktFrame.frameBuf)
	var err error
	var code int
	timeout := time.Duration(defaultSocketTimeOut)
	if pktFrame.timeout > 0 && pktFrame.timeout < defaultSocketTimeOut {
		timeout = time.Duration(pktFrame.timeout)
	}
	ioTk := time.NewTicker(1e9 * timeout)
	defer ioTk.Stop()
	// reset buf
	payload = payload[:0]
	for {
		select {
		case <-ioTk.C:
			return 0, fmt.Errorf("readPktFrame timeout after %d seconds", timeout)
		default:
		}
		// reset buff
		pktFrame.frameBuf = pktFrame.frameBuf[:cap(pktFrame.frameBuf)]
		fmt.Printf("try to readPkt from iface, timeout %d\n", pktFrame.timeout)
		// read to pktFrame.frameBuf
		_, err = pktFrame.readPkt(socketfd)
		if err != nil {
			return 0, err
		}
		//
		// decode ethernet header
		code, err = pktFrame.frameDecodeETH()
		if err != nil {
			if code > 1 {
				return 0, err
			}
			continue
		}
		// decode IP header
		code, err = pktFrame.frameDecodeIP()
		if err != nil {
			if code > 1 {
				return 0, err
			}
			continue
		}
		// decode UDP header
		code, err = pktFrame.frameDecodeUDP()
		if err != nil {
			if code > 1 {
				return 0, err
			}
			continue
		}
		//
		if laddr != nil {
			if pktFrame.local.Match(laddr) == false {
				fmt.Printf("readFrame localPktAddr mismatch\n")
				continue
			}
		}
		//
		if raddr != nil {
			if pktFrame.remote.Match(raddr) == false {
				fmt.Printf("readFrame remotePktAddr mismatch\n")
				continue
			}
		}
		//
		// pktFrame match
		//
		// frameDecodePayload
		//
		pktFrame.frameDecodePayload(payload)
		//
		break
	}
	fmt.Printf("after frameDecodeAll(%03d/%03d): %x\n", len(pktFrame.frameBuf), cap(pktFrame.frameBuf), pktFrame.frameBuf)
	fmt.Printf("after frameDecodeAll(%03d/%03d): %x\n", len(payload), cap(payload), payload)
	return len(payload), nil
}

// RawPktConn
//
type RawPktConn struct {
	iface      *net.Interface // nic
	socketfd   int            // socketfd
	promisc    bool           // promisc flag
	writeFrame *rawPktFrame   // rawPktFrame for write
	readFrame  *rawPktFrame   // rawPktFrame for read
	writeLock  sync.Mutex     // frame write lock
	readLock   sync.Mutex     // frame read lock
}

//
func newRawPktConn() *RawPktConn {
	rawPktConn := new(RawPktConn)
	rawPktConn.reset()
	return rawPktConn
}

//
func (rawPktConn *RawPktConn) reset() {
	rawPktConn.writeLock.Lock()
	rawPktConn.readLock.Lock()
	defer rawPktConn.writeLock.Unlock()
	defer rawPktConn.readLock.Unlock()
	if rawPktConn.socketfd > 0 {
		syscall.Close(rawPktConn.socketfd)
		rawPktConn.socketfd = -1
	}
	if rawPktConn.promisc && rawPktConn.iface != nil {
		rawPktConn.SetPromisc(false)
		rawPktConn.promisc = false
	}
	rawPktConn.iface = nil
	if rawPktConn.writeFrame != nil {
		rawPktConn.writeFrame.reset()
	} else {
		rawPktConn.writeFrame = newRawPktFrame()
	}
	if rawPktConn.readFrame != nil {
		rawPktConn.readFrame.reset()
	} else {
		rawPktConn.readFrame = newRawPktFrame()
	}
	//
	return
}

// SetReadTimeOut
// return old timeout
//
func (rawPktConn *RawPktConn) SetReadTimeOut(val int) int {
	rawPktConn.readLock.Lock()
	defer rawPktConn.readLock.Unlock()
	oldval := rawPktConn.readFrame.timeout
	rawPktConn.readFrame.timeout = val
	return oldval
}

// SetWriteTimeOut
// return old timeout
//
func (rawPktConn *RawPktConn) SetWriteTimeOut(val int) int {
	rawPktConn.writeLock.Lock()
	defer rawPktConn.writeLock.Unlock()
	oldval := rawPktConn.writeFrame.timeout
	rawPktConn.writeFrame.timeout = val
	return oldval
}

// SetTimeOut
// return old timeout
//
func (rawPktConn *RawPktConn) SetTimeOut(val int) (int, int) {
	//
	return rawPktConn.SetReadTimeOut(val), rawPktConn.SetWriteTimeOut(val)
}

// SetPromisc set rawPktConn iface to Promisc flag
//
func (rawPktConn *RawPktConn) SetPromisc(flag bool) (oldflag bool, err error) {
	// lock free
	if rawPktConn.iface == nil {
		return false, nil
	}
	oldflag = rawPktConn.promisc
	rawPktConn.promisc = flag
	if flag != oldflag {
		fmt.Printf("rawPktConn#%d, set %s Promisc to %v\n", rawPktConn.iface.Index, rawPktConn.iface.Name, rawPktConn.promisc)
		err = syscall.SetLsfPromisc(rawPktConn.iface.Name, rawPktConn.promisc)
		if err != nil {
			return oldflag, err
		}
	}
	return oldflag, nil
}

// Open bind RawPktConn to rawPktConn.iface
//
// return *RawPktConn and error
//
func Open(nic string) (*RawPktConn, error) {
	var iface *net.Interface
	var err error
	iface, err = net.InterfaceByName(nic)
	if err != nil {
		err = fmt.Errorf("open nic %s: %s", nic, err.Error())
		fmt.Printf("%s\n", err.Error())
		return nil, err
	}
	rawPktConn := newRawPktConn()
	rawPktConn.iface = iface
	fmt.Printf("Open#%d\n", rawPktConn.iface.Index)
	//
	// socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP|ETH_P_ARP|ETH_P_ALL)) for all ethernet frame recive
	// /usr/include/bits/socket.h
	// line 62 /* Protocol families. */
	// line 83 #define PF_PACKET 17 /* Packet family. */
	// line 94 /* Address families. */
	// line115 #define AF_PACKET PF_PACKET
	// AF_PACKET == PF_PACKET
	//
	rawPktConn.socketfd, err = syscall.LsfSocket(rawPktConn.iface.Index, syscall.ETH_P_ALL)
	if err != nil {
		rawPktConn.reset()
		rawPktConn = nil
		return nil, err
	}
	return rawPktConn, nil
}

// Close
//
func (rawPktConn *RawPktConn) Close() {
	rawPktConn.reset()
	rawPktConn = nil
	return
}

// WriteToAddr encode and write rawPktFrame full ethernet frame
// laddr/raddr should no be nil
// return bytes out and error
//
func (rawPktConn *RawPktConn) WriteToAddr(laddr *RawPktAddr, raddr *RawPktAddr, payload []byte) (int, error) {
	rawPktConn.writeLock.Lock()
	defer rawPktConn.writeLock.Unlock()
	if payload == nil {
		return 0, nil
	}
	if len(payload) == 0 {
		return 0, nil
	}
	if laddr == nil {
		return 0, errors.New("invalid local RawPktAddr for write: <nil>")
	}
	if raddr == nil {
		return 0, errors.New("invalid remote RawPktAddr for write: <nil>")
	}
	//
	return rawPktConn.writeFrame.writePktFrame(rawPktConn.socketfd, laddr, raddr, payload)
}

// ReadFromAddr encode and write rawPktFrame full ethernet frame
// lfaddr/rfaddr used for package filter, nil for match all
// return local/remote RawPktAddr and error
//
func (rawPktConn *RawPktConn) ReadFromAddr(lfaddr *RawPktAddr, rfaddr *RawPktAddr, payload []byte) (laddr *RawPktAddr, raddr *RawPktAddr, ioBytes int, err error) {
	rawPktConn.readLock.Lock()
	defer rawPktConn.readLock.Unlock()
	if payload == nil {
		return nil, nil, 0, errors.New("<nil> buffer for read")
	}
	if len(payload) == 0 {
		return nil, nil, 0, errors.New("empty buffer for read")
	}
	ioBytes, err = rawPktConn.readFrame.readPktFrame(rawPktConn.socketfd, lfaddr, rfaddr, payload)
	if err != nil {
		return nil, nil, 0, err
	}
	laddr = rawPktConn.readFrame.local.Clone()
	raddr = rawPktConn.readFrame.remote.Clone()
	return laddr, raddr, ioBytes, err
}

//
// TODO: async read/write
//

// PktConn
//
type PktConn struct {
	writeTplFrame *rawPktFrame // write addr filter
	readTplFrame  *rawPktFrame // read addr filter
	rawPktConn    *RawPktConn  // underdelay RawPktConn
}

//
//
func newPktConn() *PktConn {
	pktConn := new(PktConn)
	pktConn.reset()
	return pktConn
}

//
//
func (pktConn *PktConn) reset() {
	if pktConn.rawPktConn != nil {
		pktConn.rawPktConn.reset()
	} else {
		pktConn.rawPktConn = newRawPktConn()
	}
	if pktConn.writeTplFrame != nil {
		pktConn.writeTplFrame.reset()
	} else {
		pktConn.writeTplFrame = newRawPktFrame()
	}
	if pktConn.readTplFrame != nil {
		pktConn.readTplFrame.reset()
	} else {
		pktConn.readTplFrame = newRawPktFrame()
	}
	return
}

// Dial bind RawPktConn to nic for write
//
func Dial(nic string, addr *RawPktAddr) (*PktConn, error) {
	rc, err := Open(nic)
	if err != nil {
		return nil, err
	}
	pktConn := newPktConn()
	pktConn.rawPktConn = rc
	pktConn.SetRemoteAddr(addr)
	return pktConn, nil
}

// Listen bind RawPktConn to nic for read
//
func Listen(nic string, addr *RawPktAddr) (*PktConn, error) {
	rc, err := Open(nic)
	if err != nil {
		return nil, err
	}
	pktConn := newPktConn()
	pktConn.rawPktConn = rc
	pktConn.SetLocalAddr(addr)
	return pktConn, nil
}

// Close
//
func (pktConn *PktConn) Close() {
	pktConn.rawPktConn.Close()
	pktConn = nil
	return
}

// SetLocalAddr set read/write local RawPktAddr
//
func (pktConn *PktConn) SetLocalAddr(addr *RawPktAddr) error {
	// writeTplFrame
	if addr == nil {
		return fmt.Errorf("invalid local Tpl RawPktAddr %v", addr)
	}
	pktConn.rawPktConn.readLock.Lock()
	defer pktConn.rawPktConn.readLock.Unlock()
	pktConn.rawPktConn.writeLock.Lock()
	defer pktConn.rawPktConn.writeLock.Unlock()
	pktConn.readTplFrame.local.Copy(addr)
	pktConn.writeTplFrame.local.Copy(addr)
	return nil
}

// SetRemoteAddr
//
func (pktConn *PktConn) SetRemoteAddr(addr *RawPktAddr) error {
	// remoteTplAddr
	if addr == nil {
		return fmt.Errorf("invalid remote Tpl RawPktAddr %v", addr)
	}
	pktConn.rawPktConn.readLock.Lock()
	defer pktConn.rawPktConn.readLock.Unlock()
	pktConn.rawPktConn.writeLock.Lock()
	defer pktConn.rawPktConn.writeLock.Unlock()
	pktConn.readTplFrame.remote.Copy(addr)
	pktConn.writeTplFrame.remote.Copy(addr)
	return nil
}

// LocalAddr
// return RawPktAddr Tpl for reading
//
func (pktConn *PktConn) LocalAddr() *RawPktAddr {
	//
	return pktConn.readTplFrame.local.Clone()
}

// RemoteAddr
// return RawPktAddr Tpl for writing
//
func (pktConn *PktConn) RemoteAddr() *RawPktAddr {
	//
	return pktConn.writeTplFrame.remote.Clone()
}

// SetReadTimeOut
// return old timeout
//
func (pktConn *PktConn) SetReadTimeOut(val int) int {
	return pktConn.rawPktConn.SetReadTimeOut(val)
}

// SetWriteTimeOut
// return old timeout
//
func (pktConn *PktConn) SetWriteTimeOut(val int) int {
	return pktConn.rawPktConn.SetWriteTimeOut(val)
}

// SetTimeOut
// return old timeout of read/write
//
func (pktConn *PktConn) SetTimeOut(val int) (int, int) {
	//
	return pktConn.rawPktConn.SetTimeOut(val)
}

// SetPromisc set PktConn iface to Promisc flag
//
func (pktConn *PktConn) SetPromisc(flag bool) (oldflag bool, err error) {
	return pktConn.rawPktConn.SetPromisc(flag)
}

// Write output data to Iface
// using writeTplFrame and remoteTplAddr
func (pktConn *PktConn) Write(data []byte) (int, error) {
	// func (rawPktConn *RawPktConn) WriteToAddr(laddr *RawPktAddr, raddr *RawPktAddr, payload []byte) (int, error)
	return pktConn.rawPktConn.WriteToAddr(pktConn.writeTplFrame.local, pktConn.writeTplFrame.remote, data)
}

// WriteTo output ethernet frame of RawPktConn to pktConn.Iface
// using writeTplFrame and remoteTplAddr
func (pktConn *PktConn) WriteTo(data []byte, raddr *RawPktAddr) (int, error) {
	// func (rawPktConn *RawPktConn) WriteToAddr(laddr *RawPktAddr, raddr *RawPktAddr, payload []byte) (int, error)
	return pktConn.rawPktConn.WriteToAddr(pktConn.writeTplFrame.local, raddr, data)
}

// Read get ethernet frame from pktConn.Iface
// filte by writeTplFrame and remoteTplAddr
func (pktConn *PktConn) Read(data []byte) (int, error) {
	// func (rawPktConn *RawPktConn) ReadFromAddr(lfaddr *RawPktAddr, rfaddr *RawPktAddr, payload []byte) (laddr *RawPktAddr, raddr *RawPktAddr, err error)
	_, _, ioBytes, err := pktConn.rawPktConn.ReadFromAddr(pktConn.readTplFrame.local, pktConn.readTplFrame.remote, data)
	return ioBytes, err
}

// ReadFrom output ethernet frame of RawPktConn to pktConn.Iface
// filter by addr
func (pktConn *PktConn) ReadFrom(data []byte, raddr *RawPktAddr) (int, error) {
	// func (rawPktConn *RawPktConn) ReadFromAddr(lfaddr *RawPktAddr, rfaddr *RawPktAddr, payload []byte) (laddr *RawPktAddr, raddr *RawPktAddr, err error)
	_, _, ioBytes, err := pktConn.rawPktConn.ReadFromAddr(pktConn.readTplFrame.local, raddr, data)
	return ioBytes, err
}

// ReadFromMsg output ethernet frame of RawPktConn to pktConn.Iface
// filter by addr
func (pktConn *PktConn) ReadFromMsg(data []byte) (laddr *RawPktAddr, raddr *RawPktAddr, ioBytes int, err error) {
	// func (rawPktConn *RawPktConn) ReadFromAddr(lfaddr *RawPktAddr, rfaddr *RawPktAddr, payload []byte) (laddr *RawPktAddr, raddr *RawPktAddr, err error)
	return pktConn.rawPktConn.ReadFromAddr(nil, nil, data)
}

//
