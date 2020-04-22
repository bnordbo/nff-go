package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/bnordbo/nff-go/flow"
	"github.com/bnordbo/nff-go/packet"
	"github.com/bnordbo/nff-go/types"
)

var (
	teid  = flag.Int("teid", 1, "GTP-U TEID")
	srcIP = flag.String("src-ip", "", "Source IP address")
	dstIP = flag.String("dst-ip", "", "Destination IP address")
	data  = flag.String("data", "", "GTP-U payload")
)

func main() {
	flag.Parse()

	srcAddr, err := stringToIPv4(*srcIP)
	if err != nil {
		log.Fatal(err)
	}

	dstAddr, err := stringToIPv4(*dstIP)
	if err != nil {
		log.Fatal(err)
	}

	genFn := func(p *packet.Packet, c flow.UserContext) {
		genICMP(p, c, data)
	}

	var pkID uint16 = 0
	encapFn := func(p *packet.Packet, c flow.UserContext) bool {
		pkID++
		return encap(p, c, srcAddr, dstAddr, pkID)
	}

	flow.SystemInit(&flow.Config{CPUList: "0-9"})

	mainFlow := flow.SetGenerator(genFn, nil)
	flow.SetHandlerDrop(mainFlow, encapFn, nil)
	flow.SetStopper(mainFlow)

	flow.SystemStart()
}

func encap(
	p *packet.Packet,
	c flow.UserContext,
	srcAddr, dstAddr types.IPv4Address,
	pkID uint16,
) bool {
	if !p.EncapsulateIPv4GTP(uint32(*teid)) {
		log.Println("Error encapsulating GTP-U packet")
		return false
	}

	p.ParseL3()
	ipv4 := p.GetIPv4NoCheck()
	length := p.GetPacketLen()

	ipv4.VersionIhl = 0x45
	ipv4.TypeOfService = 0
	ipv4.PacketID = pkID
	ipv4.FragmentOffset = 0
	ipv4.TimeToLive = 64

	ipv4.TotalLength = packet.SwapBytesUint16(uint16(length - types.EtherLen))
	ipv4.NextProtoID = types.UDPNumber
	ipv4.SrcAddr = srcAddr
	ipv4.DstAddr = dstAddr
	ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))

	udp := p.GetUDPNoCheck()
	udp.SrcPort = packet.SwapUDPPortGTPU
	udp.DstPort = packet.SwapUDPPortGTPU
	udp.DgramLen = uint16(length - types.EtherLen - types.IPv4MinLen)
	udp.DgramCksum = 0

	return true
}

func genICMP(p *packet.Packet, c flow.UserContext, data *string) {
	payload, _ := hex.DecodeString(*data)
	packet.GeneratePacketFromByte(p, payload)
}

func stringToIPv4(addr string) (types.IPv4Address, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return types.IPv4Address(0), fmt.Errorf("Invalid source IP address %s", addr)
	}
	i := ip.To4()

	return types.BytesToIPv4(i[0], i[1], i[2], i[2]), nil
}
