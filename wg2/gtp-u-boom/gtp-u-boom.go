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
	teid   = flag.Int("teid", 1, "GTP-U TEID")
	srcIP  = flag.String("src-ip", "", "Source IP address")
	dstIP  = flag.String("dst-ip", "", "Destination IP address")
	data   = flag.String("data", "", "GTP-U payload")
	output = flag.Int("port", 0, "DPDK output port")
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
	flow.SystemInit(nil)

	outputPort := uint16(*output)

	var pkID uint16 = 0
	encapFn := func(p *packet.Packet, c flow.UserContext) {
		pkID++
		encap(p, c, srcAddr, dstAddr, data, pkID)
	}

	firstFlow, genChannel, _ := flow.SetFastGenerator(encapFn, 64, nil)
	flow.CheckFatal(flow.SetSender(firstFlow, outputPort))
	go updateSpeed(genChannel)
	flow.SystemStart()
}

func encap(
	p *packet.Packet,
	c flow.UserContext,
	srcAddr, dstAddr types.IPv4Address,
	data *string,
	pkID uint16,
) {
	genICMP(p, c, data)
	if !p.EncapsulateIPv4GTP(uint32(*teid)) {
		log.Println("Error encapsulating GTP-U packet")
		return
	}

	p.ParseL3()
	p.Ether.SAddr = [6]uint8{0x06, 0xc5, 0x79, 0x20, 0xd0, 0x60}
	p.Ether.DAddr = [6]uint8{0x06, 0x9a, 0x4b, 0x5a, 0x34, 0xa0}
	p.Ether.EtherType = types.SwapIPV4Number
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

	p.ParseL4ForIPv4()
	udp := p.GetUDPNoCheck()

	udp.SrcPort = packet.SwapBytesUint16(2152)
	udp.DstPort = packet.SwapBytesUint16(2152)
	udp.DgramLen = packet.SwapBytesUint16(uint16(length - types.EtherLen - types.IPv4MinLen))
	udp.DgramCksum = 0
}

func genICMP(p *packet.Packet, c flow.UserContext, data *string) {
	// adding fake Ethernet header since encapsulation will truncate it without checking if it exist
	ether := "0000000000000000000000000000"
	payload, _ := hex.DecodeString(ether + *data)
	packet.GeneratePacketFromByte(p, payload)
}

func stringToIPv4(addr string) (types.IPv4Address, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return types.IPv4Address(0), fmt.Errorf("Invalid source IP address %s", addr)
	}
	i := ip.To4()

	return types.BytesToIPv4(i[0], i[1], i[2], i[3]), nil

}

func updateSpeed(genChannel chan uint64) {
	var load int
	for {
		// Can be file or any other source
		if _, err := fmt.Scanf("%d", &load); err == nil {
			genChannel <- uint64(load)
		}
	}
}

func arpSeparator(p *packet.Packet, c flow.UserContext) bool {
	p.ParseL3()
	if p.GetARP() != nil {
		return false
	}
	return true
}

var np = 0

func dump(currentPacket *packet.Packet, context flow.UserContext) {
	if np < 9 /*dump first three packets */ {
		fmt.Printf("%v", currentPacket.Ether)
		currentPacket.ParseL3()
		ipv4 := currentPacket.GetIPv4()
		if ipv4 != nil {
			fmt.Printf("%v", ipv4)
			tcp, udp, _ := currentPacket.ParseAllKnownL4ForIPv4()
			if tcp != nil {
				fmt.Printf("%v", tcp)
			} else if udp != nil {
				fmt.Printf("%v", udp)
				gtp := currentPacket.GTPIPv4FastParsing()
				fmt.Printf("%v", gtp)
			} else {
				println("ERROR L 1")
			}
		} else {
			println("ERROR L 0")
		}
		fmt.Println("----------------------------------------------------------")
		np++
	}
}
