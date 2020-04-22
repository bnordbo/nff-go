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

	config := flow.Config{
		// Is required for KNI
		NeedKNI: false,
		CPUList: "0-3",
		SendCPUCoresPerPort: 2,
		TXQueuesNumberPerPort: 8,
	}

	flow.CheckFatal(flow.SystemInit(&config))
	//kni, err := flow.CreateKniDevice(uint16(*kniport), "kni_eth1")
	//flow.CheckFatal(err)
	//inputFlow, err := flow.SetReceiver(uint16(0))
	//flow.CheckFatal(err)
	//toKNIFlow, err := flow.SetSeparator(inputFlow, arpSeparator, nil)
	//flow.CheckFatal(err)
	//fromKNIFlow, err := flow.SetSenderReceiverKNI(toKNIFlow, kni, true)
	//flow.CheckFatal(err)
	//outputFlow, err := flow.SetMerger(inputFlow, fromKNIFlow)
	//flow.CheckFatal(err)
	//flow.CheckFatal(flow.SetSender(outputFlow, uint16(0)))

	mainFlow := flow.SetGenerator(genFn, nil)
	flow.SetHandlerDrop(mainFlow, encapFn, nil)
	//flow.SetSenderFile(mainFlow, "/tmp/gtp-u.pcap")
	// Send all generated packets to the output port
	flow.CheckFatal(flow.SetSender(mainFlow, 0))

	//flow.SetStopper(mainFlow)

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

	return true
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

func arpSeparator(p *packet.Packet, c flow.UserContext) bool {
	p.ParseL3()
	if p.GetARP() != nil {
		return false
	}
	return true
}

