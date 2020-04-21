package main

import (
	"log"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
)

var lorIP = types.BytesToIPv4(1, 2, 3, 4)
var stoIP = types.BytesToIPv4(48, 8, 8, 5)

func main() {
	flow.SystemInit(&flow.Config{CPUList: "0-9"})

	mainFlow := flow.SetGenerator(genICMP, nil)
	flow.SetHandlerDrop(mainFlow, encap, nil)
	flow.SetStopper(mainFlow)

	flow.SystemStart()
}

func encap(p *packet.Packet, c flow.UserContext) bool {
	if p.EncapsulateIPv4GTP("TODO get from flags") == false {
		log.Println("Error encapsulating GTP-U packet")
		return false
	}

	p.ParseL4()
	ipv4 := p.GetIPv4NoCheck()
	length := p.GetPacketLen()

	ipv4.VersionIhl = 0x45
	ipv4.TypeOfService = 0
	ipv4.PacketID = 0x1513
	ipv4.FragmentOffset = 0
	ipv4.TimeToLive = 64

	ipv4.TotalLength = packet.SwapBytesUint16(uint16(length - types.EtherLen))
	ipv4.NextProtoID = types.UDPNumber
	ipv4.SrcAddr = stoIP
	ipv4.DstAddr = lorIP
	ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))

	udp := p.GetIDPNoCheck()
	udp.SrcPort = packet.SwapUDPPortGTPU
	udp.DstPort = packet.SwapUDPPortGTPU
	udp.DgramLen = uint16(length - types.EtherLen - types.IPv4MiniLen)
	udp.DgramCksum = 0

	return true
}

func genICMP(p *packet.Packet, c *flow.UserContext) {
	payload := uint(25)
	packet.InitEmptyIPv4ICMPPacket(p, payload)
	ipv4 := p.GetIPv4NoCheck()
	ipv4.SrcAddr = stoIP
	ipv4.DstAddr = lorIP
}
