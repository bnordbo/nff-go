package main

import (
	"log"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
)

var SRC = types.BytesToIPv4(1, 2, 3, 4)
var DST = types.BytesToIPv4(48, 8, 8, 5)

func main() {
	flow.SystemInit(&flow.Config{CPUList: "0-9"})

	mainFlow := flow.SetGenerator(genICMP, nil)
	flow.SetHandlerDrop(mainFlow, encap, nil)

	flow.SystemStart()
}

func encap(p *packet.Packet, c flow.UserContext) bool {
	if p.EncapsulateIPv4GTP("TODO get from flags") == false {
		log.Println("Error encapsulating GTP-U packet")
		return false
	}

	return true
}

func genICMP(p *packet.Packet, c *flow.UserContext) {
	payload := uint(25)
	packet.InitEmptyIPv4UDPPacket(p, payload)
	ipv4 := p.GetIPv4NoCheck()
	udp := p.GetUDPNoCheck()
	ipv4.SrcAddr = SRC
	ipv4.DstAddr = DST
	udp.SrcPort = packet.SwapBytesUint16(1234)
	udp.DstPort = packet.SwapBytesUint16(2152)
}
