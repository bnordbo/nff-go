package main

import (
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packets"
	"github.com/intel-go/nff-go/types"
)

const src = types.BytesToIPv4(1, 2, 3, 4)
const dst = types.BytesToIPv4(48, 8, 8, 5)

func main() {
	flow.SystemInit(&flow.Config{CPUList: "0-9"})

	mainFlow := flow.SetFastGenerator(genICMP, nil)
	flow.SetHandlerDrop(mainFlow, encap, nil)

	flow.SystemStart()
}

func encap(p *packet.Packet, c flow.UserContext) bool {
	if current.EncapsulateIPv4GTP("TODO get from flags") == false {

	}

}

func genICMP(p *packet.Packet, c *flow.UserContext) {
	payload := uint(25)
	packet.InitEmptyIPv4UDPPacket(p, payload)
	ipv4 := p.GetIPv4NoCheck()
	udp := p.GetUDPNoCheck()
	ipv4.SrcAddr = src
	ipv4.DstAddr = dst
	udp.SrcPort = packet.SwapBytesUint16(1234)
	udp.DstPort = packet.SwapBytesUint16(2152)
}
