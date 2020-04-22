// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"fmt"
	"sync"
	"time"

	"github.com/bnordbo/nff-go/common"
	"github.com/bnordbo/nff-go/types"
)

const (
	arpRequestsRepeatInterval = 1 * time.Second
	arpEntryCleanup = 60 * time.Second
)

type NeighboursLookupTable struct {
	portIndex            uint16
	ipv4Table            sync.Map
	ipv6Table            sync.Map
	ipv4SentRequestTable sync.Map
	ipv6SentRequestTable sync.Map
	interfaceMAC         types.MACAddress
	// Should return true if IPv4 address belongs to interface
	checkv4 func(ipv4 types.IPv4Address) bool
	// Should return true if IPv6 address belongs to interface
	checkv6 func(ipv6 types.IPv6Address) bool
}

type neighboursLookupTableEntry struct {
	MAC      types.MACAddress
	LastUsed time.Time
}

func NewNeighbourTable(index uint16, mac types.MACAddress,
	checkv4 func(ipv4 types.IPv4Address) bool,
	checkv6 func(ipv6 types.IPv6Address) bool) *NeighboursLookupTable {

	return NewTimeoutNeighbourTable(index, mac, checkv4, checkv6, 0)
}

func NewTimeoutNeighbourTable(index uint16, mac types.MACAddress,
	checkv4 func(ipv4 types.IPv4Address) bool,
	checkv6 func(ipv6 types.IPv6Address) bool,
	cleanupInterval time.Duration) *NeighboursLookupTable {

	nlt := &NeighboursLookupTable{
		portIndex:    index,
		interfaceMAC: mac,
		checkv4:      checkv4,
		checkv6:      checkv6,
	}

	if cleanupInterval <= 0 {
		return nlt
	}

	go func() {
		ticker := time.NewTicker(cleanupInterval)

		for {
			select {
			case <-ticker.C:
				nlt.cleanup()
			}
		}
	}()

	return nlt
}

func (table *NeighboursLookupTable) cleanup() {
	table.ipv4Table.Range(func(k interface{}, v interface{}) bool {
		entry := v.(neighboursLookupTableEntry)
		if time.Since(entry.LastUsed) >= arpEntryCleanup {
			ipv4 := k.(types.IPv4Address)
			table.ipv4Table.Delete(ipv4)
			common.LogDebug(common.Debug, "Removed ARP Entry for", ipv4, ":", entry.MAC)
		}
		return true
	})
}

// HandleIPv4ARPRequest processes IPv4 ARP request and reply packets
// and sends an ARP response (if needed) to the same interface. Packet
// has to have L3 parsed. If ARP request packet has VLAN tag, VLAN tag
// is copied into reply packet.
func (table *NeighboursLookupTable) HandleIPv4ARPPacket(pkt *Packet) error {
	arp := pkt.GetARPNoCheck()

	if SwapBytesUint16(arp.Operation) != ARPRequest {
		// Handle ARP reply and record information in lookup table
		if SwapBytesUint16(arp.Operation) == ARPReply {
			ipv4 := types.ArrayToIPv4(arp.SPA)
			entry := neighboursLookupTableEntry {
				MAC: arp.SHA,
				LastUsed: time.Now(),
			}
			table.ipv4Table.Store(ipv4, entry)
			common.LogDebug(common.Debug, "Added ARP Entry for", ipv4, ":", entry.MAC)
		}
		return nil
	}

	// Check that someone is asking about MAC of my IP address and HW
	// address is blank in request
	targetIP := types.BytesToIPv4(arp.TPA[0], arp.TPA[1], arp.TPA[2], arp.TPA[3])
	if !table.checkv4(targetIP) {
		return fmt.Errorf("Warning! Got an ARP packet with target IPv4 address %s different from IPv4 address on interface. ARP request ignored.", types.IPv4ArrayToString(arp.TPA))
	}

	// Prepare an answer to this request
	answerPacket, err := NewPacket()
	if err != nil {
		return err
	}

	InitARPReplyPacket(answerPacket, table.interfaceMAC, arp.SHA, types.ArrayToIPv4(arp.TPA), types.ArrayToIPv4(arp.SPA))
	vlan := pkt.GetVLAN()
	if vlan != nil {
		answerPacket.AddVLANTag(SwapBytesUint16(vlan.TCI))
	}

	answerPacket.SendPacket(table.portIndex)
	return nil
}

// LookupMACForIPv4 tries to find MAC address for specified IPv4
// address.
func (table *NeighboursLookupTable) LookupMACForIPv4(ipv4 types.IPv4Address) (types.MACAddress, bool) {
	v, found := table.ipv4Table.Load(ipv4)
	if found {
		entry := v.(neighboursLookupTableEntry)
		entry.LastUsed = time.Now()
		table.ipv4Table.Store(ipv4, entry)
		return entry.MAC, true
	}
	return [types.EtherAddrLen]byte{}, false
}

// SendARPRequestForIPv4 sends an ARP request for specified IPv4
// address. If specified vlan tag is not zero, ARP request packet gets
// VLAN tag assigned to it.
func (table *NeighboursLookupTable) SendARPRequestForIPv4(ipv4, myIPv4Address types.IPv4Address, vlan uint16) {
	v, found := table.ipv4SentRequestTable.Load(ipv4)
	if found {
		lastsent := v.(time.Time)
		if time.Since(lastsent) < arpRequestsRepeatInterval {
			// Another ARP request has beep sent recently, we're still
			// waiting for reply
			return
		}
	}

	requestPacket, err := NewPacket()
	if err != nil {
		common.LogFatal(common.Debug, err)
	}

	InitARPRequestPacket(requestPacket, table.interfaceMAC, myIPv4Address, ipv4)

	if vlan != 0 {
		requestPacket.AddVLANTag(vlan)
	}

	requestPacket.SendPacket(table.portIndex)
	table.ipv4SentRequestTable.Store(ipv4, time.Now())
}
