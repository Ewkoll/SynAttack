package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"math/rand"
	"net"
	"time"
)

var (
	debug bool = false
)

type SynPacket struct {
	LocalIP    net.IP
	RemoteIP   net.IP
	LocalPort  uint32
	RemotePort uint32
	IpID       uint16
	TcpSeq     uint32
	TcpAck     uint32
	LocalMac   net.HardwareAddr
	RemoteMac  net.HardwareAddr
}

func (syn *SynPacket) GetSynPacket() []byte {
	rawBytes := GetRandomString(1024)

	ethernetLayer := &layers.Ethernet{
		SrcMAC:       syn.LocalMac,
		DstMAC:       syn.RemoteMac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := &layers.IPv4{
		Version:    4,
		IHL:        5,
		TOS:        0,
		Length:     60 + 1024,
		Id:         syn.IpID,
		Flags:      0x02,
		FragOffset: 0,
		TTL:        64,
		Protocol:   layers.IPProtocolTCP,
		SrcIP:      syn.LocalIP,
		DstIP:      syn.RemoteIP,
	}

	var synOptions []layers.TCPOption
	mss := layers.TCPOption{
		OptionType:   2,
		OptionLength: 4,
		OptionData:   []byte{byte(rand.Intn(255)), byte(rand.Intn(255))},
		//OptionData: []byte{0x05, 0xb4},
	}
	sack := layers.TCPOption{
		OptionType:   4,
		OptionLength: 2,
	}
	timestamp := layers.TCPOption{
		OptionType:   8,
		OptionLength: 10,
		OptionData:   []byte{byte(rand.Intn(255)), byte(rand.Intn(255)), byte(rand.Intn(255)), byte(rand.Intn(255)), 0, 0, 0, 0},
		//OptionData: []byte{0x2e, 0x4e, 0x34, 0xbf, 0, 0, 0, 0},
	}
	nop := layers.TCPOption{
		OptionType: 1,
	}
	ws := layers.TCPOption{
		OptionType:   3,
		OptionLength: 3,
		OptionData:   []byte{0x07},
	}
	synOptions = append(synOptions, mss)
	synOptions = append(synOptions, sack)
	synOptions = append(synOptions, timestamp)
	synOptions = append(synOptions, nop)
	synOptions = append(synOptions, ws)

	tcpLayer := &layers.TCP{
		SrcPort:    layers.TCPPort(syn.LocalPort),
		DstPort:    layers.TCPPort(syn.RemotePort),
		Seq:        syn.TcpSeq,
		Ack:        syn.TcpAck,
		DataOffset: 40 / 4,
		SYN:        true,
		Window:     14600,
		Options:    synOptions,
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(
		buffer,
		options,
		ethernetLayer,
		ipLayer,
		tcpLayer,
		gopacket.Payload(rawBytes),
	)

	if nil != err {
		fmt.Println(err)
	}

	outgoingPacket := buffer.Bytes()
	if debug {
		for k, v := range outgoingPacket {
			if k%16 == 0 {
				fmt.Printf("\n")
			}
			fmt.Printf("%02x\t", v)
		}
	}
	return outgoingPacket
}

func (syn *SynPacket) SendSynPacket(handle *pcap.Handle) {
	fmt.Println(time.Now())
	syn.IpID = uint16(rand.Intn(65535))
	syn.TcpSeq = rand.Uint32()
	syn.TcpAck = 0
	synPacketData := syn.GetSynPacket()

	for {
		err := handle.WritePacketData(synPacketData)
		if nil != err {
			fmt.Println(err)
		}
		time.Sleep(time.Millisecond * 500)
	}

	/*
		syn.IpID++
		syn.TcpSeq++
	*/
}
