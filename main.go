package main

import (
	"flag"
	"net"
	"time"
)

var (
	remoteMac  = flag.String("remoteMac", "00-00-00-00-00-00", "remote mac address")
	remoteIP   = flag.String("remoteIP", "00.00.00.00", "remote ip address")
	remotePort = flag.Int("remotePort", 8090, "remote port")
)

func main() {
	ipArray := GetLocalIP()
	if len(ipArray) == 0 {
		return
	}

	localIP := ipArray[2]
	device, desc := GetDeviceInfoByIP(localIP)
	if device == "" {
		return
	}

	localMac := GetMacByDescription(desc)
	if localMac == "" {
		return
	}

	srcMac := MacToByte(localMac)
	dstMac := MacToByte(*remoteMac)
	if len(srcMac) != 6 || len(dstMac) != 6 {
		return
	}

	srcIP := IpToByte(localIP)
	dstIP := IpToByte(*remoteIP)
	if len(srcIP) != 4 || len(dstIP) != 4 {
		return
	}

	handle := OpenDevice(device)
	defer handle.Close()

	for port := 10000; port < 14001; port++ {
		synPacket := SynPacket{
			RemotePort: uint32(*remotePort),
			LocalPort:  uint32(port),
			LocalIP:    net.IP(srcIP),
			RemoteIP:   net.IP(dstIP),
			LocalMac:   net.HardwareAddr(srcMac),
			RemoteMac:  net.HardwareAddr(dstMac),
		}

		go synPacket.SendSynPacket(handle)
	}

	time.Sleep(time.Hour * 1)
}
