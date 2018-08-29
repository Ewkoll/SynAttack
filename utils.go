package main

import (
	"fmt"
	"github.com/axgle/mahonia"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var (
	snapshot_len int32 = 1024
)

func ShowDevice() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return
	}

	fmt.Println("Devices found:")
	for _, device := range devices {
		fmt.Println("\nName: ", device.Name)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ", device.Flags)
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}
	}
}

func OpenDevice(device string) *pcap.Handle {
	timeout := 30 * time.Second
	handle, err := pcap.OpenLive(device, snapshot_len, false, timeout)
	if nil != err {
		return nil
	}
	return handle
}

func ShowPackage(handle *pcap.Handle) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println(packet)
	}
}

func SavePacket(handle *pcap.Handle, name string, count int) {
	if nil == handle {
		return
	}

	f, _ := os.Create(name)
	defer f.Close()

	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(uint32(snapshot_len), layers.LinkTypeEthernet)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetCount := 0
	for packet := range packetSource.Packets() {
		w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		packetCount++

		if packetCount >= count {
			break
		}
	}
}

func AnalyFile(name string) {
	handle, err := pcap.OpenOffline(name)
	if nil != err {
		return
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println(packet)
	}
}

func CmdGetMac(desc string) string {
	cmd := exec.Command("getmac", "/FO", "csv", "/v", "/NH")
	buf, err := cmd.Output()
	if err != nil {
		return ""
	}

	s := mahonia.NewDecoder("gb18030").ConvertString(string(buf))
	for _, v := range strings.Split(s, "\n") {
		result := strings.Split(v, ",")
		if len(result) == 4 {
			deviceName := strings.Trim(result[1], "\"\r")
			if deviceName == desc {
				return strings.Trim(result[2], "\"\r")
			}
		}
	}
	return ""
}

func GetLocalIP() []string {
	var ipList []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ipList
	}

	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if nil != ipnet.IP.To4() {
				ipList = append(ipList, ipnet.IP.String())
			}
		}
	}
	return ipList
}

func GetDeviceInfoByIP(ip string) (name string, desc string) {
	devices, err := pcap.FindAllDevs()
	if nil != err {
		return
	}

	for _, device := range devices {
		for _, address := range device.Addresses {
			if address.IP.String() == ip {
				return device.Name, device.Description
			}
		}
	}
	return
}

func GetMacByDescription(desc string) string {
	return CmdGetMac(desc)
}

func MacToByte(mac string) []byte {
	macArray := strings.Split(mac, "-")
	var macByte []byte
	for _, v := range macArray {
		r, err := strconv.ParseInt(v, 16, 16)
		if nil != err {
			return macByte
		}
		macByte = append(macByte, byte(r))
	}
	return macByte
}

func IpToByte(ip string) []byte {
	ipArray := strings.Split(ip, ".")
	var ipByte []byte
	for _, v := range ipArray {
		r, err := strconv.ParseInt(v, 10, 16)
		if nil != err {
			return ipByte
		}
		ipByte = append(ipByte, byte(r))
	}
	return ipByte
}

func init() {
	rand.Seed(time.Now().Unix())
}

func GetRandPort() int {
	port := rand.Intn(65535)
	if port < 1000 {
		port += 1000
	}
	return port
}

func GetRandomString(l int) []byte {
	str := "0123456789abcdefghijklmnopqrstuvwxyz"
	bytes := []byte(str)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < l; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return result
}
