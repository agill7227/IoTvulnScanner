package discovery

import (
	"fmt"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Device struct {
	IP           net.IP
	MAC          net.HardwareAddr
	Manufacturer string
	DeviceType   string
	Model        string
	OpenPorts    []int
	Services     map[int]string
	Protocols    []string
}

type Scanner struct {
	Interface *net.Interface
	IPRange   string
	Timeout   time.Duration
}

func NewScanner(iface string, ipRange string) (*Scanner, error) {
	if iface == "" {
		interfaces, err := net.Interfaces()
		if err != nil {
			return nil, fmt.Errorf("failed to list interfaces: %v", err)
		}

		fmt.Println("\nAvailable network interfaces:")
		for _, i := range interfaces {
			addrs, _ := i.Addrs()
			if len(addrs) > 0 && i.Flags&net.FlagLoopback == 0 {
				fmt.Printf("- %s (%s)\n", i.Name, i.Flags)
			}
		}

		for _, i := range interfaces {
			addrs, err := i.Addrs()
			if err != nil {
				continue
			}
			if len(addrs) == 0 || i.Flags&net.FlagLoopback != 0 {
				continue
			}
			if i.Flags&net.FlagUp == 0 {
				continue
			}
			if runtime.GOOS == "windows" &&
				(strings.Contains(i.Name, "Wi-Fi") || strings.Contains(i.Name, "Wireless")) {
				iface = i.Name
				break
			}
			iface = i.Name
			break
		}
		fmt.Printf("\nSelected interface: %s\n", iface)
	}

	intf, err := net.InterfaceByName(iface)
	if err != nil {
		interfaces, err := net.Interfaces()
		if err != nil {
			return nil, fmt.Errorf("failed to list interfaces: %v", err)
		}

		for _, i := range interfaces {
			if i.Name == "Wi-Fi" || i.Name == iface {
				intf = &i
				break
			}
		}

		if intf == nil {
			return nil, fmt.Errorf("interface not found: %v", err)
		}
	}

	addrs, err := intf.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get interface addresses: %v", err)
	}
	fmt.Printf("Interface %s has addresses: %v\n", intf.Name, addrs)

	return &Scanner{
		Interface: intf,
		IPRange:   ipRange,
		Timeout:   10 * time.Second,
	}, nil
}

func (s *Scanner) ScanNetwork() ([]Device, error) {
	fmt.Printf("\nStarting network scan on %s for range %s\n", s.Interface.Name, s.IPRange)

	var startIP, endIP net.IP
	if strings.Contains(s.IPRange, "-") {
		parts := strings.Split(s.IPRange, "-")
		startIP = net.ParseIP(parts[0])
		baseIP := strings.Join(strings.Split(parts[0], ".")[:3], ".") + "."
		endIP = net.ParseIP(baseIP + parts[1])
	} else if strings.Contains(s.IPRange, "/") {
		_, ipnet, err := net.ParseCIDR(s.IPRange)
		if err != nil {
			return nil, fmt.Errorf("invalid IP range: %v", err)
		}
		startIP = ipnet.IP
		endIP = make(net.IP, len(ipnet.IP))
		for i := range ipnet.IP {
			endIP[i] = ipnet.IP[i] | ^ipnet.Mask[i]
		}
	} else {
		startIP = net.ParseIP(s.IPRange)
		endIP = startIP
	}

	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("invalid IP range")
	}

	fmt.Printf("Scanning IP range from %s to %s\n", startIP, endIP)

	interfaceName := s.Interface.Name
	if runtime.GOOS == "windows" {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			return nil, fmt.Errorf("failed to list pcap devices: %v", err)
		}

		fmt.Println("Available pcap devices:")
		for _, dev := range devices {
			fmt.Printf("- Name: %s, Description: %s\n", dev.Name, dev.Description)
			for _, addr := range dev.Addresses {
				fmt.Printf("  Address: %v\n", addr.IP)
			}
		}

		var deviceFound bool
		for _, device := range devices {
			if strings.Contains(device.Description, "Wi-Fi") ||
				strings.Contains(device.Description, "Wireless") {
				interfaceName = device.Name
				deviceFound = true
				fmt.Printf("Selected pcap device: %s (%s)\n", device.Name, device.Description)
				break
			}
		}

		if !deviceFound {
			return nil, fmt.Errorf("failed to find wireless interface")
		}
	}

	handle, err := pcap.OpenLive(interfaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open interface %s: %v", interfaceName, err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter("arp")
	if err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %v", err)
	}

	devices := make([]Device, 0)
	stop := make(chan struct{})
	deviceMap := make(map[string]Device)
	discoveredCount := 0

	go func() {
		start := ipToInt(startIP)
		end := ipToInt(endIP)

		fmt.Printf("\nScanning network for devices...\n")
		for ip := start; ip <= end; ip++ {
			select {
			case <-stop:
				return
			default:
				targetIP := intToIP(ip)
				err := s.SendARPRequest(targetIP)
				if err != nil && strings.Contains(err.Error(), "failed to open interface") {
					fmt.Printf("Error: Could not access network interface. Please run with administrator/root privileges.\n")
					close(stop)
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
		}

		time.Sleep(2 * time.Second)
	}()

	go func() {
		time.Sleep(s.Timeout)
		close(stop)
	}()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		select {
		case <-stop:
			if discoveredCount > 0 {
				fmt.Printf("\nScan complete. Found %d devices.\n", discoveredCount)
			} else {
				fmt.Printf("\nScan complete. No devices found.\n")
			}
			for _, device := range deviceMap {
				devices = append(devices, device)
			}
			return devices, nil
		default:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}

			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply {
				continue
			}

			ip := net.IP(arp.SourceProtAddress).String()
			mac := net.HardwareAddr(arp.SourceHwAddress)

			if _, exists := deviceMap[ip]; !exists {
				device := Device{
					IP:       net.IP(arp.SourceProtAddress),
					MAC:      mac,
					Services: make(map[int]string),
				}
				device.identifyManufacturer()
				deviceMap[ip] = device
				discoveredCount++

				manufacturer := device.Manufacturer
				if manufacturer == "" {
					manufacturer = "Unknown"
				}
				fmt.Printf("Found device: %s (%s) - %s\n", ip, mac, manufacturer)
			}
		}
	}

	return devices, nil
}

func ipToInt(ip net.IP) int64 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return int64(ip[0])<<24 | int64(ip[1])<<16 | int64(ip[2])<<8 | int64(ip[3])
}

func intToIP(nn int64) net.IP {
	ip := make(net.IP, 4)
	ip[0] = byte(nn >> 24)
	ip[1] = byte(nn >> 16)
	ip[2] = byte(nn >> 8)
	ip[3] = byte(nn)
	return ip
}

func (s *Scanner) SendARPRequest(targetIP net.IP) error {
	var sourceIP net.IP
	addrs, err := s.Interface.Addrs()
	if err != nil {
		return fmt.Errorf("failed to get interface addresses: %v", err)
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipv4 := ipnet.IP.To4(); ipv4 != nil {
				sourceIP = ipv4
				break
			}
		}
	}

	if sourceIP == nil {
		return fmt.Errorf("no IPv4 address found for interface")
	}

	eth := layers.Ethernet{
		SrcMAC:       s.Interface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(s.Interface.HardwareAddr),
		SourceProtAddress: []byte(sourceIP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(targetIP),
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(buffer, opts, &eth, &arp)
	if err != nil {
		return fmt.Errorf("failed to serialize packet: %v", err)
	}

	interfaceName := s.Interface.Name
	if runtime.GOOS == "windows" {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			return fmt.Errorf("failed to list pcap devices: %v", err)
		}

		var deviceFound bool
		for _, device := range devices {
			if strings.Contains(device.Description, "Wi-Fi") ||
				strings.Contains(device.Description, "Wireless") {
				interfaceName = device.Name
				deviceFound = true
				break
			}
		}

		if !deviceFound {
			return fmt.Errorf("failed to find wireless interface")
		}
	}

	handle, err := pcap.OpenLive(interfaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %v", interfaceName, err)
	}
	defer handle.Close()

	return handle.WritePacketData(buffer.Bytes())
}

func (d *Device) identifyManufacturer() {
	macPrefix := strings.ToUpper(d.MAC.String()[:8])

	manufacturers := map[string]string{
		"1C:AF:4A": "SAMSUNG",
		"48:22:54": "MIKROTIK",
		"98:ED:5C": "TESLA",
		"F0:B0:40": "HUAWEI",
		"AC:50:DE": "APPLE",
		"44:61:32": "ECOBEE",
		"5A:C2:89": "INTEL",
		"7A:58:36": "PRIVATE",
		"74:97:79": "LENOVO",
		"6C:5A:B0": "HUAWEI",
		"18:C0:4D": "CISCO-LINKSYS",
	}

	if manufacturer, ok := manufacturers[macPrefix]; ok {
		d.Manufacturer = manufacturer
	} else {
		macPrefix = strings.ToUpper(d.MAC.String()[:6])
		if manufacturer, ok := manufacturers[macPrefix]; ok {
			d.Manufacturer = manufacturer
		}
	}

	switch d.Manufacturer {
	case "SAMSUNG":
		d.DeviceType = "Samsung Smart TV"
	case "MIKROTIK":
		d.DeviceType = "Network Router"
	case "TESLA":
		d.DeviceType = "Tesla Device"
	case "HUAWEI":
		d.DeviceType = "Huawei Device"
	case "APPLE":
		d.DeviceType = "Apple Device"
	case "ECOBEE":
		d.DeviceType = "Smart Thermostat"
	case "INTEL":
		d.DeviceType = "Intel Device"
	case "PRIVATE":
		d.DeviceType = "Privacy-Enabled Device"
	case "LENOVO":
		d.DeviceType = "Lenovo Computer"
	case "CISCO-LINKSYS":
		d.DeviceType = "Network Device"
	}
}

func hasPort(ports []int, port int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

func getMACVendor(prefix string) string {
	vendors := map[string]string{
		"00:E0:4C": "SAMSUNG",
		"00:1A:C5": "SAMSUNG",
		"00:15:B9": "SAMSUNG",
		"00:12:FB": "SAMSUNG",
		"00:00:F0": "SAMSUNG",
		"1C:AF:4A": "SAMSUNG",
		"00:E0:91": "LG",
		"00:05:C9": "LG",
		"00:1C:62": "LG",
		"00:1E:75": "LG",
		"34:FC:EF": "LG",
		"00:1E:C2": "APPLE",
		"00:17:AB": "APPLE",
		"00:1C:B3": "APPLE",
		"00:1D:4F": "APPLE",
		"00:50:43": "SONY",
		"00:01:4A": "SONY",
		"00:24:BE": "SONY",
		"04:56:E5": "INTEL",
	}

	if vendor, exists := vendors[prefix]; exists {
		return vendor
	}
	return ""
}
