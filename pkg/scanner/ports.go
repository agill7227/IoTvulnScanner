package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type PortScanner struct {
	target        string
	tcpTimeout    time.Duration
	udpTimeout    time.Duration
	portRange     []int
	numWorkers    int
	verbose       bool
	maxBannerSize int
}

type PortResult struct {
	Port       int
	State      string
	Service    string
	DeviceType string
}

func NewPortScanner(target string) *PortScanner {
	return &PortScanner{
		target:        target,
		tcpTimeout:    3 * time.Second,
		udpTimeout:    5 * time.Second,
		numWorkers:    1,
		portRange:     []int{},
		verbose:       false,
		maxBannerSize: 4096,
	}
}

func (s *PortScanner) SetPorts(ports []int) {
	commonIoTPorts := []int{
		20,    // FTP data transfer
		21,    // FTP control
		22,    // SSH remote access
		23,    // Telnet (insecure remote access)
		25,    // SMTP email
		53,    // DNS domain lookup
		80,    // HTTP web server
		443,   // HTTPS secure web
		554,   // RTSP video streaming
		1883,  // MQTT IoT messaging
		1900,  // UPnP device discovery
		3389,  // Remote desktop
		5683,  // CoAP IoT protocol
		8008,  // Alternative HTTP
		8009,  // Alternative HTTP
		8080,  // HTTP proxy
		8443,  // HTTPS alternate
		8883,  // MQTT over SSL
		9100,  // Printer port
		49152, // UPnP alternate
	}

	samsungPorts := []int{
		8001,  // Main control API
		8002,  // Secure control API
		7676,  // Debug interface
		9090,  // Web socket API
		9091,  // Secure web socket
		9197,  // Remote control
		9198,  // Secure remote control
		8889,  // Media streaming
		55000, // Remote control alternate
	}

	validPorts := make([]int, 0)

	addPort := func(port int) {
		if port > 0 && port < 65536 {
			validPorts = append(validPorts, port)
		} else if s.verbose {
			fmt.Printf("Warning: Invalid port number %d ignored\n", port)
		}
	}

	if len(ports) == 0 {
		for _, port := range commonIoTPorts {
			addPort(port)
		}
		for _, port := range samsungPorts {
			addPort(port)
		}
	} else {
		for _, port := range ports {
			addPort(port)
		}
	}

	s.portRange = removeDuplicates(validPorts)
}

func removeDuplicates(ports []int) []int {
	portsMap := make(map[int]bool)
	result := []int{}
	for _, port := range ports {
		if !portsMap[port] {
			portsMap[port] = true
			result = append(result, port)
		}
	}
	return result
}

func (s *PortScanner) SetPortRange(start, end int) {
	commonIoTPorts := []int{
		20, 21, // FTP ports
		22,         // SSH port
		23,         // Telnet port
		25,         // SMTP port
		53,         // DNS port
		80,         // HTTP port
		443,        // HTTPS port
		554,        // RTSP port
		1883,       // MQTT port
		1900,       // UPnP port
		3389,       // Remote Desktop port
		5683,       // CoAP port
		8001, 8002, // Samsung TV main ports
		7676,       // Samsung TV debug port
		9090, 9091, // Samsung TV websocket ports
		9197, 9198, // Samsung TV remote control ports
		8889,       // Samsung TV media port
		55000,      // Samsung TV alternate remote port
		8008, 8009, // Additional HTTP ports
		8080,  // HTTP proxy port
		8443,  // HTTPS alternate port
		8883,  // MQTT over SSL port
		9100,  // Printer port
		49152, // UPnP alternate port
	}

	validPorts := make(map[int]bool)
	for _, port := range commonIoTPorts {
		if port >= start && port <= end {
			validPorts[port] = true
		}
	}

	var ports []int
	for port := range validPorts {
		ports = append(ports, port)
	}

	s.portRange = ports
}

func (s *PortScanner) SetTimeout(timeout time.Duration) {
	s.tcpTimeout = timeout
}

func (s *PortScanner) SetVerbose(verbose bool) {
	s.verbose = verbose
}

func (s *PortScanner) ScanPorts() ([]PortResult, error) {
	var results []PortResult

	fmt.Printf("Starting IoT device port scan on %s...\n", s.target)

	if s.verbose {
		fmt.Printf("Scanning %d known IoT ports...\n", len(s.portRange))
		fmt.Printf("Port list: %v\n", s.portRange)
	}

	for _, port := range s.portRange {
		if result := s.scanPort(port); result != nil {
			results = append(results, *result)
			fmt.Printf("\nFound open port %d (%s)\n", port, result.Service)

			desc := s.getPortDescription(port, result.DeviceType)
			fmt.Printf("  - %s\n", desc)
		}
		time.Sleep(300 * time.Millisecond)
	}

	if len(results) == 0 {
		fmt.Printf("\nNo open ports found. Troubleshooting steps:\n")
		fmt.Printf("1. Verify the device is powered on and connected to the network\n")
		fmt.Printf("2. Check if you can ping %s\n", s.target)
		fmt.Printf("3. Verify there are no firewalls blocking access\n")
	} else {
		fmt.Printf("\nPort scan complete. Found %d open ports.\n", len(results))
	}

	return results, nil
}

func (s *PortScanner) scanPort(port int) *PortResult {
	target := fmt.Sprintf("%s:%d", s.target, port)

	dialer := &net.Dialer{
		Timeout: s.tcpTimeout,
	}

	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		if s.verbose {
			fmt.Printf("Debug: Port %d error: %v\n", port, err)
		}

		if port == 1900 || port == 5683 || port == 8001 {
			if s.verbose {
				fmt.Printf("Debug: Trying UDP on port %d\n", port)
			}

			udpAddr, err := net.ResolveUDPAddr("udp", target)
			if err != nil {
				return nil
			}

			udpConn, err := net.DialUDP("udp", nil, udpAddr)
			if err != nil {
				if s.verbose {
					fmt.Printf("Debug: UDP connection error on port %d: %v\n", port, err)
				}
				return nil
			}
			defer udpConn.Close()

			udpConn.SetDeadline(time.Now().Add(s.udpTimeout))

			var probe []byte
			switch port {
			case 1900:
				probe = []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n")
			case 5683:
				probe = []byte{0x40, 0x01, 0x00, 0x01}
			case 8001:
				probe = []byte("GET / HTTP/1.1\r\nUpgrade: websocket\r\n\r\n")
			}

			_, err = udpConn.Write(probe)
			if err != nil {
				if s.verbose {
					fmt.Printf("Debug: UDP write error on port %d: %v\n", port, err)
				}
				return nil
			}

			response := make([]byte, 1024)
			udpConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, _, err := udpConn.ReadFromUDP(response)

			if err != nil {
				if s.verbose {
					fmt.Printf("Debug: UDP read error on port %d: %v\n", port, err)
				}
				return nil
			}

			if n > 0 {
				if s.verbose {
					fmt.Printf("Debug: Got UDP response from port %d: %d bytes\n", port, n)
				}
				return &PortResult{
					Port:       port,
					State:      "open (UDP)",
					Service:    getServiceName(port),
					DeviceType: "unknown",
				}
			}
			return nil
		}
		return nil
	}
	defer conn.Close()

	if s.verbose {
		fmt.Printf("Debug: TCP port %d is open\n", port)
	}

	service := getServiceName(port)
	state := "open"

	if port == 80 || port == 8080 || port == 8001 || port == 8002 {
		client := &http.Client{
			Timeout: s.tcpTimeout,
			Transport: &http.Transport{
				DisableKeepAlives: true,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}

		url := fmt.Sprintf("http://%s", target)
		if s.verbose {
			fmt.Printf("Debug: Trying HTTP on %s\n", url)
		}

		if resp, err := client.Get(url); err == nil {
			defer resp.Body.Close()

			if resp.Header.Get("Server") != "" {
				service = fmt.Sprintf("HTTP (%s)", resp.Header.Get("Server"))
			} else {
				service = "HTTP"
			}

			if s.verbose {
				fmt.Printf("Debug: Got HTTP response from port %d\n", port)
			}
		} else {
			if s.verbose {
				fmt.Printf("Debug: HTTP error on port %d: %v\n", port, err)
			}
		}
	}

	if port == 443 || port == 8443 || port == 8002 {
		config := &tls.Config{
			InsecureSkipVerify: true,
		}

		if tlsConn, err := tls.DialWithDialer(dialer, "tcp", target, config); err == nil {
			defer tlsConn.Close()

			state = "open (SSL/TLS)"

			if len(tlsConn.ConnectionState().PeerCertificates) > 0 {
				cert := tlsConn.ConnectionState().PeerCertificates[0]
				service = fmt.Sprintf("HTTPS (%s)", cert.Subject.CommonName)
			} else {
				service = "HTTPS"
			}
		}
	}

	if service == "unknown" || service == "FTP" || service == "SSH" || service == "SMTP" || service == "Samsung TV Control" {
		if banner := grabBanner(target, s.tcpTimeout, s.maxBannerSize); banner != "" {
			service = fmt.Sprintf("%s (%s)", service, banner)
		}
	}

	deviceType := s.detectDeviceType(s.target, s.portRange)

	return &PortResult{
		Port:       port,
		State:      state,
		Service:    service,
		DeviceType: deviceType,
	}
}

func (s *PortScanner) detectDeviceType(target string, openPorts []int) string {
	targetLower := strings.ToLower(target)

	if strings.Contains(targetLower, "ecobee") {
		if containsAny(openPorts, []int{8080, 8443, 443}) {
			return "thermostat"
		}
	}

	if strings.Contains(targetLower, "samsung") {
		if containsAny(openPorts, []int{8001, 8002, 9090, 9091}) {
			return "samsung tv"
		}
	}

	if containsAny(openPorts, []int{554, 8554, 8080}) {
		return "ip camera"
	}
	if containsAny(openPorts, []int{9100, 515, 631}) {
		return "printer"
	}

	return "unknown"
}

func containsAny(slice []int, values []int) bool {
	for _, v := range values {
		for _, s := range slice {
			if v == s {
				return true
			}
		}
	}
	return false
}

func grabBanner(target string, timeout time.Duration, maxSize int) string {
	results := make(chan string, len(probeProtocols))

	for protocol, probes := range probeProtocols {
		go func(proto string, probeList []string) {
			conn, err := net.DialTimeout("tcp", target, timeout)
			if err != nil {
				results <- ""
				return
			}
			defer conn.Close()

			for _, probe := range probeList {
				conn.SetWriteDeadline(time.Now().Add(timeout))
				if _, err := conn.Write([]byte(probe)); err != nil {
					continue
				}

				conn.SetReadDeadline(time.Now().Add(timeout))
				banner := make([]byte, maxSize)
				n, err := conn.Read(banner)
				if err == nil && n > 0 {
					results <- cleanBanner(string(banner[:n]))
					return
				}
			}
			results <- ""
		}(protocol, probes)
	}

	timer := time.NewTimer(timeout * 2)
	defer timer.Stop()

	for i := 0; i < len(probeProtocols); i++ {
		select {
		case banner := <-results:
			if banner != "" {
				return banner
			}
		case <-timer.C:
			return ""
		}
	}

	return ""
}

var probeProtocols = map[string][]string{
	"http": {
		"HEAD / HTTP/1.0\r\n\r\n",
		"GET / HTTP/1.0\r\n\r\n",
	},
	"ftp": {
		"USER anonymous\r\n",
		"QUIT\r\n",
	},
	"ssh": {
		"SSH-2.0-OpenSSH\r\n",
	},
	"smtp": {
		"EHLO localhost\r\n",
		"QUIT\r\n",
	},
	"iot": {
		"Samsung UPnP SDK\r\n",
		"GET /common/1.0\r\n",
	},
}

func cleanBanner(banner string) string {
	banner = strings.Map(func(r rune) rune {
		if r < 32 && r != '\n' && r != '\r' {
			return -1
		}
		return r
	}, banner)

	lines := strings.Split(banner, "\n")
	if len(lines) > 0 {
		return strings.TrimSpace(lines[0])
	}
	return ""
}

func getServiceName(port int) string {
	services := map[int]string{
		20:    "FTP-Data",             // FTP Data transfer port
		21:    "FTP",                  // FTP Control port
		22:    "SSH",                  // Secure Shell port
		23:    "Telnet",               // Telnet port
		25:    "SMTP",                 // Simple Mail Transfer Protocol
		53:    "DNS",                  // Domain Name System
		80:    "HTTP",                 // Web server port
		110:   "POP3",                 // Post Office Protocol v3
		143:   "IMAP",                 // Internet Message Access Protocol
		443:   "HTTPS",                // Secure web server port
		445:   "SMB",                  // Server Message Block
		1883:  "MQTT",                 // Message Queuing Telemetry Transport
		1900:  "UPNP",                 // Universal Plug and Play
		3389:  "RDP",                  // Remote Desktop Protocol
		5683:  "CoAP",                 // Constrained Application Protocol
		8001:  "WebSocket API",        // Generic WebSocket port
		8002:  "Secure WebSocket API", // Secure real-time comm
		8008:  "HTTP Alt",             // Alternative HTTP port
		8009:  "HTTP Alt",             // Alternative HTTP port
		8080:  "HTTP-Proxy",           // Common HTTP proxy port
		8443:  "HTTPS Alt",            // Alternative HTTPS port
		8883:  "MQTT SSL",             // Secure MQTT port
		9090:  "WebSocket API",        // Another WebSocket port
		9091:  "WebSocket API SSL",    // Another secure WebSocket port
		9100:  "Printer",              // Network printer port
		49152: "UPnP",                 // UPnP alternative port
	}

	if service, ok := services[port]; ok {
		return service
	}
	return "unknown"
}

var portDescriptions = map[int]string{
	21:    "FTP service for file transfer",
	22:    "SSH service for secure remote access",
	23:    "Telnet service (insecure remote access)",
	80:    "HTTP web service",
	443:   "HTTPS secure web service",
	554:   "RTSP streaming service",
	1883:  "MQTT broker for IoT messaging",
	1900:  "UPnP discovery service",
	5683:  "CoAP service for IoT communication",
	8001:  "WebSocket API service",
	8002:  "Secure WebSocket API service",
	8080:  "Alternative HTTP service",
	8443:  "Alternative HTTPS service",
	9090:  "WebSocket API service",
	9100:  "Network printer service",
	49152: "UPnP service",
}

var samsungTVPorts = map[int]string{
	8001:  "Samsung TV Control API port (WebSocket API)",
	8002:  "Samsung TV Control API port (Encrypted WebSocket API)",
	9090:  "Samsung TV HTTP API",
	9091:  "Samsung TV HTTPS API",
	7676:  "Samsung TV Debug port",
	9197:  "Samsung TV Remote control interface",
	9198:  "Samsung TV Remote control interface (SSL)",
	8889:  "Samsung TV Media port",
	55000: "Samsung TV Remote Control port",
}

func (s *PortScanner) getPortDescription(port int, deviceType string) string {
	if strings.Contains(strings.ToLower(deviceType), "samsung") &&
		strings.Contains(strings.ToLower(deviceType), "tv") {
		if desc, ok := samsungTVPorts[port]; ok {
			return desc
		}
	}

	if desc, ok := portDescriptions[port]; ok {
		return desc
	}

	return "Unknown service"
}
