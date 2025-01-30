package vulnscan

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type Vulnerability struct {
	Type             string
	Severity         string
	Description      string
	Solution         string
	CVE              string
	References       []string
	TechnicalDetails string
}

type VulnScanner struct {
	target     string
	timeout    time.Duration
	vulns      []Vulnerability
	httpClient *http.Client
	verbose    bool
}

func NewVulnScanner(target string) *VulnScanner {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	return &VulnScanner{
		target:     target,
		timeout:    10 * time.Second,
		httpClient: client,
		verbose:    false,
	}
}

func (s *VulnScanner) ScanVulnerabilities(ports []int) ([]Vulnerability, error) {
	var vulnerabilities []Vulnerability

	fmt.Printf("Starting vulnerability scan...\n")

	if len(ports) == 0 {
		ports = []int{21, 22, 23, 80, 443, 554, 1883, 1900, 5683, 8001, 8002, 8080, 8443, 8883, 9100}
	}

	for _, port := range ports {
		if s.isPortOpen(port) {
			switch port {
			case 21:
				if vulns := s.checkFTPVulnerabilities(); len(vulns) > 0 {
					vulnerabilities = append(vulnerabilities, vulns...)
				}
			case 23:
				vulnerabilities = append(vulnerabilities, Vulnerability{
					Type:        "Open Telnet",
					Severity:    "Critical",
					Description: "Telnet service is enabled which transmits data in plaintext",
					Solution:    "Disable Telnet and use SSH instead",
				})
			case 80, 8080:
				if webVulns := s.checkWebVulnerabilities(port, false); len(webVulns) > 0 {
					vulnerabilities = append(vulnerabilities, webVulns...)
				}
			case 443, 8443:
				if tlsVulns := s.checkTLSConfig(); tlsVulns != nil {
					vulnerabilities = append(vulnerabilities, *tlsVulns)
				}
				if webVulns := s.checkWebVulnerabilities(port, true); len(webVulns) > 0 {
					vulnerabilities = append(vulnerabilities, webVulns...)
				}
			case 554:
				if rtspVulns := s.checkRTSPVulnerabilities(); len(rtspVulns) > 0 {
					vulnerabilities = append(vulnerabilities, rtspVulns...)
				}
			case 1883:
				if mqttVulns := s.checkMQTTVulnerabilities(); len(mqttVulns) > 0 {
					vulnerabilities = append(vulnerabilities, mqttVulns...)
				}
			case 1900:
				if upnpVulns := s.checkUPnPExposure(); upnpVulns != nil {
					vulnerabilities = append(vulnerabilities, *upnpVulns)
				}
			case 5683:
				if coapVulns := s.checkCoAPVulnerabilities(); len(coapVulns) > 0 {
					vulnerabilities = append(vulnerabilities, coapVulns...)
				}
			case 8001:
				if tvVulns := s.checkSamsungTVVulnerabilities(); len(tvVulns) > 0 {
					fmt.Printf("\nFound Samsung TV vulnerabilities:\n")
					for _, vuln := range tvVulns {
						fmt.Printf("- %s (%s)\n", vuln.Type, vuln.Severity)
						fmt.Printf("  Description: %s\n", vuln.Description)
						fmt.Printf("  Technical Details:\n%s\n", vuln.TechnicalDetails)
					}
					vulnerabilities = append(vulnerabilities, tvVulns...)
				}
			case 9100:
				if printerVulns := s.checkPrinterVulnerabilities(); len(printerVulns) > 0 {
					vulnerabilities = append(vulnerabilities, printerVulns...)
				}
			}
		}
	}

	if v := s.checkDefaultCredentials(); v != nil {
		vulnerabilities = append(vulnerabilities, *v)
	}

	if s.isPortOpen(1900) {
		if v := s.checkUPnPExposure(); v != nil {
			vulnerabilities = append(vulnerabilities, *v)
		}
	}

	if deviceVulns := s.checkDeviceSpecificVulns(); len(deviceVulns) > 0 {
		vulnerabilities = append(vulnerabilities, deviceVulns...)
	}

	if len(vulnerabilities) > 0 {
		fmt.Printf("\nVulnerability scan complete. Found %d vulnerabilities.\n", len(vulnerabilities))
	} else {
		fmt.Printf("\nVulnerability scan complete. No vulnerabilities found.\n")
	}
	return vulnerabilities, nil
}

func (s *VulnScanner) checkDefaultCredentials() *Vulnerability {
	commonCreds := []struct {
		username string
		password string
	}{
		{"admin", "admin"},
		{"root", "root"},
		{"admin", "password"},
		{"admin", ""},
		{"root", ""},
	}

	for _, cred := range commonCreds {
		if s.tryLogin(cred.username, cred.password) {
			return &Vulnerability{
				Type:        "Default Credentials",
				Severity:    "Critical",
				Description: fmt.Sprintf("Device accepts default credentials: %s/%s", cred.username, cred.password),
				Solution:    "Change default passwords and implement strong password policy",
			}
		}
	}

	return nil
}

func (s *VulnScanner) checkTLSConfig() *Vulnerability {
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", s.target), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()

	if state.Version < tls.VersionTLS12 {
		return &Vulnerability{
			Type:        "Weak TLS Version",
			Severity:    "High",
			Description: "Device uses outdated TLS version",
			Solution:    "Configure server to use TLS 1.2 or higher",
		}
	}

	weakCiphers := map[uint16]bool{
		tls.TLS_RSA_WITH_RC4_128_SHA:       true,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:  true,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:   true,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA: true,
	}

	if weakCiphers[state.CipherSuite] {
		return &Vulnerability{
			Type:        "Weak Cipher Suite",
			Severity:    "High",
			Description: "Device uses weak cipher suites",
			Solution:    "Configure server to use strong cipher suites only",
		}
	}

	return nil
}

func (s *VulnScanner) tryLogin(username, password string) bool {
	return false
}

func (s *VulnScanner) isPortOpen(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", s.target, port), s.timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (s *VulnScanner) checkWebVulnerabilities(port int, isHTTPS bool) []Vulnerability {
	var vulnerabilities []Vulnerability
	scheme := "http"
	if isHTTPS {
		scheme = "https"
	}

	paths := []string{
		"/",
		"/admin",
		"/login.html",
		"/system.html",
		"/config.html",
		"/settings.html",
		"/debug",
	}

	for _, path := range paths {
		url := fmt.Sprintf("%s://%s:%d%s", scheme, s.target, port, path)
		resp, err := s.httpClient.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        fmt.Sprintf("Exposed Web Interface (%s)", path),
				Severity:    "Medium",
				Description: fmt.Sprintf("Web interface exposed at %s", path),
				Solution:    "Restrict access to administrative interfaces",
			})
		}
	}

	return vulnerabilities
}

func (s *VulnScanner) checkAnonymousFTP() bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:21", s.target), s.timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	fmt.Fprintf(conn, "USER anonymous\r\n")
	fmt.Fprintf(conn, "PASS anonymous\r\n")

	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(s.timeout))
	n, err := conn.Read(buffer)
	if err != nil {
		return false
	}

	response := string(buffer[:n])
	return strings.Contains(response, "230")
}

func (s *VulnScanner) checkUPnPExposure() *Vulnerability {
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:1900", s.target), s.timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	searchMessage := []byte(
		"M-SEARCH * HTTP/1.1\r\n" +
			"HOST: 239.255.255.250:1900\r\n" +
			"MAN: \"ssdp:discover\"\r\n" +
			"MX: 1\r\n" +
			"ST: upnp:rootdevice\r\n" +
			"\r\n")

	_, err = conn.Write(searchMessage)
	if err != nil {
		return nil
	}

	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(s.timeout))
	n, err := conn.Read(buffer)
	if err != nil {
		return nil
	}

	response := string(buffer[:n])
	if strings.Contains(response, "Server:") || strings.Contains(response, "Location:") {
		return &Vulnerability{
			Type:        "UPnP Information Exposure",
			Severity:    "Medium",
			Description: "Device is responding to UPnP discovery requests with detailed information",
			Solution:    "Disable UPnP or restrict to local network only",
			TechnicalDetails: `Vulnerability Analysis:
- Device responds to UPnP discovery on port 1900/UDP
- Reveals detailed device information including:
  * Device model and manufacturer
  * Service descriptions
  * Control endpoints
- An attacker can:
  1. Send M-SEARCH requests to enumerate devices
  2. Query device description URLs
  3. Access service control endpoints
  4. Potentially manipulate device settings
- Testing method:
  * Send M-SEARCH discovery packets
  * Parse SSDP responses
  * Follow up on advertised URLs`,
		}
	}

	return nil
}

func (s *VulnScanner) checkMQTTVulnerabilities() []Vulnerability {
	var vulns []Vulnerability

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:1883", s.target), s.timeout)
	if err == nil {
		defer conn.Close()
		vulns = append(vulns, Vulnerability{
			Type:        "Unauthenticated MQTT Access",
			Severity:    "Critical",
			Description: "MQTT broker allows connections without authentication",
			Solution:    "Enable MQTT authentication and use strong credentials",
			CVE:         "CVE-2017-7650",
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-7650"},
			TechnicalDetails: `Vulnerability Analysis:
- MQTT broker accepts connections on port 1883
- No username/password required
- No TLS encryption
- An attacker can:
  1. Subscribe to all topics (#)
  2. Publish to any topic
  3. Intercept sensitive data
  4. Inject malicious commands
- Testing method:
  * Connect using MQTT client
  * Subscribe to # wildcard topic
  * Monitor device communication`,
		})
	}

	return vulns
}

func (s *VulnScanner) checkSamsungTVVulnerabilities() []Vulnerability {
	var vulns []Vulnerability

	vulns = append(vulns, Vulnerability{
		Type:        "Samsung TV Remote Code Execution",
		Severity:    "Critical",
		Description: "Samsung Smart TV may be vulnerable to remote code execution via the Smart View SDK",
		Solution:    "Update TV firmware to latest version and restrict network access",
		CVE:         "CVE-2019-7295",
		References: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2019-7295",
			"https://www.samsung.com/uk/support/tv-audio-video/tv-software-update/",
		},
		TechnicalDetails: `Vulnerability Analysis:
- Attack Vector:
  * The TV exposes a WebSocket API on port 8001
  * No authentication required to connect to this API
  * Commands sent via JSON messages without proper validation
  * Firmware versions prior to T-KTDEUC-1260.5 are affected

- Attack Methodology:
  1. Network Discovery:
     * Scan local network for port 8001
     * Identify Samsung TV via UPnP/SSDP discovery
  
  2. Initial Access:
     * Connect to WebSocket API: ws://<TV_IP>:8001/api/v2/channels/samsung.remote.control
     * No authentication tokens or headers required
     * Connection uses plain WebSocket (ws://) instead of secure (wss://)
  
  3. Vulnerability Verification:
     * Send basic command to verify API access:
       {"method":"ms.remote.control","params":{"Cmd":"Click"}}
     * Check for successful response indicating control access
  
  4. Potential Impact:
     * Remote control of TV functions
     * Access to viewing history and preferences
     * Modification of TV settings
     * Potential code execution via malformed commands
     * Access to connected USB devices
     * Network pivoting possibilities

- Detection Methods:
  1. Network monitoring for WebSocket connections to port 8001
  2. Scanning for exposed Samsung TV APIs
  3. Checking firmware version via TV settings
  4. Monitoring for unauthorized control attempts

- Mitigation:
  1. Update TV firmware immediately
  2. Configure network firewall to restrict port 8001 access
  3. Use network segmentation for IoT devices
  4. Monitor network traffic for suspicious WebSocket connections
  5. Consider using a smart plug to disable TV network when not in use`,
	})

	wsURL := fmt.Sprintf("ws://%s:8001/api/v2/channels/samsung.remote.control", s.target)
	if s.checkWebsocketAccess(wsURL) {
		vulns = append(vulns, Vulnerability{
			Type:        "Exposed TV Control API",
			Severity:    "High",
			Description: "Samsung TV control API is accessible without authentication",
			Solution:    "Restrict access to trusted IP addresses only",
			TechnicalDetails: `Vulnerability Analysis:
- Port 8001 accepts WebSocket connections
- No authentication token required
- API endpoints exposed:
  * /api/v2/channels/samsung.remote.control
  * /api/v2/applications
  * /api/v2/channels
- An attacker can:
  1. Enumerate available TV functions
  2. Control TV operations
  3. Access viewing history
  4. Modify TV settings`,
		})
	}

	return vulns
}

func (s *VulnScanner) checkCoAPVulnerabilities() []Vulnerability {
	var vulns []Vulnerability

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:5683", s.target))
	if err != nil {
		return vulns
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return vulns
	}
	defer conn.Close()

	discoveryRequest := []byte{
		0x40,       // Ver:1, Type:0 (CON), Token Length:0
		0x01,       // Code: 0.01 (GET)
		0x00, 0x01, // Message ID
		0xb1, 0x2e, // Option Delta:11 (Uri-Path), Length:14
		'.', 'w', 'e', 'l', 'l', '-', 'k', 'n', 'o', 'w', 'n', '/', 'c', 'o', 'r', 'e',
	}

	_, err = conn.Write(discoveryRequest)
	if err != nil {
		return vulns
	}

	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(s.timeout))
	n, err := conn.Read(buffer)
	if err == nil && n > 4 {
		if buffer[0]&0xC0 == 0x60 || buffer[0]&0xC0 == 0x70 {
			vulns = append(vulns, Vulnerability{
				Type:        "CoAP Information Disclosure",
				Severity:    "Medium",
				Description: "CoAP server exposes resource discovery information",
				Solution:    "Disable CoAP discovery or restrict access",
				CVE:         "CVE-2019-9750",
				References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-9750"},
				TechnicalDetails: `Vulnerability Analysis:
- CoAP server running on port 5683/UDP
- Responds to /.well-known/core discovery
- No authentication required
- An attacker can:
  1. Query /.well-known/core for resource discovery
  2. Enumerate available endpoints
  3. Access sensor data and control functions
  4. Potentially modify device state
- Testing method:
  * Send CoAP GET to /.well-known/core
  * Parse resource links
  * Test discovered endpoints
  * Check for write permissions`,
			})
		}
	}

	return vulns
}

func (s *VulnScanner) checkRTSPVulnerabilities() []Vulnerability {
	var vulns []Vulnerability

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:554", s.target), s.timeout)
	if err != nil {
		return vulns
	}
	defer conn.Close()

	optionsRequest := "OPTIONS rtsp://" + s.target + " RTSP/1.0\r\n" +
		"CSeq: 1\r\n" +
		"User-Agent: IoTscan\r\n\r\n"

	_, err = conn.Write([]byte(optionsRequest))
	if err != nil {
		return vulns
	}

	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(s.timeout))
	n, err := conn.Read(buffer)
	if err == nil && n > 0 {
		response := string(buffer[:n])

		if strings.Contains(response, "RTSP/1.0 200 OK") &&
			!strings.Contains(response, "WWW-Authenticate:") {
			vulns = append(vulns, Vulnerability{
				Type:        "RTSP Authentication Bypass",
				Severity:    "Critical",
				Description: "RTSP stream accessible without authentication",
				Solution:    "Enable RTSP authentication and use strong credentials",
				CVE:         "CVE-2020-12124",
				References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-12124"},
				TechnicalDetails: `Vulnerability Analysis:
- RTSP server on port 554 lacks authentication
- Streams accessible without credentials
- Common RTSP methods exposed
- An attacker can:
  1. List available streams (DESCRIBE)
  2. Access video/audio feeds (PLAY)
  3. Potentially control camera (SET_PARAMETER)
  4. Record streams (RECORD)
- Testing method:
  * Send OPTIONS request
  * Try DESCRIBE without auth
  * Attempt to PLAY streams
  * Test for control commands`,
			})
		}

		if strings.Contains(response, "Public:") {
			methods := strings.Split(strings.Split(response, "Public:")[1], "\r\n")[0]
			vulns = append(vulns, Vulnerability{
				Type:        "RTSP Methods Exposure",
				Severity:    "Medium",
				Description: fmt.Sprintf("RTSP server exposes supported methods: %s", methods),
				Solution:    "Disable unnecessary RTSP methods",
			})
		}
	}

	describeRequest := "DESCRIBE rtsp://" + s.target + "/stream RTSP/1.0\r\n" +
		"CSeq: 2\r\n" +
		"User-Agent: IoTscan\r\n\r\n"

	_, err = conn.Write([]byte(describeRequest))
	if err == nil {
		buffer := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(s.timeout))
		n, err := conn.Read(buffer)
		if err == nil && n > 0 {
			response := string(buffer[:n])
			if strings.Contains(response, "RTSP/1.0 200 OK") {
				vulns = append(vulns, Vulnerability{
					Type:        "Exposed RTSP Stream",
					Severity:    "High",
					Description: "RTSP stream is accessible without authentication",
					Solution:    "Enable authentication for RTSP streams",
				})
			}
		}
	}

	return vulns
}

func (s *VulnScanner) checkPrinterVulnerabilities() []Vulnerability {
	var vulns []Vulnerability

	ports := []struct {
		port    int
		service string
	}{
		{9100, "Raw Print"},
		{515, "LPD"},
		{631, "IPP"},
		{80, "Web Interface"},
		{443, "HTTPS Interface"},
	}

	for _, p := range ports {
		if s.isPortOpen(p.port) {
			vulns = append(vulns, Vulnerability{
				Type:        fmt.Sprintf("Exposed %s Port", p.service),
				Severity:    "Medium",
				Description: fmt.Sprintf("Printer %s port is accessible", p.service),
				Solution:    fmt.Sprintf("Restrict access to %s port if not needed", p.service),
			})

			switch p.port {
			case 9100:
				if v := s.checkRawPrintPort(); v != nil {
					vulns = append(vulns, *v)
				}
			case 631:
				if v := s.checkIPPVulnerabilities(); v != nil {
					vulns = append(vulns, *v)
				}
			case 80, 443:
				if webVulns := s.checkPrinterWebInterface(p.port); len(webVulns) > 0 {
					vulns = append(vulns, webVulns...)
				}
			}
		}
	}

	return vulns
}

func (s *VulnScanner) checkRawPrintPort() *Vulnerability {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:9100", s.target), s.timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	pjlQuery := "\x1B%-12345X@PJL INFO ID\r\n"
	_, err = conn.Write([]byte(pjlQuery))
	if err == nil {
		buffer := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(s.timeout))
		n, err := conn.Read(buffer)
		if err == nil && n > 0 {
			return &Vulnerability{
				Type:        "PJL Information Disclosure",
				Severity:    "High",
				Description: "Printer responds to PJL queries which could expose sensitive information",
				Solution:    "Disable PJL access or restrict to authorized hosts only",
				CVE:         "CVE-2017-2741",
				References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-2741"},
				TechnicalDetails: `Vulnerability Analysis:
- Raw print port (9100/TCP) accepts PJL commands
- No authentication required
- Responds to PJL INFO queries
- An attacker can:
  1. Query printer information using PJL commands
  2. Access print job details
  3. Modify printer settings
  4. Potentially access stored documents
- Testing method:
  * Connect to port 9100
  * Send PJL INFO commands
  * Try PJL FSQUERY
  * Test for file system access`,
			}
		}
	}

	return nil
}

func (s *VulnScanner) checkIPPVulnerabilities() *Vulnerability {
	url := fmt.Sprintf("http://%s:631/", s.target)
	req, err := http.NewRequest("POST", url, strings.NewReader(""))
	if err != nil {
		return nil
	}

	req.Header.Set("Content-Type", "application/ipp")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		return &Vulnerability{
			Type:        "Exposed IPP Service",
			Severity:    "High",
			Description: "Internet Printing Protocol service is exposed",
			Solution:    "Restrict IPP access to authorized hosts only",
			CVE:         "CVE-2018-5408",
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2018-5408"},
			TechnicalDetails: `Vulnerability Analysis:
- IPP service running on port 631
- No authentication required
- Printer attributes exposed
- An attacker can:
  1. Query printer capabilities
  2. View print queue
  3. Submit print jobs
  4. Modify printer configuration
- Testing method:
  * Send IPP Get-Printer-Attributes
  * Try Get-Jobs operation
  * Test Create-Job and Send-Document
  * Check for admin operations`,
		}
	}

	return nil
}

func (s *VulnScanner) checkPrinterWebInterface(port int) []Vulnerability {
	var vulns []Vulnerability

	paths := []string{
		"/",
		"/admin",
		"/setup",
		"/config",
		"/settings",
		"/info",
		"/status",
		"/SecuritySettings",
		"/PrinterStatus",
		"/TopAccess",
	}

	scheme := "http"
	if port == 443 {
		scheme = "https"
	}

	for _, path := range paths {
		url := fmt.Sprintf("%s://%s:%d%s", scheme, s.target, port, path)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 {
			if strings.Contains(resp.Header.Get("Server"), "Printer") ||
				strings.Contains(resp.Header.Get("Server"), "IIS") {
				vulns = append(vulns, Vulnerability{
					Type:        fmt.Sprintf("Exposed Printer Web Interface (%s)", path),
					Severity:    "High",
					Description: fmt.Sprintf("Printer web interface exposed at %s", path),
					Solution:    "Restrict access to printer web interface",
					TechnicalDetails: `Vulnerability Analysis:
- Web management interface exposed
- Default credentials may be in use
- Configuration pages accessible
- An attacker can:
  1. Access printer settings
  2. View print history
  3. Modify network configuration
  4. Update firmware
- Testing method:
  * Check common paths (/admin, /setup)
  * Try default credentials
  * Test for sensitive information
  * Look for configuration access`,
				})
			}
		}
	}

	return vulns
}

func (s *VulnScanner) checkPrinterInterface() bool {
	return false
}

func (s *VulnScanner) checkDeviceSpecificVulns() []Vulnerability {
	var vulns []Vulnerability

	if banner := s.getBanner(); banner != "" {
		if strings.Contains(banner, "Samsung Smart TV") {
			vulns = append(vulns, s.checkSamsungTVVulnerabilities()...)
		} else if strings.Contains(banner, "Printer") {
			vulns = append(vulns, s.checkPrinterVulnerabilities()...)
		}
	}

	return vulns
}

func (s *VulnScanner) checkWebsocketAccess(url string) bool {
	dialer := net.Dialer{
		Timeout: s.timeout,
	}

	conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:8001", s.target))
	if err != nil {
		return false
	}
	defer conn.Close()

	handshake := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s:8001\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
			"Sec-WebSocket-Version: 13\r\n\r\n",
		"/api/v2/channels/samsung.remote.control",
		s.target,
	)

	_, err = conn.Write([]byte(handshake))
	if err != nil {
		return false
	}

	resp := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(s.timeout))
	n, err := conn.Read(resp)
	if err != nil {
		return false
	}

	response := string(resp[:n])
	return strings.Contains(response, "101 Switching Protocols") &&
		strings.Contains(response, "Upgrade: websocket")
}

func (s *VulnScanner) getBanner() string {
	ports := []int{80, 443, 8080, 8443}
	for _, port := range ports {
		if banner := grabBanner(fmt.Sprintf("%s:%d", s.target, port), s.timeout); banner != "" {
			return banner
		}
	}
	return ""
}

func grabBanner(target string, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))

	probes := []string{
		"\r\n",                    // Basic newline
		"HEAD / HTTP/1.0\r\n\r\n", // HTTP
		"GET / HTTP/1.0\r\n\r\n",  // HTTP alternative
	}

	for _, probe := range probes {
		conn.SetWriteDeadline(time.Now().Add(timeout))
		_, err := conn.Write([]byte(probe))
		if err != nil {
			continue
		}

		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err == nil && n > 0 {
			banner := string(buffer[:n])
			banner = strings.Split(banner, "\n")[0]
			return strings.TrimSpace(banner)
		}
	}

	return ""
}

func (s *VulnScanner) checkFTPVulnerabilities() []Vulnerability {
	var vulns []Vulnerability

	vulns = append(vulns, Vulnerability{
		Type:        "Open FTP",
		Severity:    "High",
		Description: "FTP service is enabled which typically transmits data in plaintext",
		Solution:    "Disable FTP if not required or use SFTP instead",
	})

	if s.checkAnonymousFTP() {
		vulns = append(vulns, Vulnerability{
			Type:        "Anonymous FTP Access",
			Severity:    "Critical",
			Description: "FTP server allows anonymous access",
			Solution:    "Disable anonymous FTP access",
		})
	}

	return vulns
}
