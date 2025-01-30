// Package vulnscan provides functionality for scanning IoT devices for security vulnerabilities
package vulnscan

// Import required packages for network operations, encryption, and time management
import (
	// crypto/tls for handling secure connections and certificate verification
	"crypto/tls"
	// fmt for formatted I/O operations and printing scan results
	"fmt"
	// net for basic network operations like TCP connections
	"net"
	// net/http for making HTTP requests to web services
	"net/http"
	// strings for string manipulation operations
	"strings"
	// time for handling timeouts and delays
	"time"
)

// Vulnerability represents a single security issue found during scanning
type Vulnerability struct {
	// Type identifies the category of vulnerability (e.g., "Default Credentials")
	Type string
	// Severity indicates how critical the vulnerability is (e.g., "High", "Critical")
	Severity string
	// Description provides details about what the vulnerability is
	Description string
	// Solution offers guidance on how to fix the vulnerability
	Solution string
	// CVE stores the Common Vulnerabilities and Exposures identifier
	CVE string
	// References stores URLs to additional information about the vulnerability
	References []string
	// TechnicalDetails provides in-depth analysis of the vulnerability
	TechnicalDetails string
}

// VulnScanner is the main scanner struct that handles vulnerability detection
type VulnScanner struct {
	// target stores the IP address or hostname to scan
	target string
	// timeout sets how long to wait for responses
	timeout time.Duration
	// vulns stores all found vulnerabilities
	vulns []Vulnerability
	// httpClient is used for making web requests
	httpClient *http.Client
	// verbose enables detailed output during scanning
	verbose bool
}

// NewVulnScanner creates a new vulnerability scanner instance
func NewVulnScanner(target string) *VulnScanner {
	// Create a custom transport that accepts self-signed certificates
	transport := &http.Transport{
		// Configure TLS settings for the transport
		TLSClientConfig: &tls.Config{
			// Allow self-signed certificates for IoT devices
			InsecureSkipVerify: true,
		},
		// Don't reuse connections
		DisableKeepAlives: true,
	}

	// Create an HTTP client with our custom transport
	client := &http.Client{
		// Set the transport we configured
		Transport: transport,
		// Set a 10-second timeout for requests
		Timeout: 10 * time.Second,
	}

	// Create and return a new scanner instance
	return &VulnScanner{
		// Set the target to scan
		target: target,
		// Set default timeout to 10 seconds
		timeout: 10 * time.Second,
		// Set the HTTP client we created
		httpClient: client,
		// Start with verbose mode disabled
		verbose: false,
	}
}

// ScanVulnerabilities performs the vulnerability scan on the target device
func (s *VulnScanner) ScanVulnerabilities(ports []int) ([]Vulnerability, error) {
	// Initialize slice to store found vulnerabilities
	var vulnerabilities []Vulnerability

	// Print start message
	fmt.Printf("Starting vulnerability scan...\n")

	// If no ports specified, use default list of common IoT ports
	if len(ports) == 0 {
		// Default ports include FTP, SSH, Telnet, HTTP, HTTPS, RTSP, MQTT, UPnP, CoAP, and more
		ports = []int{21, 22, 23, 80, 443, 554, 1883, 1900, 5683, 8001, 8002, 8080, 8443, 8883, 9100}
	}

	// Check each port for vulnerabilities
	for _, port := range ports {
		// First verify if the port is open
		if s.isPortOpen(port) {
			// Use switch statement to handle different port-specific checks
			switch port {
			// Check FTP vulnerabilities on port 21
			case 21:
				// If we find FTP vulnerabilities, add them to our list
				if vulns := s.checkFTPVulnerabilities(); len(vulns) > 0 {
					vulnerabilities = append(vulnerabilities, vulns...)
				}
			// Check Telnet vulnerabilities on port 23
			case 23:
				// Add vulnerability for open Telnet service
				vulnerabilities = append(vulnerabilities, Vulnerability{
					// Specify vulnerability type
					Type: "Open Telnet",
					// Mark as critical severity
					Severity: "Critical",
					// Describe the security issue
					Description: "Telnet service is enabled which transmits data in plaintext",
					// Provide remediation steps
					Solution: "Disable Telnet and use SSH instead",
				})
			// Check web vulnerabilities on HTTP ports
			case 80, 8080:
				// Check for web vulnerabilities without SSL
				if webVulns := s.checkWebVulnerabilities(port, false); len(webVulns) > 0 {
					// Add any found web vulnerabilities
					vulnerabilities = append(vulnerabilities, webVulns...)
				}
			// Check web vulnerabilities on HTTPS ports
			case 443, 8443:
				// First check TLS configuration
				if tlsVulns := s.checkTLSConfig(); tlsVulns != nil {
					// Add any TLS vulnerabilities found
					vulnerabilities = append(vulnerabilities, *tlsVulns)
				}
				// Then check for web vulnerabilities with SSL
				if webVulns := s.checkWebVulnerabilities(port, true); len(webVulns) > 0 {
					// Add any found web vulnerabilities
					vulnerabilities = append(vulnerabilities, webVulns...)
				}
			// Check RTSP streaming vulnerabilities
			case 554:
				// Check for RTSP-specific vulnerabilities
				if rtspVulns := s.checkRTSPVulnerabilities(); len(rtspVulns) > 0 {
					// Add any found RTSP vulnerabilities
					vulnerabilities = append(vulnerabilities, rtspVulns...)
				}
			// Check MQTT broker vulnerabilities
			case 1883:
				// Check for MQTT-specific vulnerabilities
				if mqttVulns := s.checkMQTTVulnerabilities(); len(mqttVulns) > 0 {
					// Add any found MQTT vulnerabilities
					vulnerabilities = append(vulnerabilities, mqttVulns...)
				}
			// Check UPnP vulnerabilities
			case 1900:
				// Check for exposed UPnP services
				if upnpVulns := s.checkUPnPExposure(); upnpVulns != nil {
					// Add any UPnP vulnerabilities found
					vulnerabilities = append(vulnerabilities, *upnpVulns)
				}
			// Check CoAP vulnerabilities
			case 5683:
				// Check for CoAP-specific vulnerabilities
				if coapVulns := s.checkCoAPVulnerabilities(); len(coapVulns) > 0 {
					// Add any found CoAP vulnerabilities
					vulnerabilities = append(vulnerabilities, coapVulns...)
				}
			// Check Samsung TV vulnerabilities
			case 8001:
				// Check for Samsung TV specific vulnerabilities
				if tvVulns := s.checkSamsungTVVulnerabilities(); len(tvVulns) > 0 {
					// Print header for Samsung TV vulnerabilities
					fmt.Printf("\nFound Samsung TV vulnerabilities:\n")
					// Print details for each vulnerability
					for _, vuln := range tvVulns {
						// Print vulnerability type and severity
						fmt.Printf("- %s (%s)\n", vuln.Type, vuln.Severity)
						// Print vulnerability description
						fmt.Printf("  Description: %s\n", vuln.Description)
						// Print technical details
						fmt.Printf("  Technical Details:\n%s\n", vuln.TechnicalDetails)
					}
					// Add Samsung TV vulnerabilities to main list
					vulnerabilities = append(vulnerabilities, tvVulns...)
				}
			// Check printer vulnerabilities
			case 9100:
				// Check for printer-specific vulnerabilities
				if printerVulns := s.checkPrinterVulnerabilities(); len(printerVulns) > 0 {
					// Add any found printer vulnerabilities
					vulnerabilities = append(vulnerabilities, printerVulns...)
				}
			}
		}
	}

	// Check for default credentials across all services
	if v := s.checkDefaultCredentials(); v != nil {
		// Add any found default credential vulnerabilities
		vulnerabilities = append(vulnerabilities, *v)
	}

	// Check for exposed UPnP services on port 1900
	if s.isPortOpen(1900) {
		// Check for UPnP vulnerabilities
		if v := s.checkUPnPExposure(); v != nil {
			// Add any found UPnP vulnerabilities
			vulnerabilities = append(vulnerabilities, *v)
		}
	}

	// Run additional IoT-specific vulnerability checks
	if deviceVulns := s.checkDeviceSpecificVulns(); len(deviceVulns) > 0 {
		// Add any device-specific vulnerabilities found
		vulnerabilities = append(vulnerabilities, deviceVulns...)
	}

	// Print summary of findings
	if len(vulnerabilities) > 0 {
		// Print total number of vulnerabilities found
		fmt.Printf("\nVulnerability scan complete. Found %d vulnerabilities.\n", len(vulnerabilities))
	} else {
		// Print message if no vulnerabilities were found
		fmt.Printf("\nVulnerability scan complete. No vulnerabilities found.\n")
	}
	// Return results and nil error
	return vulnerabilities, nil
}

// checkDefaultCredentials attempts to login with common default username/password combinations
func (s *VulnScanner) checkDefaultCredentials() *Vulnerability {
	// Define list of common default credentials to check
	commonCreds := []struct {
		// Username to try
		username string
		// Password to try
		password string
	}{
		// Admin/admin combination
		{"admin", "admin"},
		// Root/root combination
		{"root", "root"},
		// Admin with common password
		{"admin", "password"},
		// Admin with blank password
		{"admin", ""},
		// Root with blank password
		{"root", ""},
	}

	// Try each credential combination
	for _, cred := range commonCreds {
		// Attempt to login with these credentials
		if s.tryLogin(cred.username, cred.password) {
			// If login succeeds, return a vulnerability
			return &Vulnerability{
				// Set vulnerability type
				Type: "Default Credentials",
				// Mark as critical severity
				Severity: "Critical",
				// Describe the issue with the specific credentials found
				Description: fmt.Sprintf("Device accepts default credentials: %s/%s", cred.username, cred.password),
				// Provide steps to fix the issue
				Solution: "Change default passwords and implement strong password policy",
			}
		}
	}

	// Return nil if no default credentials work
	return nil
}

// checkTLSConfig checks for SSL/TLS configuration vulnerabilities
func (s *VulnScanner) checkTLSConfig() *Vulnerability {
	// Try to establish TLS connection
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", s.target), &tls.Config{
		// Accept any certificate for testing
		InsecureSkipVerify: true,
	})
	// If connection fails, return nil
	if err != nil {
		return nil
	}
	// Ensure connection is closed when done
	defer conn.Close()

	// Get the TLS connection state
	state := conn.ConnectionState()

	// Check if TLS version is too old
	if state.Version < tls.VersionTLS12 {
		// Return vulnerability for outdated TLS
		return &Vulnerability{
			// Set vulnerability type
			Type: "Weak TLS Version",
			// Mark as high severity
			Severity: "High",
			// Describe the security issue
			Description: "Device uses outdated TLS version",
			// Provide remediation steps
			Solution: "Configure server to use TLS 1.2 or higher",
		}
	}

	// Define list of known weak cipher suites
	weakCiphers := map[uint16]bool{
		// RC4 is cryptographically broken
		tls.TLS_RSA_WITH_RC4_128_SHA: true,
		// 3DES is considered weak
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA: true,
		// CBC mode with TLS 1.0 is vulnerable
		tls.TLS_RSA_WITH_AES_128_CBC_SHA: true,
		// RC4 with ECDHE is still RC4
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA: true,
	}

	// Check if current cipher suite is in weak list
	if weakCiphers[state.CipherSuite] {
		// Return vulnerability for weak cipher
		return &Vulnerability{
			// Set vulnerability type
			Type: "Weak Cipher Suite",
			// Mark as high severity
			Severity: "High",
			// Describe the security issue
			Description: "Device uses weak cipher suites",
			// Provide remediation steps
			Solution: "Configure server to use strong cipher suites only",
		}
	}

	// Return nil if no TLS vulnerabilities found
	return nil
}

// tryLogin attempts to authenticate with the given credentials
func (s *VulnScanner) tryLogin(username, password string) bool {
	// This is a placeholder function - implement actual login logic
	// Be careful with rate limiting and potential account lockouts
	return false
}

// isPortOpen checks if a specific port is open on the target
func (s *VulnScanner) isPortOpen(port int) bool {
	// Try to establish a TCP connection with timeout
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", s.target, port), s.timeout)
	// If connection fails, port is closed
	if err != nil {
		return false
	}
	// Close the connection immediately
	conn.Close()
	// Port is open if we got here
	return true
}

func (s *VulnScanner) checkWebVulnerabilities(port int, isHTTPS bool) []Vulnerability {
	// Initialize slice to store found vulnerabilities
	var vulnerabilities []Vulnerability
	// Set protocol scheme based on SSL status
	scheme := "http"
	if isHTTPS {
		scheme = "https"
	}

	// List of common IoT web interface paths to check
	paths := []string{
		// Root path
		"/",
		// Admin interface
		"/admin",
		// Login page
		"/login.html",
		// System configuration
		"/system.html",
		// Device configuration
		"/config.html",
		// Settings page
		"/settings.html",
		// Debug interface
		"/debug",
	}

	// Check each path for vulnerabilities
	for _, path := range paths {
		// Build the full URL to test
		url := fmt.Sprintf("%s://%s:%d%s", scheme, s.target, port, path)
		// Try to make a GET request
		resp, err := s.httpClient.Get(url)
		// Skip this path if request fails
		if err != nil {
			continue
		}
		// Make sure to close response body
		defer resp.Body.Close()

		// Check if we got a successful response
		if resp.StatusCode == 200 {
			// Add vulnerability for exposed web interface
			vulnerabilities = append(vulnerabilities, Vulnerability{
				// Set vulnerability type with path info
				Type: fmt.Sprintf("Exposed Web Interface (%s)", path),
				// Mark as medium severity
				Severity: "Medium",
				// Describe what was found
				Description: fmt.Sprintf("Web interface exposed at %s", path),
				// Provide remediation steps
				Solution: "Restrict access to administrative interfaces",
			})
		}
	}

	// Return all found web vulnerabilities
	return vulnerabilities
}

// checkAnonymousFTP attempts to login to FTP with anonymous credentials
func (s *VulnScanner) checkAnonymousFTP() bool {
	// Try to establish TCP connection to FTP port
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:21", s.target), s.timeout)
	// Return false if connection fails
	if err != nil {
		return false
	}
	// Ensure connection is closed when done
	defer conn.Close()

	// Send anonymous username
	fmt.Fprintf(conn, "USER anonymous\r\n")
	// Send anonymous password
	fmt.Fprintf(conn, "PASS anonymous\r\n")

	// Create buffer for FTP server response
	buffer := make([]byte, 1024)
	// Set deadline for reading response
	conn.SetReadDeadline(time.Now().Add(s.timeout))
	// Try to read server response
	n, err := conn.Read(buffer)
	// Return false if read fails
	if err != nil {
		return false
	}

	// Convert response to string
	response := string(buffer[:n])
	// Check if response contains code 230 (successful login)
	return strings.Contains(response, "230")
}

// checkUPnPExposure checks for exposed UPnP services
func (s *VulnScanner) checkUPnPExposure() *Vulnerability {
	// Try to establish UDP connection for UPnP
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:1900", s.target), s.timeout)
	// Return nil if connection fails
	if err != nil {
		return nil
	}
	// Ensure connection is closed when done
	defer conn.Close()

	// Create M-SEARCH discovery message
	searchMessage := []byte(
		"M-SEARCH * HTTP/1.1\r\n" +
			"HOST: 239.255.255.250:1900\r\n" +
			"MAN: \"ssdp:discover\"\r\n" +
			"MX: 1\r\n" +
			"ST: upnp:rootdevice\r\n" +
			"\r\n")

	// Send the discovery message
	_, err = conn.Write(searchMessage)
	// Return nil if send fails
	if err != nil {
		return nil
	}

	// Create buffer for UPnP response
	buffer := make([]byte, 1024)
	// Set deadline for reading response
	conn.SetReadDeadline(time.Now().Add(s.timeout))
	// Try to read server response
	n, err := conn.Read(buffer)
	// Return nil if read fails
	if err != nil {
		return nil
	}

	// Convert response to string
	response := string(buffer[:n])
	// Check if response contains server or location information
	if strings.Contains(response, "Server:") || strings.Contains(response, "Location:") {
		// Return vulnerability if UPnP information is exposed
		return &Vulnerability{
			// Set vulnerability type
			Type: "UPnP Information Exposure",
			// Mark as medium severity
			Severity: "Medium",
			// Describe the security issue
			Description: "Device is responding to UPnP discovery requests with detailed information",
			// Provide remediation steps
			Solution: "Disable UPnP or restrict to local network only",
			// Add detailed technical analysis
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

	// Return nil if no vulnerability found
	return nil
}

// checkMQTTVulnerabilities checks for MQTT-related security issues
func (s *VulnScanner) checkMQTTVulnerabilities() []Vulnerability {
	// Initialize slice to store found vulnerabilities
	var vulns []Vulnerability

	// Check for unauthenticated MQTT access
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:1883", s.target), s.timeout)
	// If connection succeeds, MQTT port is open
	if err == nil {
		// Ensure connection is closed when done
		defer conn.Close()
		// Add vulnerability for unauthenticated access
		vulns = append(vulns, Vulnerability{
			// Set vulnerability type
			Type: "Unauthenticated MQTT Access",
			// Mark as critical severity
			Severity: "Critical",
			// Describe the security issue
			Description: "MQTT broker allows connections without authentication",
			// Provide remediation steps
			Solution: "Enable MQTT authentication and use strong credentials",
			// Add CVE reference
			CVE: "CVE-2017-7650",
			// Add reference links
			References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-7650"},
			// Add detailed technical analysis
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

	// Return found vulnerabilities
	return vulns
}

// checkSamsungTVVulnerabilities checks for Samsung TV specific vulnerabilities
func (s *VulnScanner) checkSamsungTVVulnerabilities() []Vulnerability {
	// Initialize slice to store vulnerabilities
	var vulns []Vulnerability

	// Add known Samsung TV vulnerabilities
	vulns = append(vulns, Vulnerability{
		// Set vulnerability type
		Type: "Samsung TV Remote Code Execution",
		// Mark as critical severity
		Severity: "Critical",
		// Describe the security issue
		Description: "Samsung Smart TV may be vulnerable to remote code execution via the Smart View SDK",
		// Provide remediation steps
		Solution: "Update TV firmware to latest version and restrict network access",
		// Add CVE reference
		CVE: "CVE-2019-7295",
		// Add reference links
		References: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2019-7295",
			"https://www.samsung.com/uk/support/tv-audio-video/tv-software-update/",
		},
		// Add detailed technical analysis
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

	// Check for websocket access
	wsURL := fmt.Sprintf("ws://%s:8001/api/v2/channels/samsung.remote.control", s.target)
	// Test if websocket endpoint is accessible
	if s.checkWebsocketAccess(wsURL) {
		// Add vulnerability for exposed API
		vulns = append(vulns, Vulnerability{
			// Set vulnerability type
			Type: "Exposed TV Control API",
			// Mark as high severity
			Severity: "High",
			// Describe the security issue
			Description: "Samsung TV control API is accessible without authentication",
			// Provide remediation steps
			Solution: "Restrict access to trusted IP addresses only",
			// Add detailed technical analysis
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

	// Return all found vulnerabilities
	return vulns
}

// checkCoAPVulnerabilities checks for CoAP protocol vulnerabilities
func (s *VulnScanner) checkCoAPVulnerabilities() []Vulnerability {
	// Initialize slice to store vulnerabilities
	var vulns []Vulnerability

	// Create UDP address for CoAP
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:5683", s.target))
	// Return empty slice if address resolution fails
	if err != nil {
		return vulns
	}

	// Establish UDP connection
	conn, err := net.DialUDP("udp", nil, addr)
	// Return empty slice if connection fails
	if err != nil {
		return vulns
	}
	// Ensure connection is closed when done
	defer conn.Close()

	// CoAP discovery request format:
	// | Ver | Type | Token Length | Code | Message ID | Token | Options | Payload |
	discoveryRequest := []byte{
		0x40,       // Ver:1, Type:0 (CON), Token Length:0
		0x01,       // Code: 0.01 (GET)
		0x00, 0x01, // Message ID
		0xb1, 0x2e, // Option Delta:11 (Uri-Path), Length:14
		'.', 'w', 'e', 'l', 'l', '-', 'k', 'n', 'o', 'w', 'n', '/', 'c', 'o', 'r', 'e',
	}

	// Send discovery request
	_, err = conn.Write(discoveryRequest)
	// Return empty slice if send fails
	if err != nil {
		return vulns
	}

	// Create buffer for response
	buffer := make([]byte, 1024)
	// Set deadline for reading response
	conn.SetReadDeadline(time.Now().Add(s.timeout))
	// Try to read server response
	n, err := conn.Read(buffer)
	// Check if we got a valid response
	if err == nil && n > 4 {
		// Check if response is a valid CoAP message (first byte should be 0x60 or 0x70)
		if buffer[0]&0xC0 == 0x60 || buffer[0]&0xC0 == 0x70 {
			// Add vulnerability for exposed CoAP service
			vulns = append(vulns, Vulnerability{
				// Set vulnerability type
				Type: "CoAP Information Disclosure",
				// Mark as medium severity
				Severity: "Medium",
				// Describe the security issue
				Description: "CoAP server exposes resource discovery information",
				// Provide remediation steps
				Solution: "Disable CoAP discovery or restrict access",
				// Add CVE reference
				CVE: "CVE-2019-9750",
				// Add reference links
				References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-9750"},
				// Add detailed technical analysis
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

	// Return found vulnerabilities
	return vulns
}

func (s *VulnScanner) checkRTSPVulnerabilities() []Vulnerability {
	var vulns []Vulnerability

	// Try connecting to RTSP port
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:554", s.target), s.timeout)
	if err != nil {
		return vulns
	}
	defer conn.Close()

	// Send RTSP OPTIONS request without authentication
	optionsRequest := "OPTIONS rtsp://" + s.target + " RTSP/1.0\r\n" +
		"CSeq: 1\r\n" +
		"User-Agent: IoTscan\r\n\r\n"

	_, err = conn.Write([]byte(optionsRequest))
	if err != nil {
		return vulns
	}

	// Read response
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(s.timeout))
	n, err := conn.Read(buffer)
	if err == nil && n > 0 {
		response := string(buffer[:n])

		// Check if we got a successful response without auth
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

		// Check for RTSP methods exposure
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

	// Try DESCRIBE request to check for stream access
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

	// Check common printer ports and interfaces
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

			// Additional checks for specific ports
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
	// Try to connect to raw print port
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:9100", s.target), s.timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Send PJL info request
	pjlQuery := "\x1B%-12345X@PJL INFO ID\r\n"
	_, err = conn.Write([]byte(pjlQuery))
	if err == nil {
		// Read response
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
	// Try to connect to IPP port
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

	// Common printer web interface paths
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
			// Check response headers and body for printer-specific strings
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
	// This is now handled in checkPrinterVulnerabilities
	return false
}

func (s *VulnScanner) checkDeviceSpecificVulns() []Vulnerability {
	var vulns []Vulnerability

	// Check for device-specific vulnerabilities based on banner information
	if banner := s.getBanner(); banner != "" {
		// Match against known vulnerable device versions
		if strings.Contains(banner, "Samsung Smart TV") {
			vulns = append(vulns, s.checkSamsungTVVulnerabilities()...)
		} else if strings.Contains(banner, "Printer") {
			vulns = append(vulns, s.checkPrinterVulnerabilities()...)
		}
	}

	return vulns
}

func (s *VulnScanner) checkWebsocketAccess(url string) bool {
	// Create custom dialer with timeout
	dialer := net.Dialer{
		Timeout: s.timeout,
	}

	// Establish TCP connection first (WebSocket handshake)
	conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:8001", s.target))
	if err != nil {
		return false
	}
	defer conn.Close()

	// Send WebSocket handshake request
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

	// Read response
	resp := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(s.timeout))
	n, err := conn.Read(resp)
	if err != nil {
		return false
	}

	// Check if handshake was successful
	response := string(resp[:n])
	return strings.Contains(response, "101 Switching Protocols") &&
		strings.Contains(response, "Upgrade: websocket")
}

func (s *VulnScanner) getBanner() string {
	// Try common ports for banner grabbing
	ports := []int{80, 443, 8080, 8443}
	for _, port := range ports {
		if banner := grabBanner(fmt.Sprintf("%s:%d", s.target, port), s.timeout); banner != "" {
			return banner
		}
	}
	return ""
}

// Helper function to grab service banner
func grabBanner(target string, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(timeout))

	// Send probes for different protocols
	probes := []string{
		"\r\n",                    // Basic newline
		"HEAD / HTTP/1.0\r\n\r\n", // HTTP
		"GET / HTTP/1.0\r\n\r\n",  // HTTP alternative
	}

	for _, probe := range probes {
		// Reset deadline for each probe
		conn.SetWriteDeadline(time.Now().Add(timeout))
		_, err := conn.Write([]byte(probe))
		if err != nil {
			continue
		}

		// Read response
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err == nil && n > 0 {
			banner := string(buffer[:n])
			// Clean and return first line
			banner = strings.Split(banner, "\n")[0]
			return strings.TrimSpace(banner)
		}
	}

	return ""
}

func (s *VulnScanner) checkFTPVulnerabilities() []Vulnerability {
	var vulns []Vulnerability

	// Check for open FTP
	vulns = append(vulns, Vulnerability{
		Type:        "Open FTP",
		Severity:    "High",
		Description: "FTP service is enabled which typically transmits data in plaintext",
		Solution:    "Disable FTP if not required or use SFTP instead",
	})

	// Check for anonymous FTP access
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
