// Package scanner provides functionality for scanning IoT devices on a network
// This is the core package that handles port scanning and service detection
package scanner

// We import several essential Go packages that we'll need for network operations
import (
	// crypto/tls allows us to handle secure HTTPS connections and verify SSL certificates

	// fmt gives us formatted I/O, useful for printing scan results
	"fmt"
	// net provides the core networking capabilities we need for scanning
	"net"
	// http lets us make web requests to detect web services

	// strings helps us manipulate text data from responses
	"strings"
	// time helps us manage timeouts and delays between scans
	"time"
	// http provides HTTP-related functionality
	"net/http"
	// tls provides TLS-related functionality
	"crypto/tls"
)

// PortScanner is our main scanning engine
// It holds all the configuration and state needed for scanning
type PortScanner struct {
	// target stores the IP address or hostname we're scanning
	target string
	// tcpTimeout sets how long we'll wait for TCP connections
	tcpTimeout time.Duration
	// udpTimeout sets how long we'll wait for UDP responses (usually longer than TCP)
	udpTimeout time.Duration
	// portRange stores the list of ports we'll scan
	portRange []int
	// numWorkers determines how many concurrent scans we'll run
	numWorkers int
	// verbose enables detailed output for debugging
	verbose bool
	// maxBannerSize limits how much data we'll read from services
	maxBannerSize int
}

// PortResult stores what we find for each scanned port
type PortResult struct {
	// Port is the port number we scanned
	Port int
	// State tells us if the port is open, closed, or filtered
	State string
	// Service identifies what's running on the port (like HTTP, FTP, etc.)
	Service string
	// DeviceType helps identify the device (printer, camera, etc.)
	DeviceType string
}

// NewPortScanner creates a new scanner with sensible defaults
func NewPortScanner(target string) *PortScanner {
	// Create and return a new scanner configured for the target
	return &PortScanner{
		// Store the IP or hostname we're scanning
		target: target,
		// Set TCP timeout to 3 seconds - enough time for most responses
		tcpTimeout: 3 * time.Second,
		// UDP needs more time, so we set 5 seconds
		udpTimeout: 5 * time.Second,
		// Use single worker to be gentle on the network
		numWorkers: 1,
		// Start with empty port range - we'll set this later
		portRange: []int{},
		// Start with verbose mode off
		verbose: false,
		// Set maximum banner size to 4KB - enough for most services
		maxBannerSize: 4096,
	}
}

// SetPorts configures which ports we'll scan
func (s *PortScanner) SetPorts(ports []int) {
	// Define common IoT device ports we want to check
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

	// Define Samsung TV specific ports
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

	// Create a list for valid ports
	validPorts := make([]int, 0)

	// Helper function to add valid ports
	addPort := func(port int) {
		// Only accept ports in valid range (1-65535)
		if port > 0 && port < 65536 {
			validPorts = append(validPorts, port)
		} else if s.verbose {
			// Warn about invalid ports in verbose mode
			fmt.Printf("Warning: Invalid port number %d ignored\n", port)
		}
	}

	// If no ports specified, use our predefined lists
	if len(ports) == 0 {
		// Add all common IoT ports
		for _, port := range commonIoTPorts {
			addPort(port)
		}
		// Add all Samsung TV ports
		for _, port := range samsungPorts {
			addPort(port)
		}
	} else {
		// Use the specified ports after validation
		for _, port := range ports {
			addPort(port)
		}
	}

	// Remove any duplicate ports and store the final list
	s.portRange = removeDuplicates(validPorts)
}

// Helper function that takes a list of ports and removes any duplicates
func removeDuplicates(ports []int) []int {
	// Create a map to track which ports we've seen
	portsMap := make(map[int]bool)
	// Create an empty slice to store unique ports
	result := []int{}
	// Loop through each port in the input list
	for _, port := range ports {
		// If we haven't seen this port before
		if !portsMap[port] {
			// Mark this port as seen in our map
			portsMap[port] = true
			// Add the port to our result list
			result = append(result, port)
		}
	}
	// Return the list of unique ports
	return result
}

// SetPortRange allows users to specify a range of ports to scan
func (s *PortScanner) SetPortRange(start, end int) {
	// Define all the ports we know about for IoT devices
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

	// Create a map to store valid ports within our range
	validPorts := make(map[int]bool)
	// Check each IoT port to see if it falls within our range
	for _, port := range commonIoTPorts {
		// If the port is within our specified range
		if port >= start && port <= end {
			// Add it to our valid ports map
			validPorts[port] = true
		}
	}

	// Create a slice to hold our final list of ports
	var ports []int
	// Convert our map of valid ports back to a slice
	for port := range validPorts {
		ports = append(ports, port)
	}

	// Store the final port list in our scanner
	s.portRange = ports
}

// SetTimeout allows users to configure how long to wait for responses
func (s *PortScanner) SetTimeout(timeout time.Duration) {
	// Update the TCP timeout value in our scanner
	s.tcpTimeout = timeout
}

// SetVerbose enables or disables detailed output during scanning
func (s *PortScanner) SetVerbose(verbose bool) {
	// Update the verbose flag in our scanner
	s.verbose = verbose
}

// ScanPorts is our main scanning function that checks all configured ports
// It returns a list of results and any errors encountered during scanning
func (s *PortScanner) ScanPorts() ([]PortResult, error) {
	// Initialize an empty slice to store our scan results
	var results []PortResult

	// Print a message to show we're starting the scan
	fmt.Printf("Starting IoT device port scan on %s...\n", s.target)

	// If verbose mode is enabled, show additional information
	if s.verbose {
		// Show how many ports we're going to scan
		fmt.Printf("Scanning %d known IoT ports...\n", len(s.portRange))
		// Show the actual list of ports we'll scan
		fmt.Printf("Port list: %v\n", s.portRange)
	}

	// Loop through each port in our range and scan it
	for _, port := range s.portRange {
		// Scan this specific port and get the result
		if result := s.scanPort(port); result != nil {
			// If we found an open port, add it to our results
			results = append(results, *result)
			// Print information about the open port
			fmt.Printf("\nFound open port %d (%s)\n", port, result.Service)

			// Get and print a description of what this port is typically used for
			desc := s.getPortDescription(port, result.DeviceType)
			// Print the description with proper formatting
			fmt.Printf("  - %s\n", desc)
		}
		// Add a delay between port scans to be network-friendly
		time.Sleep(300 * time.Millisecond)
	}

	// After scanning all ports, check if we found any
	if len(results) == 0 {
		// Print a header for troubleshooting steps
		fmt.Printf("\nNo open ports found. Troubleshooting steps:\n")
		// Step 1: Check if device is powered on
		fmt.Printf("1. Verify the device is powered on and connected to the network\n")
		// Step 2: Suggest trying to ping the device
		fmt.Printf("2. Check if you can ping %s\n", s.target)
		// Step 3: Check firewall settings
		fmt.Printf("3. Verify there are no firewalls blocking access\n")
	} else {
		// Print a summary of our findings
		fmt.Printf("\nPort scan complete. Found %d open ports.\n", len(results))
	}

	// Return our results and nil for error since scan completed successfully
	return results, nil
}

// scanPort attempts to connect to a single port and determine if it's open
// It returns detailed information about the port if it's open, or nil if it's closed
func (s *PortScanner) scanPort(port int) *PortResult {
	// Format the target address with the port number
	target := fmt.Sprintf("%s:%d", s.target, port)

	// Create a dialer with our configured timeout
	dialer := &net.Dialer{
		Timeout: s.tcpTimeout,
	}

	// First try a TCP connection to the port
	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		// If verbose mode is on, show the error
		if s.verbose {
			fmt.Printf("Debug: Port %d error: %v\n", port, err)
		}

		// If TCP failed, try UDP for specific ports that commonly use it
		if port == 1900 || port == 5683 || port == 8001 {
			// Print debug info if verbose mode is on
			if s.verbose {
				fmt.Printf("Debug: Trying UDP on port %d\n", port)
			}

			// Resolve the UDP address
			udpAddr, err := net.ResolveUDPAddr("udp", target)
			// Return nil if we couldn't resolve the UDP address
			if err != nil {
				return nil
			}

			// Create a UDP connection to the target
			udpConn, err := net.DialUDP("udp", nil, udpAddr)
			// Check if we had an error creating the UDP connection
			if err != nil {
				// If verbose mode is enabled, log the UDP connection error
				if s.verbose {
					// Print the detailed error message for debugging
					fmt.Printf("Debug: UDP connection error on port %d: %v\n", port, err)
				}
				// Return nil since we couldn't establish a connection
				return nil
			}
			// Ensure we clean up the UDP connection when we're done
			defer udpConn.Close()

			// Set a deadline for the UDP connection to prevent hanging
			udpConn.SetDeadline(time.Now().Add(s.udpTimeout))

			// Initialize a variable to hold our probe data
			var probe []byte
			// Choose the appropriate probe based on the port number
			switch port {
			// Case for UPnP discovery protocol
			case 1900:
				// Create a standard UPnP discovery message
				probe = []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n")
			// Case for CoAP IoT protocol
			case 5683:
				// Create a CoAP GET request (binary format)
				probe = []byte{0x40, 0x01, 0x00, 0x01}
			// Case for WebSocket connections
			case 8001:
				// Create a WebSocket upgrade request
				probe = []byte("GET / HTTP/1.1\r\nUpgrade: websocket\r\n\r\n")
			}

			// Send the probe packet to the target
			_, err = udpConn.Write(probe)
			// Check if we had an error sending the probe
			if err != nil {
				// If verbose mode is enabled, log the write error
				if s.verbose {
					// Print the detailed error message for debugging
					fmt.Printf("Debug: UDP write error on port %d: %v\n", port, err)
				}
				// Return nil since we couldn't send the probe
				return nil
			}

			// Create a buffer to store the response
			response := make([]byte, 1024)
			// Set a deadline for reading the response
			udpConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			// Try to read the response from the target
			n, _, err := udpConn.ReadFromUDP(response)

			// Check if we had an error reading the response
			if err != nil {
				// If verbose mode is enabled, log the read error
				if s.verbose {
					// Print the detailed error message for debugging
					fmt.Printf("Debug: UDP read error on port %d: %v\n", port, err)
				}
				// Return nil since we couldn't read a response
				return nil
			}

			// Check if we got any response from the UDP port
			if n > 0 {
				// If we're in verbose mode, we'll log additional details
				if s.verbose {
					// Print a debug message showing how many bytes we received
					fmt.Printf("Debug: Got UDP response from port %d: %d bytes\n", port, n)
				}
				// Since we got a response, we'll create a result object
				return &PortResult{
					// Store the port number we just scanned
					Port: port,
					// Mark this as an open UDP port
					State: "open (UDP)",
					// Get the name of the service typically running on this port
					Service: getServiceName(port),
					// Set device type as unknown for now
					DeviceType: "unknown",
				}
			}
			// If we didn't get any response, return nil
			return nil
		}
		return nil
	}
	// Close the TCP connection when we're done with it
	defer conn.Close()

	// If we're in verbose mode, print debug information
	if s.verbose {
		// Log that we found an open TCP port
		fmt.Printf("Debug: TCP port %d is open\n", port)
	}

	// Get the name of the service for this port
	service := getServiceName(port)
	// Set the initial state of the port
	state := "open"

	// Check if this port is commonly used for HTTP services
	if port == 80 || port == 8080 || port == 8001 || port == 8002 {
		// Create a new HTTP client with specific settings
		client := &http.Client{
			// Set the timeout for HTTP requests
			Timeout: s.tcpTimeout,
			// Configure the transport layer settings
			Transport: &http.Transport{
				// Don't keep connections alive
				DisableKeepAlives: true,
				// Configure TLS settings
				TLSClientConfig: &tls.Config{
					// Allow self-signed certificates
					InsecureSkipVerify: true,
				},
			},
		}

		// Build the full URL to test
		url := fmt.Sprintf("http://%s", target)
		// If we're in verbose mode, log what we're doing
		if s.verbose {
			// Print that we're attempting an HTTP connection
			fmt.Printf("Debug: Trying HTTP on %s\n", url)
		}

		// Try to make an HTTP GET request
		if resp, err := client.Get(url); err == nil {
			// Make sure to close the response body when done
			defer resp.Body.Close()

			// Check if the server identifies itself
			if resp.Header.Get("Server") != "" {
				// If it does, include that in our service info
				service = fmt.Sprintf("HTTP (%s)", resp.Header.Get("Server"))
			} else {
				// If not, just mark it as HTTP
				service = "HTTP"
			}

			// If we're in verbose mode, log the success
			if s.verbose {
				// Print that we got a response
				fmt.Printf("Debug: Got HTTP response from port %d\n", port)
			}
		} else {
			// If the HTTP request failed and we're in verbose mode
			if s.verbose {
				// Log the error details
				fmt.Printf("Debug: HTTP error on port %d: %v\n", port, err)
			}
		}
	}

	// Try to get more info for HTTPS services
	if port == 443 || port == 8443 || port == 8002 {
		// Create TLS config that accepts self-signed certificates
		config := &tls.Config{
			// Allow any certificate by skipping verification
			InsecureSkipVerify: true,
		}

		// Try to establish a TLS connection using our dialer and config
		if tlsConn, err := tls.DialWithDialer(dialer, "tcp", target, config); err == nil {
			// Make sure we properly close the TLS connection when done
			defer tlsConn.Close()

			// Update the state to indicate this is a secure port
			state = "open (SSL/TLS)"

			// Check if we can get certificate information from the connection
			if len(tlsConn.ConnectionState().PeerCertificates) > 0 {
				// Get the first certificate from the chain
				cert := tlsConn.ConnectionState().PeerCertificates[0]
				// Update service info to include the certificate's common name
				service = fmt.Sprintf("HTTPS (%s)", cert.Subject.CommonName)
			} else {
				// If no certificate info available, just mark as HTTPS
				service = "HTTPS"
			}
		}
	}

	// Try banner grabbing for services that typically provide identifying information
	if service == "unknown" || service == "FTP" || service == "SSH" || service == "SMTP" || service == "Samsung TV Control" {
		// Attempt to grab a banner and check if we got one
		if banner := grabBanner(target, s.tcpTimeout, s.maxBannerSize); banner != "" {
			// If we got a banner, append it to the service information
			service = fmt.Sprintf("%s (%s)", service, banner)
		}
	}

	// Determine the type of device based on manufacturer info and open ports
	deviceType := s.detectDeviceType(s.target, s.portRange)

	// Create and return a PortResult with all the information we gathered
	return &PortResult{
		// The port number we scanned
		Port: port,
		// The state of the port (open, open SSL/TLS)
		State: state,
		// The service we identified
		Service: service,
		// The type of device we detected
		DeviceType: deviceType,
	}
}

// Improved device type detection function
func (s *PortScanner) detectDeviceType(target string, openPorts []int) string {
	// Convert target to lowercase for case-insensitive matching
	targetLower := strings.ToLower(target)

	// Check if the target might be an Ecobee device
	if strings.Contains(targetLower, "ecobee") {
		// Verify it has typical Ecobee ports open
		if containsAny(openPorts, []int{8080, 8443, 443}) {
			// Return thermostat if it matches Ecobee characteristics
			return "thermostat"
		}
	}

	// Check if the target might be a Samsung device
	if strings.Contains(targetLower, "samsung") {
		// Verify it has typical Samsung TV ports open
		if containsAny(openPorts, []int{8001, 8002, 9090, 9091}) {
			// Return samsung tv if it matches Samsung TV characteristics
			return "samsung tv"
		}
	}

	// Check for generic IoT device types based on common port patterns
	if containsAny(openPorts, []int{554, 8554, 8080}) {
		// Return ip camera if it has typical camera ports
		return "ip camera"
	}
	// Check for printer ports
	if containsAny(openPorts, []int{9100, 515, 631}) {
		// Return printer if it has typical printer ports
		return "printer"
	}

	// If no specific device type was identified
	return "unknown"
}

// Helper function to check if a slice contains any of the specified values
func containsAny(slice []int, values []int) bool {
	// Loop through each value we're looking for
	for _, v := range values {
		// Check each element in the slice
		for _, s := range slice {
			// If we find a match
			if v == s {
				// Return true as we found one of the values
				return true
			}
		}
	}
	// Return false if none of the values were found
	return false
}

// Improved banner grabbing with protocol-specific connections
func grabBanner(target string, timeout time.Duration, maxSize int) string {
	// Create a channel to receive banner results from all protocol probes
	results := make(chan string, len(probeProtocols))

	// Start a goroutine for each protocol we want to test
	for protocol, probes := range probeProtocols {
		// Launch a goroutine to handle this protocol's probes
		go func(proto string, probeList []string) {
			// Try to establish a TCP connection with timeout
			conn, err := net.DialTimeout("tcp", target, timeout)
			// If connection fails, send empty result and return
			if err != nil {
				results <- ""
				return
			}
			// Ensure connection is closed when we're done
			defer conn.Close()

			// Try each probe string for this protocol
			for _, probe := range probeList {
				// Set deadline for writing the probe
				conn.SetWriteDeadline(time.Now().Add(timeout))
				// Send the probe data to the target
				if _, err := conn.Write([]byte(probe)); err != nil {
					// If write fails, try next probe
					continue
				}

				// Set deadline for reading the response
				conn.SetReadDeadline(time.Now().Add(timeout))
				// Create buffer to store the banner response
				banner := make([]byte, maxSize)
				// Try to read the response
				n, err := conn.Read(banner)
				// If read succeeds and we got data
				if err == nil && n > 0 {
					// Clean and send the banner through results channel
					results <- cleanBanner(string(banner[:n]))
					return
				}
			}
			// If no probes succeeded, send empty result
			results <- ""
		}(protocol, probes)
	}

	// Create a timer to enforce overall timeout for all probes
	timer := time.NewTimer(timeout * 2)
	// Ensure timer is cleaned up when we're done
	defer timer.Stop()

	// Check results from all protocol probes
	for i := 0; i < len(probeProtocols); i++ {
		// Use select to handle either a result or timeout
		select {
		// Handle incoming banner result
		case banner := <-results:
			// If we got a valid banner
			if banner != "" {
				// Return the first valid banner we find
				return banner
			}
		// Handle timeout case
		case <-timer.C:
			// Return empty string if we timeout
			return ""
		}
	}

	// Return empty string if no valid banners were found
	return ""
}

// Protocol-specific probes for different services
// Each protocol has a list of probes that might elicit a response
var probeProtocols = map[string][]string{
	// HTTP probes - basic HEAD and GET requests
	"http": {
		// Simple HEAD request to minimize data transfer
		"HEAD / HTTP/1.0\r\n\r\n",
		// Basic GET request as fallback
		"GET / HTTP/1.0\r\n\r\n",
	},
	// FTP probes - try anonymous login
	"ftp": {
		// Try anonymous user login
		"USER anonymous\r\n",
		// Clean exit command
		"QUIT\r\n",
	},
	// SSH probe - send client identification
	"ssh": {
		// Standard SSH client identification string
		"SSH-2.0-OpenSSH\r\n",
	},
	// SMTP probes - basic email server checks
	"smtp": {
		// Extended HELO command for SMTP
		"EHLO localhost\r\n",
		// Clean exit from SMTP session
		"QUIT\r\n",
	},
	// IoT specific probes for device identification
	"iot": {
		// Samsung specific UPnP probe to identify Samsung devices
		"Samsung UPnP SDK\r\n",
		// Generic IoT API probe to check for common IoT interfaces
		"GET /common/1.0\r\n",
	},
}

// cleanBanner processes the raw banner text to make it more readable
// It removes control characters and returns only the first line
func cleanBanner(banner string) string {
	// Remove control characters except newline and carriage return
	banner = strings.Map(func(r rune) rune {
		// If it's a control character (except \n and \r), remove it
		if r < 32 && r != '\n' && r != '\r' {
			// Return -1 to remove the character
			return -1
		}
		// Keep all other characters
		return r
	}, banner)

	// Split the banner into lines
	lines := strings.Split(banner, "\n")
	// If we have at least one line
	if len(lines) > 0 {
		// Return the first line with whitespace trimmed
		return strings.TrimSpace(lines[0])
	}
	// Return empty string if no valid lines found
	return ""
}

// getServiceName maps port numbers to their common service names
// This function provides generic service names for well-known ports
func getServiceName(port int) string {
	// Define a map of common service ports and their names
	services := map[int]string{
		20:    "FTP-Data",          // FTP Data transfer port
		21:    "FTP",               // FTP Control port
		22:    "SSH",               // Secure Shell port
		23:    "Telnet",            // Telnet port
		25:    "SMTP",              // Simple Mail Transfer Protocol
		53:    "DNS",               // Domain Name System
		80:    "HTTP",              // Web server port
		110:   "POP3",              // Post Office Protocol v3
		143:   "IMAP",              // Internet Message Access Protocol
		443:   "HTTPS",             // Secure web server port
		445:   "SMB",               // Server Message Block
		1883:  "MQTT",              // Message Queuing Telemetry Transport
		1900:  "UPNP",              // Universal Plug and Play
		3389:  "RDP",               // Remote Desktop Protocol
		5683:  "CoAP",              // Constrained Application Protocol
		8001:  "WebSocket API",     // Generic WebSocket port
		8002:  "WebSocket API SSL", // Secure WebSocket port
		8008:  "HTTP Alt",          // Alternative HTTP port
		8009:  "HTTP Alt",          // Alternative HTTP port
		8080:  "HTTP-Proxy",        // Common HTTP proxy port
		8443:  "HTTPS Alt",         // Alternative HTTPS port
		8883:  "MQTT SSL",          // Secure MQTT port
		9090:  "WebSocket API",     // Another WebSocket port
		9091:  "WebSocket API SSL", // Another secure WebSocket port
		9100:  "Printer",           // Network printer port
		49152: "UPnP",              // UPnP alternative port
	}

	// Look up the service name for this port
	if service, ok := services[port]; ok {
		// Return the service name if found
		return service
	}
	// Return "unknown" if port isn't in our map
	return "unknown"
}

// generatePortRange creates a sequential list of ports between start and end
// This function is now only used internally by the scanner
func generatePortRange(start, end int) []int {
	// Create an empty slice to hold our port numbers
	var ports []int
	// Loop from start to end, adding each port number to our list
	for port := start; port <= end; port++ {
		ports = append(ports, port)
	}
	// Return the complete list of ports
	return ports
}

// portDescriptions maps port numbers to human-readable descriptions
// These are generic descriptions used when we don't know the specific device type
var portDescriptions = map[int]string{
	21:    "FTP service for file transfer",           // Standard FTP port
	22:    "SSH service for secure remote access",    // Secure Shell
	23:    "Telnet service (insecure remote access)", // Legacy remote access
	80:    "HTTP web service",                        // Standard web server
	443:   "HTTPS secure web service",                // Secure web server
	554:   "RTSP streaming service",                  // Video streaming
	1883:  "MQTT broker for IoT messaging",           // IoT messaging protocol
	1900:  "UPnP discovery service",                  // Device discovery
	5683:  "CoAP service for IoT communication",      // IoT protocol
	8001:  "WebSocket API service",                   // Real-time communication
	8002:  "Secure WebSocket API service",            // Secure real-time comm
	8080:  "Alternative HTTP service",                // Web server alternate
	8443:  "Alternative HTTPS service",               // Secure web alternate
	9090:  "WebSocket API service",                   // Another WebSocket port
	9091:  "Secure WebSocket API service",            // Secure WebSocket alt
	9100:  "Network printer service",                 // Printer port
	49152: "UPnP service",                            // UPnP alternate
}

// samsungTVPorts maps Samsung TV specific ports to their descriptions
// These descriptions are only used when we've identified a Samsung TV
var samsungTVPorts = map[int]string{
	8001:  "Samsung TV Control API port (WebSocket API)",           // Main control interface
	8002:  "Samsung TV Control API port (Encrypted WebSocket API)", // Secure control
	9090:  "Samsung TV HTTP API",                                   // Web API
	9091:  "Samsung TV HTTPS API",                                  // Secure Web API
	7676:  "Samsung TV Debug port",                                 // Debugging interface
	9197:  "Samsung TV Remote control interface",                   // Remote control
	9198:  "Samsung TV Remote control interface (SSL)",             // Secure remote
	8889:  "Samsung TV Media port",                                 // Media streaming
	55000: "Samsung TV Remote Control port",                        // Additional remote
}

// getPortDescription returns a human-readable description of what a port is typically used for
// It takes into account both the port number and the type of device we're scanning
func (s *PortScanner) getPortDescription(port int, deviceType string) string {
	// First check if this is a Samsung TV and use specific descriptions
	if strings.Contains(strings.ToLower(deviceType), "samsung") &&
		strings.Contains(strings.ToLower(deviceType), "tv") {
		// Look up Samsung-specific port description
		if desc, ok := samsungTVPorts[port]; ok {
			return desc
		}
	}

	// If not a Samsung TV or port not found, use generic descriptions
	if desc, ok := portDescriptions[port]; ok {
		return desc
	}

	// If we don't recognize the port, return a generic message
	return "Unknown service"
}
