package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/IoTscan/pkg/discovery"
	"github.com/IoTscan/pkg/report"
	"github.com/IoTscan/pkg/scanner"
	"github.com/IoTscan/pkg/vulnscan"
	"github.com/spf13/cobra"
)

var (
	ipRange      string
	interface_   string
	reportFormat string
	outputFile   string
	portRange    string
	verbose      bool
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "iotscan",
		Short: "IoT Device Vulnerability Scanner",
		Long: `A comprehensive IoT device vulnerability scanner that helps identify and assess 
security risks in IoT environments. Designed for network administrators and security professionals.`,
	}

	var scanCmd = &cobra.Command{
		Use:   "scan",
		Short: "Start full scanning for IoT devices",
		Long:  `Performs a comprehensive scan of the network to discover and analyze IoT devices.`,
		Run:   runScan,
	}

	var discoverCmd = &cobra.Command{
		Use:   "discover",
		Short: "Discover devices on the network",
		Long:  `Only performs network discovery to find devices, without port or vulnerability scanning.`,
		Run:   runDiscover,
	}

	// Add flags to scan command
	scanCmd.Flags().StringVarP(&ipRange, "range", "r", "", "IP range to scan (e.g., 192.168.1.0/24)")
	scanCmd.Flags().StringVarP(&interface_, "interface", "i", "", "Network interface to use")
	scanCmd.Flags().StringVarP(&reportFormat, "report-format", "f", "html", "Report format (html/json)")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "iotscan-report", "Output file name")
	scanCmd.Flags().StringVarP(&portRange, "ports", "p", "", "Port range to scan (default: common IoT ports)")
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	// Add flags to discover command
	discoverCmd.Flags().StringVarP(&ipRange, "range", "r", "", "IP range to scan (e.g., 192.168.1.0/24)")
	discoverCmd.Flags().StringVarP(&interface_, "interface", "i", "", "Network interface to use")
	discoverCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(discoverCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func parsePorts(portRange string) []int {
	// If no port range specified, return empty slice to use default IoT ports
	if portRange == "" {
		return []int{}
	}

	var ports []int
	// Split by comma
	ranges := strings.Split(portRange, ",")
	for _, r := range ranges {
		// Convert single port
		port, err := strconv.Atoi(r)
		if err == nil {
			ports = append(ports, port)
			continue
		}

		// Try range (e.g., "80-100")
		parts := strings.Split(r, "-")
		if len(parts) == 2 {
			start, err1 := strconv.Atoi(parts[0])
			end, err2 := strconv.Atoi(parts[1])
			if err1 == nil && err2 == nil && start <= end {
				for port := start; port <= end; port++ {
					ports = append(ports, port)
				}
			}
		}
	}
	return ports
}

func runScan(cmd *cobra.Command, args []string) {
	// Initialize network scanner
	netScanner, err := discovery.NewScanner(interface_, ipRange)
	if err != nil {
		log.Fatalf("Failed to initialize network scanner: %v", err)
	}

	// Start device discovery
	fmt.Println("Starting device discovery...")
	devices, err := netScanner.ScanNetwork()
	if err != nil {
		log.Fatalf("Failed to scan network: %v", err)
	}

	// Initialize scan results
	results := &report.ScanResult{
		Timestamp:    time.Now(),
		NetworkRange: ipRange,
		TotalDevices: len(devices),
	}

	// Scan each discovered device
	for _, device := range devices {
		if verbose {
			fmt.Printf("Scanning device: %s\n", device.IP)
		}

		// Port scanning
		portScanner := scanner.NewPortScanner(device.IP.String())
		portScanner.SetPorts(parsePorts(portRange))
		portScanner.SetVerbose(verbose)
		ports, err := portScanner.ScanPorts()
		if err != nil && verbose {
			fmt.Printf("Warning: port scan failed for %s: %v\n", device.IP, err)
		}

		// Vulnerability scanning
		vulnScanner := vulnscan.NewVulnScanner(device.IP.String())
		vulns, err := vulnScanner.ScanVulnerabilities(nil)
		if err != nil && verbose {
			fmt.Printf("Warning: vulnerability scan failed for %s: %v\n", device.IP, err)
		}

		// Add results
		deviceResult := report.DeviceResult{
			Device:          device,
			OpenPorts:       ports,
			Vulnerabilities: vulns,
		}
		results.Devices = append(results.Devices, deviceResult)
	}

	// Generate report
	outputPath := fmt.Sprintf("%s.%s", outputFile, reportFormat)
	reportGen := report.NewReportGenerator(results, outputPath, reportFormat)

	fmt.Printf("Generating report in %s format...\n", reportFormat)
	if err := reportGen.Generate(); err != nil {
		log.Fatalf("Failed to generate report: %v", err)
	}

	fmt.Printf("Scan complete! Report saved to: %s\n", outputPath)
	fmt.Printf("Total devices scanned: %d\n", len(devices))
}

func runDiscover(cmd *cobra.Command, args []string) {
	// Initialize network scanner
	netScanner, err := discovery.NewScanner(interface_, ipRange)
	if err != nil {
		log.Fatalf("Failed to initialize network scanner: %v", err)
	}

	// Start device discovery
	fmt.Println("Starting device discovery...")
	devices, err := netScanner.ScanNetwork()
	if err != nil {
		log.Fatalf("Failed to scan network: %v", err)
	}

	// Print results in a clean format
	fmt.Printf("\nDiscovered devices:\n")
	fmt.Printf("%-16s %-20s %-15s\n", "IP Address", "MAC Address", "Manufacturer")
	fmt.Printf("%-16s %-20s %-15s\n", strings.Repeat("-", 16), strings.Repeat("-", 17), strings.Repeat("-", 15))

	for _, device := range devices {
		manufacturer := device.Manufacturer
		if manufacturer == "" {
			manufacturer = "Unknown"
		}
		fmt.Printf("%-16s %-20s %-15s",
			device.IP.String(),
			device.MAC.String(),
			manufacturer)
		if device.DeviceType != "" {
			fmt.Printf(" (%s)", device.DeviceType)
		}
		fmt.Println()
	}

	fmt.Printf("\nTotal devices found: %d\n", len(devices))
}
