package main

import (
	"fmt"
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
	reportFormat string
	outputFile   string
	verbose      bool
	ports        string
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
		Short: "Start scanning for IoT devices",
		Long:  `Performs a comprehensive scan of the network to discover and analyze IoT devices.`,
		Run: func(cmd *cobra.Command, args []string) {
			if verbose {
				fmt.Printf("Starting scan on target: %s\n", ipRange)
				if ports != "" {
					fmt.Printf("Scanning ports: %s\n", ports)
				}
			}

			// Parse ports string into []int
			var portList []int
			if ports != "" {
				portStrings := strings.Split(ports, ",")
				for _, p := range portStrings {
					port, err := strconv.Atoi(strings.TrimSpace(p))
					if err != nil {
						fmt.Printf("Invalid port number: %s\n", p)
						os.Exit(1)
					}
					portList = append(portList, port)
				}
			} else {
				// Default to common IoT ports if none specified
				portList = []int{8001, 8002, 8080, 80, 443, 23, 22, 21, 554, 1900, 5683}
			}

			if verbose {
				fmt.Printf("Will scan the following ports: %v\n", portList)
			}

			fmt.Println("Starting device discovery...")

			// Create and run network discovery scanner
			discoveryScanner, err := discovery.NewScanner("", ipRange)
			if err != nil {
				fmt.Printf("Failed to initialize discovery scanner: %v\n", err)
				os.Exit(1)
			}

			discoveredDevices, err := discoveryScanner.ScanNetwork()
			if err != nil {
				fmt.Printf("Discovery scan failed: %v\n", err)
				os.Exit(1)
			}

			// Initialize result first
			result := &report.ScanResult{
				Timestamp:    time.Now(),
				NetworkRange: ipRange,
				TotalDevices: len(discoveredDevices),
				VulnsByLevel: make(map[string]int),
			}

			var deviceResults []report.DeviceResult

			// For each discovered device, perform port and vulnerability scanning
			for _, device := range discoveredDevices {
				if verbose {
					fmt.Printf("\nScanning device: %s (%s)\n", device.IP, device.MAC)
					fmt.Printf("Manufacturer: %s\n", device.Manufacturer)
					fmt.Printf("Device Type: %s\n", device.DeviceType)
				}

				// Create port scanner
				portScanner := scanner.NewPortScanner(device.IP.String())
				portScanner.SetPorts(portList)
				portScanner.SetTimeout(5 * time.Second)

				// Run port scan
				fmt.Printf("\nStarting port scan on %s...\n", device.IP)
				portResults, err := portScanner.ScanPorts()
				if err != nil {
					fmt.Printf("Port scan failed for %s: %v\n", device.IP, err)
					portResults = []scanner.PortResult{} // Initialize empty slice instead of skipping
				}

				if verbose {
					fmt.Printf("Found %d open ports on %s\n", len(portResults), device.IP)
					for _, port := range portResults {
						fmt.Printf("  Port %d: %s (%s)\n", port.Port, port.Service, port.State)
					}
				}

				// Create and run vulnerability scanner
				vulnScanner := vulnscan.NewVulnScanner(device.IP.String())
				vulns, err := vulnScanner.ScanVulnerabilities(getOpenPorts(portResults))
				if err != nil {
					fmt.Printf("Vulnerability scan failed for %s: %v\n", device.IP, err)
					vulns = []vulnscan.Vulnerability{} // Initialize empty slice instead of nil
				}

				// Add results
				deviceResult := report.DeviceResult{
					Device:          device,
					OpenPorts:       portResults,
					Vulnerabilities: vulns,
				}
				deviceResults = append(deviceResults, deviceResult)

				// Update vulnerability statistics
				for _, vuln := range vulns {
					result.VulnsByLevel[vuln.Severity]++
				}
			}

			// Update final results
			result.Devices = deviceResults

			reportPath := outputFile
			if !strings.HasSuffix(reportPath, "."+reportFormat) {
				reportPath += "." + reportFormat
			}

			generator := report.NewReportGenerator(result, reportPath, reportFormat)
			if err := generator.Generate(); err != nil {
				fmt.Printf("Failed to generate report: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Scan complete! Report saved to: %s\n", reportPath)
			fmt.Printf("Total devices scanned: %d\n", result.TotalDevices)
		},
	}

	// Add flags to scan command
	scanCmd.Flags().StringVarP(&ipRange, "range", "r", "", "IP range to scan (e.g., 192.168.1.0/24)")
	scanCmd.Flags().StringVarP(&reportFormat, "report-format", "f", "html", "Report format (html/pdf/json)")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "iotscan-report", "Output file name")
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	scanCmd.Flags().StringVarP(&ports, "ports", "p", "", "Comma-separated list of ports to scan (e.g., 21,22,23,80)")

	rootCmd.AddCommand(scanCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// Helper function to extract port numbers from port results
func getOpenPorts(results []scanner.PortResult) []int {
	var ports []int
	for _, result := range results {
		ports = append(ports, result.Port)
	}
	return ports
}
