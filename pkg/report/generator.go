package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/IoTscan/pkg/discovery"
	"github.com/IoTscan/pkg/scanner"
	"github.com/IoTscan/pkg/vulnscan"
)

type ScanResult struct {
	Timestamp    time.Time
	NetworkRange string
	Devices      []DeviceResult
	TotalDevices int
	VulnsByLevel map[string]int
}

type DeviceResult struct {
	Device          discovery.Device
	OpenPorts       []scanner.PortResult
	Vulnerabilities []vulnscan.Vulnerability
}

type ReportGenerator struct {
	result     *ScanResult
	outputPath string
	format     string
}

func NewReportGenerator(result *ScanResult, outputPath, format string) *ReportGenerator {
	return &ReportGenerator{
		result:     result,
		outputPath: outputPath,
		format:     format,
	}
}

func (g *ReportGenerator) Generate() error {
	switch g.format {
	case "html":
		return g.generateHTML()
	case "json":
		return g.generateJSON()
	default:
		return fmt.Errorf("unsupported format: %s", g.format)
	}
}

func (g *ReportGenerator) generateJSON() error {
	file, err := os.Create(g.outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(g.result)
}

func (g *ReportGenerator) generateHTML() error {
	const htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>IoT Security Scan Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 20px;
            color: #333;
        }
        .header {
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .device {
            border: 1px solid #ddd;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 5px;
        }
        .vulnerability {
            margin: 10px 0;
            padding: 10px;
            border-left: 4px solid #ddd;
        }
        .critical { border-left-color: #dc3545; }
        .high { border-left-color: #fd7e14; }
        .medium { border-left-color: #ffc107; }
        .low { border-left-color: #28a745; }
        .technical-details {
            background-color: #f8f9fa;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }
        .technical-details pre {
            white-space: pre-wrap;
            word-wrap: break-word;
            font-family: monospace;
            margin: 0;
            font-size: 14px;
            line-height: 1.4;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }
        th, td {
            padding: 8px;
            border: 1px solid #ddd;
            text-align: left;
        }
        th {
            background-color: #f8f9fa;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>IoT Security Scan Report</h1>
        <p>Scan Time: {{.Timestamp}}</p>
        <p>Network Range: {{.NetworkRange}}</p>
        <p>Total Devices: {{.TotalDevices}}</p>
    </div>

    <h2>Summary</h2>
    <table>
        <tr>
            <th>Severity</th>
            <th>Count</th>
        </tr>
        {{range $severity, $count := .VulnsByLevel}}
        <tr>
            <td>{{$severity}}</td>
            <td>{{$count}}</td>
        </tr>
        {{end}}
    </table>

    <h2>Detailed Results</h2>
    {{range .Devices}}
    <div class="device">
        <h3>Device: {{.Device.IP}}</h3>
        <p>MAC: {{.Device.MAC}}</p>
        {{if .Device.Manufacturer}}
        <p>Manufacturer: {{.Device.Manufacturer}}</p>
        {{end}}
        {{if .Device.DeviceType}}
        <p>Device Type: {{.Device.DeviceType}}</p>
        {{end}}
        {{if .Device.Model}}
        <p>Model: {{.Device.Model}}</p>
        {{end}}

        <h4>Open Ports</h4>
        {{if .OpenPorts}}
        <table>
            <tr>
                <th>Port</th>
                <th>Service</th>
                <th>State</th>
            </tr>
            {{range .OpenPorts}}
            <tr>
                <td>{{.Port}}</td>
                <td>{{if .Service}}{{.Service}}{{else}}unknown{{end}}</td>
                <td>{{if .State}}{{.State}}{{else}}open{{end}}</td>
            </tr>
            {{end}}
        </table>
        {{else}}
        <p>No open ports found</p>
        {{end}}

        <h4>Vulnerabilities</h4>
        {{range .Vulnerabilities}}
        <div class="vulnerability {{.Severity | lower}}">
            <h4>{{.Type}} ({{.Severity}})</h4>
            <p><strong>Description:</strong> {{.Description}}</p>
            <p><strong>Solution:</strong> {{.Solution}}</p>
            {{if .TechnicalDetails}}
            <div class="technical-details">
                <h5>Technical Details & Attack Methodology:</h5>
                <pre>{{.TechnicalDetails}}</pre>
            </div>
            {{end}}
            {{if .CVE}}
            <p><strong>CVE:</strong> {{.CVE}}</p>
            {{end}}
            {{if .References}}
            <p><strong>References:</strong></p>
            <ul>
                {{range .References}}
                <li><a href="{{.}}">{{.}}</a></li>
                {{end}}
            </ul>
            {{end}}
        </div>
        {{end}}
    </div>
    {{end}}
</body>
</html>
`

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"lower": strings.ToLower,
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %v", err)
	}

	file, err := os.Create(g.outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer file.Close()

	return tmpl.Execute(file, g.result)
}

func (g *ReportGenerator) calculateVulnerabilityStats() {
	g.result.VulnsByLevel = make(map[string]int)
	for _, device := range g.result.Devices {
		for _, vuln := range device.Vulnerabilities {
			g.result.VulnsByLevel[vuln.Severity]++
		}
	}
}
