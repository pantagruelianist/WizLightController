package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

type WizDevice struct {
	IP       string
	Mac      string
	Model    string
	Firmware string
	LastSeen time.Time
	RawJSON  string
}

type WizDeviceManager struct {
	Devices map[string]*WizDevice
	mu      sync.Mutex
}

func NewWizDeviceManager() *WizDeviceManager {
	return &WizDeviceManager{
		Devices: make(map[string]*WizDevice),
	}
}

func (m *WizDeviceManager) UpdateFromDiscovery(resp WizDiscoveryResponse) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mac := resp.Result.Mac
	if mac == "" {
		return
	}
	m.Devices[mac] = &WizDevice{
		IP:       resp.Result.IP,
		Mac:      mac,
		Model:    resp.Result.Module,
		Firmware: resp.Result.Firmware,
		LastSeen: time.Now(),
		RawJSON:  resp.RawJson,
	}
}

func (m *WizDeviceManager) Snapshot() []*WizDevice {
	m.mu.Lock()
	defer m.mu.Unlock()
	devices := make([]*WizDevice, 0, len(m.Devices))
	for _, dev := range m.Devices {
		devices = append(devices, dev)
	}
	return devices
}

type WizDiscoveryResponse struct {
	Method string `json:"method"`
	Env    string `json:"env,omitempty"`
	Result struct {
		Mac      string `json:"mac"`
		Module   string `json:"moduleName"`
		Firmware string `json:"fwVersion"`
		IP       string `json:"-"`
	} `json:"result"`
	RawJson string `json:"-"`
}

// packet log info...
const maxPacketLogLines = 5

var (
	packetLog  []string
	logMu      sync.Mutex
	paused     bool
	pauseMu    sync.Mutex
	selectedIP string
	targetMu   sync.Mutex
)

func addPacketLogLine(line string) {
	logMu.Lock()
	defer logMu.Unlock()
	if len(packetLog) >= maxPacketLogLines {
		packetLog = packetLog[1:]
	}
	packetLog = append(packetLog, line)
}

func getPacketLogSnapshot() []string {
	logMu.Lock()
	defer logMu.Unlock()
	return append([]string(nil), packetLog...)
}

//terminal clearing when we're not paused...

func clearTerminal() {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	} else {
		fmt.Print("\033[2J\033[H")
	}
}

func printScreen(devices []*WizDevice, packets []string, paused bool) {
	clearTerminal()
	status := "ACTIVE"
	if paused {
		status = "PAUSED"
	}
	fmt.Printf("Wiz Devices Monitor [%s]\n", status)
	selected := getTargetIP()
	for i, d := range devices {
		sel := " "
		if d.IP == selected {
			sel = "*"
		}
		fmt.Printf("[%d]%s MAC: %s | IP: %s | Model: %s | FW: %s | Seen: %s\n",
			i, sel, d.Mac, d.IP, d.Model, d.Firmware, d.LastSeen.Format(time.RFC3339))
	}
	fmt.Println("\nUDP Packet Log:")
	for _, line := range packets {
		fmt.Println(line)
	}
}

//unified discovery and command interface...

func runUnifiedDiscovery(manager *WizDeviceManager) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 38899})
	if err != nil {
		fmt.Printf("Failed to bind UDP socket: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	broadcastAddr := net.UDPAddr{IP: net.IPv4bcast, Port: 38899}
	probe := []byte(`{"method":"getSystemConfig"}`)

	buffer := make([]byte, 4096)
	lastDiscovery := time.Time{}

	for {
		now := time.Now()
		if now.Sub(lastDiscovery) > 5*time.Second {
			_, err := conn.WriteToUDP(probe, &broadcastAddr)
			if err != nil {
				addPacketLogLine("[ERR] Broadcast failed: " + err.Error())
			}
			lastDiscovery = now
		}

		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, src, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if !strings.Contains(err.Error(), "i/o timeout") {
				addPacketLogLine("[ERR] " + err.Error())
			}
			continue
		}

		raw := string(buffer[:n])
		addPacketLogLine(fmt.Sprintf("[%s] %s → %s",
			now.Format("15:04:05"), src.IP, raw))

		var resp WizDiscoveryResponse
		if json.Unmarshal(buffer[:n], &resp) == nil && resp.Method == "getSystemConfig" {
			resp.Result.IP = src.IP.String()
			resp.RawJson = raw
			manager.UpdateFromDiscovery(resp)
		}
	}
}

//send a command...

func sendCommand(ip string, jsonStr string) error {
	addr := net.UDPAddr{
		IP:   net.ParseIP(ip),
		Port: 38899,
	}
	conn, err := net.DialUDP("udp", nil, &addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(jsonStr))
	return err
}

//target the device...

func setTargetIP(ip string) {
	targetMu.Lock()
	defer targetMu.Unlock()
	selectedIP = ip
}

func getTargetIP() string {
	targetMu.Lock()
	defer targetMu.Unlock()
	return selectedIP
}

func runCommandInterface(manager *WizDeviceManager) {
	reader := os.Stdin
	for {
		fmt.Print("\nEnter command (select <#>, on, off, bright <0-100>, rgb <r> <g> <b>): ")
		var cmd string
		_, err := fmt.Fscanf(reader, "%s", &cmd)
		if err != nil {
			continue
		}

		devices := manager.Snapshot()
		if len(devices) == 0 {
			fmt.Println("No devices available.")
			continue
		}

		switch cmd {
		case "select":
			var index int
			fmt.Fscanf(reader, "%d", &index)
			if index < 0 || index >= len(devices) {
				fmt.Println("Invalid device number.")
			} else {
				setTargetIP(devices[index].IP)
				fmt.Printf("Selected device: %s (%s)\n", devices[index].IP, devices[index].Mac)
			}
		case "on", "off", "bright", "rgb":
			ip := getTargetIP()
			if ip == "" {
				fmt.Println("Please select a device first using 'select <number>'")
				continue
			}

			var jsonStr string
			switch cmd {
			case "on":
				jsonStr = `{"method":"setState","params":{"state":true}}`
			case "off":
				jsonStr = `{"method":"setState","params":{"state":false}}`
			case "bright":
				var val int
				fmt.Fscanf(reader, "%d", &val)
				jsonStr = fmt.Sprintf(`{"method":"setState","params":{"dimming":%d}}`, val)
			case "rgb":
				var r, g, b int
				fmt.Fscanf(reader, "%d %d %d", &r, &g, &b)
				jsonStr = fmt.Sprintf(`{"method":"setState","params":{"r":%d,"g":%d,"b":%d}}`, r, g, b)
			}

			err := sendCommand(ip, jsonStr)
			if err != nil {
				fmt.Printf("Failed to send to %s: %v\n", ip, err)
			} else {
				fmt.Printf("Sent to %s\n", ip)
			}
		default:
			fmt.Println("Unknown command.")
		}
	}
}

func togglePause() {
	pauseMu.Lock()
	defer pauseMu.Unlock()
	paused = !paused
	if paused {
		fmt.Println("\n[PAUSED] Screen refresh is paused. Press 'P' again to resume.")
		fmt.Println("Available commands:")
		fmt.Println("  select <#>            → choose device by index")
		fmt.Println("  on                    → turn selected light ON")
		fmt.Println("  off                   → turn selected light OFF")
		fmt.Println("  bright <0-100>        → set brightness")
		fmt.Println("  rgb <r> <g> <b>       → set RGB color")
		fmt.Println("  p                     → toggle pause/resume")
	} else {
		fmt.Println("\n[RESUMED] Screen refresh is active.")
	}
}

func isPaused() bool {
	pauseMu.Lock()
	defer pauseMu.Unlock()
	return paused
}

func runUIUpdater(manager *WizDeviceManager, interval time.Duration) {
	for {
		if !isPaused() {
			devices := manager.Snapshot()
			logs := getPacketLogSnapshot()
			printScreen(devices, logs, false)
		}
		time.Sleep(interval)
	}
}

func main() {
	manager := NewWizDeviceManager()

	go runUnifiedDiscovery(manager)
	go runUIUpdater(manager, 1*time.Second)
	go runCommandInterface(manager)

	// Pause toggle listener
	go func() {
		for {
			var input string
			fmt.Scanln(&input)
			if strings.TrimSpace(strings.ToLower(input)) == "p" {
				togglePause()
			}
		}
	}()

	fmt.Println("Wiz monitor started. Press Ctrl+C to exit.")
	select {} // Block forever
}
