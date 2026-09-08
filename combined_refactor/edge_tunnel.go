package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	defaultEdgeTestTarget = "http://speed.cloudflare.com/__down?bytes=1024"
	edgeTestTimeout       = 25 * time.Second
)

type edgeTestResult struct {
	IP        string `json:"ip"`
	Host      string `json:"host"`
	Protocol  string `json:"protocol"`
	TargetURL string `json:"targetURL"`
	Status    int    `json:"status"`
	LatencyMS int64  `json:"latencyMs"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
}

type edgeWebsocketConn struct {
	ws               *websocket.Conn
	readMu           sync.Mutex
	writeMu          sync.Mutex
	reader           io.Reader
	stripVLESSHeader bool
	vlessHeaderRead  bool
	closeOne         sync.Once
}

func (c *edgeWebsocketConn) readRaw(p []byte) (int, error) {
	for {
		if c.reader != nil {
			n, err := c.reader.Read(p)
			if n > 0 {
				if err == io.EOF {
					c.reader = nil
				}
				return n, nil
			}
			if err != nil {
				c.reader = nil
				if err != io.EOF {
					return 0, err
				}
			}
		}
		messageType, reader, err := c.ws.NextReader()
		if err != nil {
			return 0, err
		}
		if messageType != websocket.BinaryMessage && messageType != websocket.TextMessage {
			continue
		}
		c.reader = reader
	}
}

func (c *edgeWebsocketConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.stripVLESSHeader && !c.vlessHeaderRead {
		var header [2]byte
		if _, err := io.ReadFull(&edgeRawReader{conn: c}, header[:]); err != nil {
			return 0, err
		}
		if header[0] != 1 {
			return 0, fmt.Errorf("VLESS 响应版本无效")
		}
		c.vlessHeaderRead = true
	}
	return c.readRaw(p)
}

type edgeRawReader struct{ conn *edgeWebsocketConn }

func (r *edgeRawReader) Read(p []byte) (int, error) { return r.conn.readRaw(p) }

func (c *edgeWebsocketConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.ws.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *edgeWebsocketConn) Close() error {
	var err error
	c.closeOne.Do(func() { err = c.ws.Close() })
	return err
}

func (c *edgeWebsocketConn) LocalAddr() net.Addr                { return edgeAddr("local") }
func (c *edgeWebsocketConn) RemoteAddr() net.Addr               { return edgeAddr("edge") }
func (c *edgeWebsocketConn) SetDeadline(t time.Time) error      { return c.ws.SetReadDeadline(t) }
func (c *edgeWebsocketConn) SetReadDeadline(t time.Time) error  { return c.ws.SetReadDeadline(t) }
func (c *edgeWebsocketConn) SetWriteDeadline(t time.Time) error { return c.ws.SetWriteDeadline(t) }

type edgeAddr string

func (a edgeAddr) Network() string { return "tcp" }
func (a edgeAddr) String() string  { return string(a) }

func normalizeEdgePath(raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "/", "", nil
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Path == "" {
			return "", "", fmt.Errorf("WS Path 无效")
		}
		return parsed.EscapedPath(), parsed.RawQuery, nil
	}
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("WS Path 无效")
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	return path, parsed.RawQuery, nil
}

func targetAddress(target *url.URL) (string, int, error) {
	host := target.Hostname()
	if host == "" {
		return "", 0, fmt.Errorf("目标 URL 缺少主机名")
	}
	port := 80
	if target.Scheme == "https" {
		port = 443
	}
	if target.Port() != "" {
		parsed, err := strconv.Atoi(target.Port())
		if err != nil || parsed < 1 || parsed > 65535 {
			return "", 0, fmt.Errorf("目标端口无效")
		}
		port = parsed
	}
	return host, port, nil
}

func buildVLESSRequest(uuid, host string, port int) ([]byte, error) {
	clean := strings.ReplaceAll(strings.TrimSpace(uuid), "-", "")
	if len(clean) != 32 {
		return nil, fmt.Errorf("VLESS UUID 格式无效")
	}
	identity, err := hex.DecodeString(clean)
	if err != nil || len(identity) != 16 {
		return nil, fmt.Errorf("VLESS UUID 格式无效")
	}
	hostBytes := []byte(host)
	if len(hostBytes) > 255 {
		return nil, fmt.Errorf("目标主机名过长")
	}
	addressType := byte(2)
	address := hostBytes
	if parsedIP := net.ParseIP(host); parsedIP != nil {
		if v4 := parsedIP.To4(); v4 != nil {
			addressType = 1
			address = v4
		} else {
			addressType = 3
			address = parsedIP.To16()
		}
	}
	packet := make([]byte, 0, 24+len(address))
	packet = append(packet, 1)
	packet = append(packet, identity...)
	packet = append(packet, 0, 1, byte(port>>8), byte(port), addressType)
	if addressType == 2 {
		packet = append(packet, byte(len(address)))
	}
	packet = append(packet, address...)
	return packet, nil
}

func buildTrojanRequest(password, host string, port int) ([]byte, error) {
	password = strings.TrimSpace(password)
	if password == "" {
		return nil, fmt.Errorf("Trojan 密码不能为空")
	}
	hostBytes := []byte(host)
	if len(hostBytes) > 255 {
		return nil, fmt.Errorf("目标主机名过长")
	}
	hash := sha256.New224()
	_, _ = hash.Write([]byte(password))
	packet := make([]byte, 0, 64+len(hostBytes))
	packet = append(packet, []byte(hex.EncodeToString(hash.Sum(nil)))...)
	packet = append(packet, '\r', '\n', 1, 3, byte(len(hostBytes)))
	packet = append(packet, hostBytes...)
	packet = append(packet, byte(port>>8), byte(port), 0)
	return packet, nil
}

func openEdgeTunnel(ctx context.Context, ip, host string, port int, protocol, credential, path, query string, targetHost string, targetPort int) (net.Conn, int, error) {
	dialer := websocket.Dialer{
		HandshakeTimeout:  12 * time.Second,
		EnableCompression: false,
		TLSClientConfig:   &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
	}
	dialer.NetDialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: 8 * time.Second}
		return d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	}
	wsURL := url.URL{Scheme: "wss", Host: net.JoinHostPort(host, strconv.Itoa(port)), Path: path, RawQuery: query}
	ws, response, err := dialer.DialContext(ctx, wsURL.String(), nil)
	status := 0
	if response != nil {
		status = response.StatusCode
	}
	if err != nil {
		bodyText := ""
		if response != nil && response.Body != nil {
			body, _ := io.ReadAll(io.LimitReader(response.Body, 512))
			bodyText = strings.TrimSpace(string(body))
		}
		if status > 0 {
			if bodyText != "" {
				return nil, status, fmt.Errorf("WebSocket 握手失败（HTTP %d）: %s", status, bodyText)
			}
			return nil, status, fmt.Errorf("WebSocket 握手失败（HTTP %d）: %w", status, err)
		}
		return nil, status, fmt.Errorf("WebSocket 握手失败: %w", err)
	}
	conn := &edgeWebsocketConn{ws: ws, stripVLESSHeader: strings.EqualFold(protocol, "vless")}
	var packet []byte
	if strings.EqualFold(protocol, "vless") {
		packet, err = buildVLESSRequest(credential, targetHost, targetPort)
	} else {
		packet, err = buildTrojanRequest(credential, targetHost, targetPort)
	}
	if err != nil {
		_ = conn.Close()
		return nil, status, err
	}
	if _, err := conn.Write(packet); err != nil {
		_ = conn.Close()
		return nil, status, fmt.Errorf("发送 %s 首包失败: %w", protocol, err)
	}
	return conn, status, nil
}

func runEdgeTunnelRequest(ctx context.Context, params startEdgeTestRequest) edgeTestResult {
	result := edgeTestResult{IP: strings.TrimSpace(params.IP), Host: strings.TrimSpace(params.Host), Protocol: strings.ToLower(strings.TrimSpace(params.Protocol)), TargetURL: strings.TrimSpace(params.TargetURL)}
	if result.Protocol != "vless" && result.Protocol != "trojan" {
		result.Error = "协议必须是 VLESS 或 Trojan"
		return result
	}
	if result.IP == "" || result.Host == "" {
		result.Error = "候选 IP 和 EdgeTunnel 域名不能为空"
		return result
	}
	if params.Port <= 0 {
		params.Port = 443
	}
	if params.Port > 65535 {
		result.Error = "EdgeTunnel 端口无效"
		return result
	}
	if result.TargetURL == "" {
		result.TargetURL = defaultEdgeTestTarget
	}
	target, err := url.Parse(result.TargetURL)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" {
		result.Error = "目标 URL 必须是有效的 http/https 地址"
		return result
	}
	targetHost, targetPort, err := targetAddress(target)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	path, query, err := normalizeEdgePath(params.Path)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	testCtx, cancel := context.WithTimeout(ctx, edgeTestTimeout)
	defer cancel()
	start := time.Now()
	transport := &http.Transport{
		DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			conn, _, err := openEdgeTunnel(dialCtx, result.IP, result.Host, params.Port, result.Protocol, params.UUID, path, query, targetHost, targetPort)
			return conn, err
		},
		TLSClientConfig:    &tls.Config{ServerName: targetHost, MinVersion: tls.VersionTLS12},
		DisableCompression: true,
		ForceAttemptHTTP2:  false,
	}
	client := &http.Client{Transport: transport, Timeout: edgeTestTimeout}
	req, err := http.NewRequestWithContext(testCtx, http.MethodGet, result.TargetURL, nil)
	if err != nil {
		result.Error = "目标请求构造失败: " + err.Error()
		return result
	}
	req.Header.Set("User-Agent", "CFData-EdgeTunnel-Test/1.0")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	if err != nil {
		result.LatencyMS = time.Since(start).Milliseconds()
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, 64*1024)
	result.Status = resp.StatusCode
	result.LatencyMS = time.Since(start).Milliseconds()
	result.Success = resp.StatusCode >= 200 && resp.StatusCode < 400
	if !result.Success {
		result.Error = fmt.Sprintf("目标返回 HTTP %d", resp.StatusCode)
	}
	transport.CloseIdleConnections()
	return result
}

func runEdgeTest(ctx context.Context, session *appSession, params startEdgeTestRequest) {
	result := runEdgeTunnelRequest(ctx, params)
	session.sendWSMessage("edge_test_result", result)
}
