package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"gopkg.in/yaml.v3"
)

type GlobalConfig struct {
	DialTimeout        time.Duration
	WSHandshakeTimeout time.Duration
	WSWriteTimeout     time.Duration
	WSReadTimeout      time.Duration
	PingInterval       time.Duration
	ReconnectDelay     time.Duration
	ReadBuf32K         int
	ReadBuf64K         int
}

// FileConfig 表示配置文件的结构
type FileConfig struct {
	ListenAddr       string        `yaml:"listen"`
	ForwardAddr      string        `yaml:"forward"`
	IP               string        `yaml:"ip"`
	UDPBlockPorts    string        `yaml:"udp_block_ports"`
	Token            string        `yaml:"token"`
	ConnectionNum    int           `yaml:"connection_num"`
	Insecure         bool          `yaml:"insecure"`
	IPs              string        `yaml:"ips"`
	DNSServer        string        `yaml:"dns_server"`
	ECHDomain        string        `yaml:"ech_domain"`
	Fallback         bool          `yaml:"fallback"`
	DialTimeout      time.Duration `yaml:"dial_timeout"`
	WSHandTimeout    time.Duration `yaml:"ws_handshake_timeout"`
	WSWriteTimeout   time.Duration `yaml:"ws_write_timeout"`
	WSReadTimeout    time.Duration `yaml:"ws_read_timeout"`
	PingInterval     time.Duration `yaml:"ping_interval"`
	ReconnectDelay   time.Duration `yaml:"reconnect_delay"`
}

var cfg = GlobalConfig{
	DialTimeout:        3 * time.Second,
	WSHandshakeTimeout: 5 * time.Second,
	WSWriteTimeout:     5 * time.Second,
	WSReadTimeout:      10 * time.Second,
	PingInterval:       3 * time.Second,
	ReconnectDelay:     1 * time.Second,
	ReadBuf32K:         32 * 1024,
	ReadBuf64K:         64 * 1024,
}

var buf32kPool = sync.Pool{New: func() any { b := make([]byte, 32*1024); return &b }}
var buf64kPool = sync.Pool{New: func() any { b := make([]byte, 64*1024); return &b }}

var (
	configFile       string
	listenAddr       string
	forwardAddr      string
	ipAddr           string
	udpBlockPortsStr string
	token            string
	connectionNum    int
	insecure         bool
	ips              string
	dnsServer        string
	echDomain        string
	fallback         bool

	echListMu sync.RWMutex
	echList   []byte
	refreshMu sync.Mutex

	echPool *ECHPool

	clientID      string
	udpBlockPorts map[int]struct{}

	ipStrategy byte
)

const (
	IPStrategyDefault  byte = 0
	IPStrategyIPv4Only byte = 1
	IPStrategyIPv6Only byte = 2
	IPStrategyPv4Pv6   byte = 3
	IPStrategyPv6Pv4   byte = 4
)

func init() {
	flag.StringVar(&configFile, "config", "", "配置文件路径 (YAML格式)")
	flag.StringVar(&listenAddr, "l", "", "SOCKS5监听地址 (格式: socks5://[user:pass@]0.0.0.0:1080)")
	flag.StringVar(&forwardAddr, "f", "", "服务地址 (格式: wss://host:port/path)")
	flag.StringVar(&ipAddr, "ip", "", "指定连接的IP地址（多个用逗号分隔）")
	flag.StringVar(&udpBlockPortsStr, "block", "443", "拦截的UDP端口列表，逗号分隔")
	flag.BoolVar(&insecure, "insecure", false, "忽略证书校验")
	flag.StringVar(&token, "token", "", "身份验证令牌")
	flag.StringVar(&dnsServer, "dns", "https://doh.pub/dns-query", "ECH查询DNS服务器")
	flag.StringVar(&echDomain, "ech", "cloudflare-ech.com", "ECH公钥查询域名")
	flag.BoolVar(&fallback, "fallback", false, "禁用ECH回落到TLS 1.3")
	flag.IntVar(&connectionNum, "n", 3, "每个IP的WebSocket连接数")
	flag.StringVar(&ips, "ips", "", "服务端IP解析偏好 (4/6/4,6/6,4)")
}

// loadConfigFromFile 从配置文件读取配置，并应用到全局变量
// 参数优先级: 命令行参数 > 配置文件 > 程序默认值
func loadConfigFromFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("无法读取文件: %w", err)
	}

	var fileConfig FileConfig
	if err := yaml.Unmarshal(data, &fileConfig); err != nil {
		return fmt.Errorf("YAML解析失败: %w", err)
	}

	// 获取命令行中实际设置的参数
	commandLineSet := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		commandLineSet[f.Name] = true
	})

	// 只有当命令行中未设置该参数时，才使用配置文件中的值
	
	if !commandLineSet["l"] && fileConfig.ListenAddr != "" {
		listenAddr = fileConfig.ListenAddr
	}

	if !commandLineSet["f"] && fileConfig.ForwardAddr != "" {
		forwardAddr = fileConfig.ForwardAddr
	}

	if !commandLineSet["ip"] && fileConfig.IP != "" {
		ipAddr = fileConfig.IP
	}

	if !commandLineSet["block"] && fileConfig.UDPBlockPorts != "" {
		udpBlockPortsStr = fileConfig.UDPBlockPorts
	}

	if !commandLineSet["token"] && fileConfig.Token != "" {
		token = fileConfig.Token
	}

	if !commandLineSet["n"] && fileConfig.ConnectionNum != 0 {
		connectionNum = fileConfig.ConnectionNum
	}

	if !commandLineSet["insecure"] && fileConfig.Insecure {
		insecure = fileConfig.Insecure
	}

	if !commandLineSet["ips"] && fileConfig.IPs != "" {
		ips = fileConfig.IPs
	}

	if !commandLineSet["dns"] && fileConfig.DNSServer != "" {
		dnsServer = fileConfig.DNSServer
	}

	if !commandLineSet["ech"] && fileConfig.ECHDomain != "" {
		echDomain = fileConfig.ECHDomain
	}

	if !commandLineSet["fallback"] && fileConfig.Fallback {
		fallback = fileConfig.Fallback
	}

	// 应用全局配置中的超时设置（这些参数没有命令行选项）
	if fileConfig.DialTimeout > 0 {
		cfg.DialTimeout = fileConfig.DialTimeout
	}

	if fileConfig.WSHandTimeout > 0 {
		cfg.WSHandshakeTimeout = fileConfig.WSHandTimeout
	}

	if fileConfig.WSWriteTimeout > 0 {
		cfg.WSWriteTimeout = fileConfig.WSWriteTimeout
	}

	if fileConfig.WSReadTimeout > 0 {
		cfg.WSReadTimeout = fileConfig.WSReadTimeout
	}

	if fileConfig.PingInterval > 0 {
		cfg.PingInterval = fileConfig.PingInterval
	}

	if fileConfig.ReconnectDelay > 0 {
		cfg.ReconnectDelay = fileConfig.ReconnectDelay
	}

	log.Printf("[客户端] 配置文件加载成功: %s", filePath)
	return nil
}

func main() {
	flag.Parse()

	// 如果指定了配置文件，先从配置文件读取
	if configFile != "" {
		if err := loadConfigFromFile(configFile); err != nil {
			log.Fatalf("[客户端] 读取配置文件失败: %v", err)
		}
	}

	if listenAddr == "" || forwardAddr == "" {
		flag.Usage()
		return
	}

	ipStrategy = parseIPStrategy(ips)
	if ips != "" {
		log.Printf("[客户端] IP策略: %s (code: %d)", ips, ipStrategy)
	}

	var targetIPs []string
	if ipAddr != "" {
		parts := strings.Split(ipAddr, ",")
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" {
				targetIPs = append(targetIPs, trimmed)
			}
		}
	}

	forwardURL, err := url.Parse(forwardAddr)
	if err != nil {
		log.Fatalf("[客户端] 无效的服务地址: %v", err)
	}

	if !strings.EqualFold(forwardURL.Scheme, "wss") {
		log.Fatalf("[客户端] 仅支持 wss:// 协议 (当前: %s)", forwardURL.Scheme)
	}

	if insecure {
		if !fallback {
			fallback = true
			log.Printf("[客户端] insecure模式：已自动禁用ECH")
		}
	}

	if !fallback {
		if err := prepareECH(); err != nil {
			log.Fatalf("[客户端] 获取ECH公钥失败: %v", err)
		}
	} else {
		log.Printf("[客户端] fallback模式：使用标准TLS 1.3")
	}

	if udpBlockPortsStr != "" {
		udpBlockPorts = make(map[int]struct{})
		parts := strings.Split(udpBlockPortsStr, ",")
		for _, p := range parts {
			pp := strings.TrimSpace(p)
			if pp == "" {
				continue
			}
			var port int
			_, _ = fmt.Sscanf(pp, "%d", &port)
			if port > 0 && port < 65536 {
				udpBlockPorts[port] = struct{}{}
			}
		}
	}

	clientID = uuid.NewString()
	log.Printf("[客户端] 客户端ID: %s", clientID)

	echPool = NewECHPool(forwardAddr, connectionNum, targetIPs, clientID)
	echPool.Start()

	runSOCKS5Listener(listenAddr)
}

func parseIPStrategy(s string) byte {
	s = strings.ReplaceAll(strings.TrimSpace(s), " ", "")
	switch s {
	case "4":
		return IPStrategyIPv4Only
	case "6":
		return IPStrategyIPv6Only
	case "4,6":
		return IPStrategyPv4Pv6
	case "6,4":
		return IPStrategyPv6Pv4
	default:
		return IPStrategyDefault
	}
}

func isNormalCloseError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var ce *websocket.CloseError
	if errors.As(err, &ce) {
		switch ce.Code {
		case websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseNoStatusReceived:
			return true
		}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return false
}

type MessageType uint8

const (
	MsgTCPConnect MessageType = iota + 1
	MsgTCPData
	MsgTCPClose
	MsgUDPConnect
	MsgUDPData
	MsgUDPClose
	MsgConnStatus
	MsgUplink
	MsgSelectDownlink
)

type ConnStatus uint8

const (
	StatusOK  ConnStatus = 0
	StatusERR ConnStatus = 1
)

const headerLen = 8

func encodeMessage(t MessageType, connID string, meta, payload []byte) []byte {
	if len(connID) > 255 {
		connID = connID[:255]
	}
	buf := make([]byte, headerLen+len(connID)+len(meta)+len(payload))
	buf[0] = byte(t)
	buf[1] = byte(len(connID))
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(meta)))
	binary.BigEndian.PutUint32(buf[4:8], uint32(len(payload)))
	off := headerLen
	copy(buf[off:], connID)
	off += len(connID)
	copy(buf[off:], meta)
	off += len(meta)
	copy(buf[off:], payload)
	return buf
}

func decodeMessage(b []byte) (t MessageType, connID string, meta, payload []byte, err error) {
	if len(b) < headerLen {
		return 0, "", nil, nil, errors.New("frame too short")
	}
	t = MessageType(b[0])
	idLen := int(b[1])
	metaLen := int(binary.BigEndian.Uint16(b[2:4]))
	payloadLen := int(binary.BigEndian.Uint32(b[4:8]))
	total := headerLen + idLen + metaLen + payloadLen
	if idLen < 0 || metaLen < 0 || payloadLen < 0 || total < headerLen || total > len(b) {
		return 0, "", nil, nil, errors.New("invalid length")
	}
	off := headerLen
	connID = string(b[off : off+idLen])
	off += idLen
	meta = b[off : off+metaLen]
	off += metaLen
	payload = b[off : off+payloadLen]
	return t, connID, meta, payload, nil
}

const typeHTTPS = 65

func prepareECH() error {
	for {
		log.Printf("[客户端] DNS查询ECH: %s -> %s", dnsServer, echDomain)
		echBase64, err := queryHTTPSRecord(echDomain, dnsServer)
		if err != nil {
			log.Printf("[客户端] DNS查询失败: %v，重试...", err)
			time.Sleep(2 * time.Second)
			continue
		}
		if echBase64 == "" {
			log.Printf("[客户端] 未找到ECH参数，重试...")
			time.Sleep(2 * time.Second)
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(echBase64)
		if err != nil {
			log.Printf("[客户端] ECH Base64解码失败: %v，重试...", err)
			time.Sleep(2 * time.Second)
			continue
		}
		echListMu.Lock()
		echList = raw
		echListMu.Unlock()
		log.Printf("[客户端] ECHConfigList长度: %d字节", len(raw))
		return nil
	}
}

func refreshECH() error {
	if fallback {
		return nil
	}
	refreshMu.Lock()
	defer refreshMu.Unlock()
	log.Printf("[客户端] 刷新ECH配置...")
	return prepareECH()
}

func getECHList() ([]byte, error) {
	if fallback {
		return nil, nil
	}
	echListMu.RLock()
	defer echListMu.RUnlock()
	if len(echList) == 0 {
		return nil, errors.New("ECH配置尚未加载")
	}
	return echList, nil
}

func buildTLSConfigWithECH(serverName string, echList []byte) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:                     tls.VersionTLS13,
		ServerName:                     serverName,
		EncryptedClientHelloConfigList: echList,
		EncryptedClientHelloRejectionVerify: func(cs tls.ConnectionState) error {
			return errors.New("ECH rejected")
		},
		RootCAs: roots,
	}, nil
}

func buildStandardTLSConfig(serverName string) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         serverName,
		RootCAs:            roots,
		InsecureSkipVerify: insecure,
	}, nil
}

func buildUnifiedTLSConfig(serverName string) (*tls.Config, error) {
	if fallback {
		return buildStandardTLSConfig(serverName)
	}
	ech, e := getECHList()
	if e != nil {
		return nil, e
	}
	cfgTLS, err := buildTLSConfigWithECH(serverName, ech)
	if err != nil {
		return nil, err
	}
	cfgTLS.InsecureSkipVerify = insecure
	return cfgTLS, nil
}

func queryHTTPSRecord(domain, dnsServer string) (string, error) {
	if strings.HasPrefix(dnsServer, "http://") || strings.HasPrefix(dnsServer, "https://") {
		return queryDoH(domain, dnsServer)
	}
	return queryDNSUDP(domain, dnsServer)
}

func queryDNSUDP(domain, dnsServer string) (string, error) {
	if !strings.Contains(dnsServer, ":") {
		dnsServer = dnsServer + ":53"
	}
	query := buildDNSQuery(domain, typeHTTPS)
	conn, err := net.Dial("udp", dnsServer)
	if err != nil {
		return "", fmt.Errorf("connect DNS failed: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = conn.Write(query); err != nil {
		return "", fmt.Errorf("send query failed: %v", err)
	}
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "", fmt.Errorf("DNS query timeout")
		}
		return "", fmt.Errorf("read DNS response failed: %v", err)
	}
	return parseDNSResponse(response[:n])
}

func queryDoH(domain, dohURL string) (string, error) {
	u, err := url.Parse(dohURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	dnsQuery := buildDNSQuery(domain, typeHTTPS)
	dnsBase64 := base64.RawURLEncoding.EncodeToString(dnsQuery)
	q.Set("dns", dnsBase64)
	u.RawQuery = q.Encode()
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DoH status: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return parseDNSResponse(body)
}

func buildDNSQuery(domain string, qtype uint16) []byte {
	query := make([]byte, 0, 512)
	query = append(query, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, label := range strings.Split(domain, ".") {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0x00)
	query = append(query, byte(qtype>>8), byte(qtype), 0x00, 0x01)
	return query
}

func parseDNSResponse(response []byte) (string, error) {
	if len(response) < 12 {
		return "", fmt.Errorf("response too short")
	}
	ancount := binary.BigEndian.Uint16(response[6:8])
	if ancount == 0 {
		return "", fmt.Errorf("no answer")
	}
	offset := 12
	for offset < len(response) && response[offset] != 0 {
		offset += int(response[offset]) + 1
	}
	offset += 5
	for i := 0; i < int(ancount); i++ {
		if offset >= len(response) {
			break
		}
		if response[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(response) && response[offset] != 0 {
				offset += int(response[offset]) + 1
			}
			offset++
		}
		if offset+10 > len(response) {
			break
		}
		rrType := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 8
		dataLen := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2
		if offset+int(dataLen) > len(response) {
			break
		}
		data := response[offset : offset+int(dataLen)]
		offset += int(dataLen)
		if rrType == typeHTTPS {
			if ech := parseHTTPSRecord(data); ech != "" {
				return ech, nil
			}
		}
	}
	return "", nil
}

func parseHTTPSRecord(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	offset := 2
	if offset < len(data) && data[offset] == 0 {
		offset++
	} else {
		for offset < len(data) && data[offset] != 0 {
			offset += int(data[offset]) + 1
		}
		offset++
	}
	for offset+4 <= len(data) {
		key := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		if offset+int(length) > len(data) {
			break
		}
		value := data[offset : offset+int(length)]
		offset += int(length)
		if key == 5 {
			return base64.StdEncoding.EncodeToString(value)
		}
	}
	return ""
}

type WriteJob struct {
	msgType int
	data    []byte
	size    int
}

type ClientConnState struct {
	reqType    string
	tcpConn    net.Conn
	udpAssoc   *UDPAssociation
	uplink     int
	downlink   int
	lastCh     int
	start      time.Time
	target     string
	connected  chan bool
	clientAddr string
	closed     bool
}

type ECHPool struct {
	globalQueueBytes int64
	globalQueueLimit int64
	nextChannel      uint64

	wsServerAddr  string
	connectionNum int
	targetIPs     []string
	clientID      string

	wsConnsMu   sync.RWMutex
	wsConns     []*websocket.Conn
	writeQueues []chan WriteJob

	mu    sync.RWMutex
	conns map[string]*ClientConnState
}

func (p *ECHPool) chIndex(chID int) (int, error) {
	idx := chID - 1
	if idx < 0 || idx >= len(p.writeQueues) {
		return -1, fmt.Errorf("invalid channel %d", chID)
	}
	return idx, nil
}

func NewECHPool(addr string, n int, ips []string, clientID string) *ECHPool {
	total := n
	if len(ips) > 0 {
		total = len(ips) * n
	}
	p := &ECHPool{
		wsServerAddr:     addr,
		connectionNum:    n,
		targetIPs:        ips,
		clientID:         clientID,
		wsConns:          make([]*websocket.Conn, total),
		writeQueues:      make([]chan WriteJob, total),
		conns:            make(map[string]*ClientConnState),
		globalQueueLimit: 0,
	}
	for i := 0; i < total; i++ {
		p.writeQueues[i] = make(chan WriteJob, 4096)
	}
	p.globalQueueLimit = int64(cfg.ReadBuf64K) * 512
	return p
}

func (p *ECHPool) Start() {
	for i := 0; i < len(p.writeQueues); i++ {
		ip := ""
		if len(p.targetIPs) > 0 {
			if idx := i / p.connectionNum; idx < len(p.targetIPs) {
				ip = p.targetIPs[idx]
			}
		}
		go p.dialAndServe(i, ip)
	}
}

func (p *ECHPool) dialAndServe(idx int, ip string) {
	chID := idx + 1
	for {
		wsConn, err := dialWebSocketWithECH(p.wsServerAddr, 3, ip, p.clientID)
		if err != nil {
			log.Printf("[客户端] 通道%d (IP:%s) 连接失败: %v", chID, ip, err)
			time.Sleep(3 * time.Second)
			continue
		}
		p.wsConnsMu.Lock()
		p.wsConns[idx] = wsConn
		p.wsConnsMu.Unlock()
		log.Printf("[客户端] 通道%d (IP:%s) 就绪", chID, ip)

		ctx, cancel := context.WithCancel(context.Background())
		go p.writeWorker(ctx, idx, wsConn)
		p.handleChannel(chID, wsConn)
		cancel()
		_ = wsConn.Close()

		p.wsConnsMu.Lock()
		p.wsConns[idx] = nil
		p.wsConnsMu.Unlock()
		p.cleanupChannel(chID)
		log.Printf("[客户端] 通道%d 断开，重连中...", chID)
		time.Sleep(cfg.ReconnectDelay)
	}
}

func (p *ECHPool) writeWorker(ctx context.Context, id int, conn *websocket.Conn) {
	queue := p.writeQueues[id]
	ticker := time.NewTicker(cfg.PingInterval)
	defer ticker.Stop()
	defer func() {
		for {
			select {
			case j := <-queue:
				atomic.AddInt64(&p.globalQueueBytes, int64(-j.size))
			default:
				return
			}
		}
	}()
	var pending *WriteJob
	for {
		var job WriteJob
		if pending != nil {
			job = *pending
			pending = nil
		} else {
			select {
			case <-ctx.Done():
				return
			case job = <-queue:
			case <-ticker.C:
				_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				if err := conn.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
					_ = conn.Close()
					return
				}
				continue
			}
		}
		atomic.AddInt64(&p.globalQueueBytes, int64(-job.size))
		if job.msgType != websocket.BinaryMessage {
			_ = conn.SetWriteDeadline(time.Now().Add(cfg.WSWriteTimeout))
			if err := conn.WriteMessage(job.msgType, job.data); err != nil {
				_ = conn.Close()
				return
			}
			_ = conn.SetWriteDeadline(time.Time{})
			continue
		}
		t, connID, meta, payload, err := decodeMessage(job.data)
		if err != nil || t != MsgTCPData {
			_ = conn.SetWriteDeadline(time.Now().Add(cfg.WSWriteTimeout))
			if err := conn.WriteMessage(job.msgType, job.data); err != nil {
				_ = conn.Close()
				return
			}
			_ = conn.SetWriteDeadline(time.Time{})
			continue
		}
		maxAgg := cfg.ReadBuf64K * 4
		total := len(payload)
		var parts [][]byte
		parts = append(parts, payload)
		for {
			select {
			case next := <-queue:
				atomic.AddInt64(&p.globalQueueBytes, int64(-next.size))
				if next.msgType != websocket.BinaryMessage {
					pending = &next
					goto writeAgg
				}
				tt, cid, mm, pl, e := decodeMessage(next.data)
				if e != nil || tt != MsgTCPData || cid != connID || len(mm) != 0 {
					pending = &next
					goto writeAgg
				}
				if total+len(pl) > maxAgg {
					pending = &next
					goto writeAgg
				}
				parts = append(parts, pl)
				total += len(pl)
			default:
				goto writeAgg
			}
		}
	writeAgg:
		var merged []byte
		if len(parts) == 1 {
			merged = parts[0]
		} else {
			merged = make([]byte, total)
			off := 0
			for _, p0 := range parts {
				copy(merged[off:], p0)
				off += len(p0)
			}
		}
		_ = conn.SetWriteDeadline(time.Now().Add(cfg.WSWriteTimeout))
		if err := conn.WriteMessage(websocket.BinaryMessage, encodeMessage(MsgTCPData, connID, meta, merged)); err != nil {
			_ = conn.Close()
			return
		}
		_ = conn.SetWriteDeadline(time.Time{})
	}
}

func (p *ECHPool) asyncWriteDirect(chID int, msgType int, data []byte) error {
	idx, err := p.chIndex(chID)
	if err != nil {
		return err
	}
	size := int64(len(data))
	if atomic.AddInt64(&p.globalQueueBytes, size) > p.globalQueueLimit {
		atomic.AddInt64(&p.globalQueueBytes, -size)
		return fmt.Errorf("queue limit exceeded")
	}
	select {
	case p.writeQueues[idx] <- WriteJob{msgType, data, int(size)}:
		return nil
	default:
		timer := time.NewTimer(100 * time.Millisecond)
		defer timer.Stop()
		select {
		case p.writeQueues[idx] <- WriteJob{msgType, data, int(size)}:
			return nil
		case <-timer.C:
			atomic.AddInt64(&p.globalQueueBytes, -size)
			return fmt.Errorf("channel %d congested", chID)
		}
	}
}

func shortID(id string) string {
	if len(id) >= 8 {
		return id[:8]
	}
	return id
}

func (p *ECHPool) broadcastWrite(msgType int, data []byte) {
	p.wsConnsMu.RLock()
	sent := false
	for i, c := range p.wsConns {
		if c == nil {
			continue
		}
		_ = p.asyncWriteDirect(i+1, msgType, data)
		sent = true
	}
	p.wsConnsMu.RUnlock()
	if sent {
		return
	}
	idx := int(atomic.AddUint64(&p.nextChannel, 1)) % len(p.writeQueues)
	_ = p.asyncWriteDirect(idx+1, msgType, data)
}

func (p *ECHPool) noteUplink(connID string, chID int) {
	p.mu.Lock()
	st := p.conns[connID]
	if st == nil {
		p.mu.Unlock()
		return
	}
	if st.uplink == 0 {
		st.uplink = chID
	}
	p.mu.Unlock()
}

func (p *ECHPool) noteLastChannel(connID string, chID int) {
	p.mu.Lock()
	st := p.conns[connID]
	if st != nil {
		st.lastCh = chID
	}
	p.mu.Unlock()
}

func (p *ECHPool) GetUplinkChannel(connID string) (int, bool) {
	p.mu.RLock()
	st := p.conns[connID]
	p.mu.RUnlock()
	if st == nil || st.uplink == 0 {
		return 0, false
	}
	return st.uplink, true
}

func (p *ECHPool) RegisterAndBroadcastTCP(connID, target string, first []byte, tcpConn net.Conn, reqType string) {
	p.mu.Lock()
	st := p.conns[connID]
	if st == nil {
		st = &ClientConnState{}
		p.conns[connID] = st
	}
	st.tcpConn = tcpConn
	st.target = target
	st.connected = make(chan bool, 1)
	st.start = time.Now()
	if reqType != "" {
		st.reqType = reqType
	}
	if tcpConn != nil {
		if ra := tcpConn.RemoteAddr(); ra != nil {
			st.clientAddr = ra.String()
		}
	}
	st.uplink = 0
	st.downlink = 0
	p.mu.Unlock()

	meta := make([]byte, 1+len(target))
	meta[0] = ipStrategy
	copy(meta[1:], target)

	msg := encodeMessage(MsgTCPConnect, connID, meta, first)
	p.broadcastWrite(websocket.BinaryMessage, msg)
}

func (p *ECHPool) RegisterUDP(connID string, assoc *UDPAssociation) {
	p.mu.Lock()
	st := p.conns[connID]
	if st == nil {
		st = &ClientConnState{}
		p.conns[connID] = st
	}
	st.udpAssoc = assoc
	if st.connected == nil {
		st.connected = make(chan bool, 1)
	}
	if st.reqType == "" {
		st.reqType = "SOCKS5 UDP"
	}
	if assoc != nil && assoc.tcpConn != nil {
		if ra := assoc.tcpConn.RemoteAddr(); ra != nil {
			st.clientAddr = ra.String()
		}
	}
	p.mu.Unlock()
}

func (p *ECHPool) StartUDPRace(connID, target string) {
	p.mu.Lock()
	st := p.conns[connID]
	if st == nil {
		st = &ClientConnState{}
		p.conns[connID] = st
	}
	st.target = target
	st.start = time.Now()
	st.reqType = "SOCKS5 UDP"
	st.uplink = 0
	st.downlink = 0
	p.mu.Unlock()

	meta := make([]byte, 1+len(target))
	meta[0] = ipStrategy
	copy(meta[1:], target)

	p.broadcastWrite(websocket.BinaryMessage, encodeMessage(MsgUDPConnect, connID, meta, nil))
}

func (p *ECHPool) Unregister(connID string) {
	p.mu.Lock()
	st := p.conns[connID]
	if st == nil {
		p.mu.Unlock()
		return
	}
	if st.closed {
		p.mu.Unlock()
		return
	}
	st.closed = true
	target := st.target
	up, down := st.uplink, st.downlink
	if up == 0 && st.lastCh > 0 {
		up = st.lastCh
	}
	if down == 0 && st.lastCh > 0 {
		down = st.lastCh
	}
	u := "-"
	d := "-"
	if up > 0 {
		u = fmt.Sprintf("%d", up)
	}
	if down > 0 {
		d = fmt.Sprintf("%d", down)
	}
	client := "-"
	typ := st.reqType
	if typ == "" {
		typ = "SOCKS5"
	}
	if st.clientAddr != "" {
		client = st.clientAddr
	}
	if target == "" {
		target = "-"
	}
	log.Printf("[客户端] %s %s 访问: %s, 通道: TX %s RX %s, ID:%s, 已关闭", client, typ, target, u, d, shortID(connID))
	if st.tcpConn != nil {
		_ = st.tcpConn.Close()
	}
	if st.udpAssoc != nil {
		st.udpAssoc.Close()
	}
	delete(p.conns, connID)
	p.mu.Unlock()
}

func (p *ECHPool) handleChannel(chID int, conn *websocket.Conn) {
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(cfg.WSReadTimeout))
		return nil
	})
	_ = conn.SetReadDeadline(time.Now().Add(cfg.WSReadTimeout))
	conn.SetPingHandler(func(m string) error {
		_ = conn.SetReadDeadline(time.Now().Add(cfg.WSReadTimeout))
		return p.asyncWriteDirect(chID, websocket.PongMessage, []byte(m))
	})

	for {
		mt, msg, err := conn.ReadMessage()
		if err != nil {
			if !isNormalCloseError(err) {
				log.Printf("[客户端] 通道%d 异常: %v", chID, err)
			}
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(cfg.WSReadTimeout))

		if mt != websocket.BinaryMessage {
			continue
		}

		mtype, connID, meta, payload, err := decodeMessage(msg)
		if err != nil {
			continue
		}

		p.noteLastChannel(connID, chID)

		switch mtype {
		case MsgUplink:
			p.noteUplink(connID, chID)

		case MsgConnStatus:
			if len(meta) < 1 {
				continue
			}
			if ConnStatus(meta[0]) == StatusOK {
				p.signalConnected(connID)
			} else {
				p.Unregister(connID)
			}

		case MsgTCPData:
			selected, chosen, start, target, up, typ := p.selectDownlink(connID, chID)
			if selected {
				_ = p.asyncWriteDirect(chID, websocket.BinaryMessage, encodeMessage(MsgSelectDownlink, connID, nil, nil))
				if !start.IsZero() && up > 0 {
					if typ == "" {
						typ = "SOCKS5"
					}
					client := "-"
					p.mu.RLock()
					if st := p.conns[connID]; st != nil && st.clientAddr != "" {
						client = st.clientAddr
					}
					p.mu.RUnlock()
					ms := float64(time.Since(start)) / float64(time.Millisecond)
					log.Printf("[客户端] %s %s 访问: %s, 通道: TX %d RX %d, ID:%s, 延迟 %.1f ms", client, typ, target, up, chID, shortID(connID), ms)
				}
			}
			if chosen != chID {
				continue
			}
			p.mu.RLock()
			var c net.Conn
			if st := p.conns[connID]; st != nil {
				c = st.tcpConn
			}
			p.mu.RUnlock()
			if c != nil {
				_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if _, err := c.Write(payload); err != nil {
					_ = p.SendCloseDirect(chID, connID)
					_ = c.Close()
				}
				_ = c.SetWriteDeadline(time.Time{})
			} else {
				_ = p.SendCloseDirect(chID, connID)
			}

		case MsgTCPClose:
			p.noteUplink(connID, chID)
			var c net.Conn
			p.mu.RLock()
			if st := p.conns[connID]; st != nil {
				c = st.tcpConn
			}
			p.mu.RUnlock()
			if c != nil {
				_ = c.Close()
			}
			p.Unregister(connID)

		case MsgUDPData:
			selected, chosen, start, target, up, typ := p.selectDownlink(connID, chID)
			if selected {
				_ = p.asyncWriteDirect(chID, websocket.BinaryMessage, encodeMessage(MsgSelectDownlink, connID, nil, nil))
				if !start.IsZero() && up > 0 {
					if typ == "" {
						typ = "SOCKS5 UDP"
					}
					client := "-"
					p.mu.RLock()
					if st := p.conns[connID]; st != nil && st.clientAddr != "" {
						client = st.clientAddr
					}
					p.mu.RUnlock()
					ms := float64(time.Since(start)) / float64(time.Millisecond)
					log.Printf("[客户端] %s %s 访问: %s, 通道: TX %d RX %d, ID:%s, 延迟 %.1f ms", client, typ, target, up, chID, shortID(connID), ms)
				}
			}
			if chosen != chID {
				continue
			}
			p.mu.RLock()
			var assoc *UDPAssociation
			if st := p.conns[connID]; st != nil {
				assoc = st.udpAssoc
			}
			p.mu.RUnlock()
			if assoc != nil {
				assoc.handleUDPResponse(string(meta), payload)
			}

		case MsgUDPClose:
			p.noteUplink(connID, chID)
			p.mu.RLock()
			var assoc *UDPAssociation
			if st := p.conns[connID]; st != nil {
				assoc = st.udpAssoc
			}
			p.mu.RUnlock()
			if assoc != nil {
				assoc.Close()
			} else {
				p.Unregister(connID)
			}
		}
	}
}

func (p *ECHPool) selectDownlink(connID string, chID int) (selected bool, chosen int, start time.Time, target string, uplink int, typ string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.conns[connID]
	if st == nil || st.target == "" {
		return
	}
	if st.downlink > 0 {
		chosen = st.downlink
		selected = false
	} else {
		st.downlink = chID
		chosen = chID
		selected = true
		start = st.start
	}
	target = st.target
	uplink = -1
	if st.uplink > 0 {
		uplink = st.uplink
	}
	typ = st.reqType
	return
}

func (p *ECHPool) signalConnected(id string) {
	p.mu.RLock()
	st := p.conns[id]
	var ch chan bool
	if st != nil {
		ch = st.connected
	}
	p.mu.RUnlock()
	if ch != nil {
		select {
		case ch <- true:
		default:
		}
	}
}

func (p *ECHPool) SendDataDirect(chID int, connID string, b []byte) error {
	return p.asyncWriteDirect(chID, websocket.BinaryMessage, encodeMessage(MsgTCPData, connID, nil, b))
}

func (p *ECHPool) SendCloseDirect(chID int, connID string) error {
	return p.asyncWriteDirect(chID, websocket.BinaryMessage, encodeMessage(MsgTCPClose, connID, nil, nil))
}

func (p *ECHPool) SendUDPDataDirect(chID int, connID string, data []byte) error {
	return p.asyncWriteDirect(chID, websocket.BinaryMessage, encodeMessage(MsgUDPData, connID, nil, data))
}

func (p *ECHPool) SendUDPCloseDirect(chID int, connID string) {
	_ = p.asyncWriteDirect(chID, websocket.BinaryMessage, encodeMessage(MsgUDPClose, connID, nil, nil))
	p.Unregister(connID)
}

func (p *ECHPool) cleanupChannel(chID int) {
	p.mu.Lock()
	var toClose []string
	for id, st := range p.conns {
		if st.uplink == chID || st.downlink == chID {
			toClose = append(toClose, id)
		}
	}
	p.mu.Unlock()
	for _, id := range toClose {
		p.mu.RLock()
		st := p.conns[id]
		p.mu.RUnlock()
		if st == nil {
			continue
		}
		if st.tcpConn != nil {
			_ = st.tcpConn.Close()
		}
		if st.udpAssoc != nil {
			st.udpAssoc.Close()
		}
		p.Unregister(id)
	}
}

func dialWebSocketWithECH(addr string, retries int, ip string, clientID string) (*websocket.Conn, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(u.Scheme, "wss") {
		return nil, fmt.Errorf("only wss:// supported (got: %s)", u.Scheme)
	}

	dialURL := *u
	q := dialURL.Query()
	if clientID != "" {
		q.Set("client_id", clientID)
	}
	dialURL.RawQuery = q.Encode()
	dialAddr := dialURL.String()

	serverName := u.Hostname()
	for i := 1; i <= retries; i++ {
		tlsCfg, e := buildUnifiedTLSConfig(serverName)
		if e != nil {
			if i < retries {
				_ = refreshECH()
				time.Sleep(1 * time.Second)
				continue
			}
			return nil, e
		}

		dialer := websocket.Dialer{
			TLSClientConfig:  tlsCfg,
			HandshakeTimeout: cfg.WSHandshakeTimeout,
			ReadBufferSize:   cfg.ReadBuf64K,
			WriteBufferSize:  cfg.ReadBuf64K,
		}
		if token != "" {
			dialer.Subprotocols = []string{token}
		}
		if ip != "" {
			dialer.NetDial = func(network, address string) (net.Conn, error) {
				_, port, _ := net.SplitHostPort(address)
				return net.DialTimeout(network, net.JoinHostPort(ip, port), cfg.DialTimeout)
			}
		}

		conn, resp, err := dialer.Dial(dialAddr, nil)
		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusUnauthorized {
				return nil, fmt.Errorf("auth failed: token mismatch")
			}
			if !fallback && (strings.Contains(err.Error(), "ECH") || strings.Contains(err.Error(), "ech")) && i < retries {
				_ = refreshECH()
				time.Sleep(1 * time.Second)
				continue
			}
			return nil, err
		}
		return conn, nil
	}
	return nil, fmt.Errorf("connection failed")
}

type ProxyConfig struct {
	Username, Password, Host string
}

type UDPAssociation struct {
	connID        string
	tcpConn       net.Conn
	udpListener   *net.UDPConn
	clientUDPAddr *net.UDPAddr
	pool          *ECHPool

	mu        sync.Mutex
	closed    bool
	done      chan bool
	receiving bool
	channelID int
}

func parseAuthAndAddr(full string) (string, string, string, error) {
	u, p, h := "", "", full
	if strings.Contains(full, "@") {
		parts := strings.SplitN(full, "@", 2)
		if len(parts) != 2 {
			return "", "", "", fmt.Errorf("format error")
		}
		auth := parts[0]
		if strings.Contains(auth, ":") {
			ap := strings.SplitN(auth, ":", 2)
			u, p = ap[0], ap[1]
		}
		h = parts[1]
	}
	return h, u, p, nil
}

func runSOCKS5Listener(addr string) {
	h, u, p, err := parseAuthAndAddr(strings.TrimPrefix(addr, "socks5://"))
	if err != nil {
		log.Fatalf("[客户端] SOCKS5地址解析失败: %v", err)
	}
	l, err := net.Listen("tcp", h)
	if err != nil {
		log.Fatalf("[客户端] SOCKS5监听失败: %v", err)
	}
	log.Printf("[客户端] SOCKS5代理: %s", h)
	cfgp := &ProxyConfig{u, p, h}
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go handleSOCKS5(c, cfgp)
	}
}

func handleSOCKS5(c net.Conn, cfgp *ProxyConfig) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil || buf[0] != 0x05 {
		return
	}
	methods := make([]byte, buf[1])
	_, _ = io.ReadFull(c, methods)
	if cfgp.Username != "" {
		_, _ = c.Write([]byte{0x05, 0x02})
		if err := handleSOCKS5UserPassAuth(c, cfgp); err != nil {
			return
		}
	} else {
		_, _ = c.Write([]byte{0x05, 0x00})
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	var target string
	switch head[3] {
	case 0x01:
		b := make([]byte, 4)
		_, _ = io.ReadFull(c, b)
		target = net.IP(b).String()
	case 0x03:
		b := make([]byte, 1)
		_, _ = io.ReadFull(c, b)
		addr := make([]byte, b[0])
		_, _ = io.ReadFull(c, addr)
		target = string(addr)
	case 0x04:
		b := make([]byte, 16)
		_, _ = io.ReadFull(c, b)
		target = net.IP(b).String()
	}
	pb := make([]byte, 2)
	_, _ = io.ReadFull(c, pb)
	port := int(pb[0])<<8 | int(pb[1])
	target = net.JoinHostPort(target, fmt.Sprintf("%d", port))

	host, _, _ := net.SplitHostPort(target)
	ip := net.ParseIP(host)

	if head[1] == 0x01 {
		if ipStrategy == IPStrategyIPv4Only {
			if head[3] == 0x04 || (ip != nil && ip.To4() == nil) {
				_, _ = c.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				return
			}
		}
		if ipStrategy == IPStrategyIPv6Only {
			if head[3] == 0x01 || (ip != nil && ip.To4() != nil) {
				_, _ = c.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				return
			}
		}
	}

	_ = c.SetDeadline(time.Time{})

	switch head[1] {
	case 0x01:
		handleSOCKS5Connect(c, target)
	case 0x03:
		handleSOCKS5UDP(c, cfgp)
	}
}

func handleSOCKS5UserPassAuth(c net.Conn, cfgp *ProxyConfig) error {
	b := make([]byte, 2)
	_, _ = io.ReadFull(c, b)
	u := make([]byte, b[1])
	_, _ = io.ReadFull(c, u)
	_, _ = io.ReadFull(c, b[:1])
	p := make([]byte, b[0])
	_, _ = io.ReadFull(c, p)
	if string(u) == cfgp.Username && string(p) == cfgp.Password {
		_, _ = c.Write([]byte{0x01, 0x00})
		return nil
	}
	_, _ = c.Write([]byte{0x01, 0x01})
	return errors.New("auth failed")
}

func handleSOCKS5Connect(c net.Conn, target string) {
	connID := uuid.New().String()

	_, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		_ = c.Close()
		return
	}

	echPool.RegisterAndBroadcastTCP(connID, target, nil, c, "SOCKS5")

	bufPtr := buf32kPool.Get().(*[]byte)
	buf := *bufPtr
	defer buf32kPool.Put(bufPtr)

	defer func() {
		if chID, ok := echPool.GetUplinkChannel(connID); ok {
			_ = echPool.SendCloseDirect(chID, connID)
		} else {
			echPool.broadcastWrite(websocket.BinaryMessage, encodeMessage(MsgTCPClose, connID, nil, nil))
		}
		_ = c.Close()
		echPool.Unregister(connID)
	}()

	for {
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		if chID, ok := echPool.GetUplinkChannel(connID); ok {
			if err := echPool.SendDataDirect(chID, connID, buf[:n]); err != nil {
				return
			}
		} else {
			echPool.broadcastWrite(websocket.BinaryMessage, encodeMessage(MsgTCPData, connID, nil, buf[:n]))
		}
	}
}

func handleSOCKS5UDP(c net.Conn, cfgp *ProxyConfig) {
	host, _, _ := net.SplitHostPort(cfgp.Host)
	uAddr, _ := net.ResolveUDPAddr("udp", net.JoinHostPort(host, "0"))
	ul, _ := net.ListenUDP("udp", uAddr)
	defer ul.Close()

	actual := ul.LocalAddr().(*net.UDPAddr)
	resp := []byte{0x05, 0x00, 0x00}
	if ip4 := actual.IP.To4(); ip4 != nil {
		resp = append(resp, 0x01)
		resp = append(resp, ip4...)
	} else {
		resp = append(resp, 0x04)
		resp = append(resp, actual.IP...)
	}
	resp = append(resp, byte(actual.Port>>8), byte(actual.Port))
	_, _ = c.Write(resp)

	connID := uuid.New().String()
	assoc := &UDPAssociation{
		connID:      connID,
		tcpConn:     c,
		udpListener: ul,
		pool:        echPool,
		done:        make(chan bool, 5),
		channelID:   -1,
	}
	echPool.RegisterUDP(connID, assoc)

	go assoc.loop()
	b := make([]byte, 1)
	for {
		if _, err := c.Read(b); err != nil {
			assoc.done <- true
			assoc.Close()
			return
		}
	}
}

func (a *UDPAssociation) loop() {
	bufPtr := buf64kPool.Get().(*[]byte)
	buf := *bufPtr
	defer buf64kPool.Put(bufPtr)

	for {
		n, addr, err := a.udpListener.ReadFromUDP(buf)
		if err != nil {
			a.done <- true
			return
		}
		a.mu.Lock()
		if a.clientUDPAddr == nil {
			a.clientUDPAddr = addr
		} else if a.clientUDPAddr.String() != addr.String() {
			a.mu.Unlock()
			continue
		}
		a.mu.Unlock()

		tgt, data, err := parseSOCKS5UDPPacket(buf[:n])
		if err == nil {
			h, ps, _ := net.SplitHostPort(tgt)
			if ip := net.ParseIP(h); ip != nil {
				if ipStrategy == IPStrategyIPv4Only && ip.To4() == nil {
					continue
				}
				if ipStrategy == IPStrategyIPv6Only && ip.To4() != nil {
					continue
				}
			}
			var prt int
			_, _ = fmt.Sscanf(ps, "%d", &prt)
			if _, ok := udpBlockPorts[prt]; ok {
				continue
			}
			a.send(tgt, data)
		}
	}
}

func (a *UDPAssociation) send(target string, data []byte) {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	needStart := !a.receiving
	if needStart {
		a.receiving = true
	}
	chID := a.channelID
	a.mu.Unlock()

	if needStart {
		a.pool.StartUDPRace(a.connID, target)
	}

	if chID < 0 {
		if id, ok := a.pool.GetUplinkChannel(a.connID); ok {
			a.mu.Lock()
			a.channelID = id
			chID = id
			a.mu.Unlock()
		} else {
			a.pool.broadcastWrite(websocket.BinaryMessage, encodeMessage(MsgUDPData, a.connID, nil, data))
			return
		}
	}
	_ = a.pool.SendUDPDataDirect(chID, a.connID, data)
}

func (a *UDPAssociation) handleUDPResponse(addrStr string, data []byte) {
	host, portStr, _ := net.SplitHostPort(addrStr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	pkt, _ := buildSOCKS5UDPPacket(host, port, data)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.clientUDPAddr != nil {
		_, _ = a.udpListener.WriteToUDP(pkt, a.clientUDPAddr)
	}
}

func (a *UDPAssociation) Close() {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	closedHadReceiving := a.receiving
	chID := a.channelID
	connID := a.connID
	a.closed = true
	a.mu.Unlock()

	if closedHadReceiving {
		if chID >= 0 {
			a.pool.SendUDPCloseDirect(chID, connID)
		} else {
			a.pool.broadcastWrite(websocket.BinaryMessage, encodeMessage(MsgUDPClose, connID, nil, nil))
			a.pool.Unregister(connID)
		}
	} else {
		a.pool.Unregister(connID)
	}
	_ = a.udpListener.Close()
}

func parseSOCKS5UDPPacket(b []byte) (string, []byte, error) {
	if len(b) < 10 || b[2] != 0 {
		return "", nil, errors.New("invalid data")
	}
	off := 4
	var h string
	switch b[3] {
	case 0x01:
		if off+4 > len(b) {
			return "", nil, errors.New("ipv4 too short")
		}
		h = net.IP(b[off : off+4]).String()
		off += 4
	case 0x03:
		if off+1 > len(b) {
			return "", nil, errors.New("domain length missing")
		}
		l := int(b[off])
		off++
		if off+l > len(b) {
			return "", nil, errors.New("domain too short")
		}
		h = string(b[off : off+l])
		off += l
	case 0x04:
		if off+16 > len(b) {
			return "", nil, errors.New("ipv6 too short")
		}
		h = net.IP(b[off : off+16]).String()
		off += 16
	default:
		return "", nil, errors.New("invalid address type")
	}
	if off+2 > len(b) {
		return "", nil, errors.New("port too short")
	}
	p := int(b[off])<<8 | int(b[off+1])
	off += 2
	t := fmt.Sprintf("%s:%d", h, p)
	if b[3] == 0x04 {
		t = fmt.Sprintf("[%s]:%d", h, p)
	}
	return t, b[off:], nil
}

func buildSOCKS5UDPPacket(h string, p int, d []byte) ([]byte, error) {
	buf := []byte{0, 0, 0}
	ip := net.ParseIP(h)
	if ip4 := ip.To4(); ip4 != nil {
		buf = append(buf, 0x01)
		buf = append(buf, ip4...)
	} else if ip != nil {
		buf = append(buf, 0x04)
		buf = append(buf, ip...)
	} else {
		buf = append(buf, 0x03, byte(len(h)))
		buf = append(buf, h...)
	}
	buf = append(buf, byte(p>>8), byte(p))
	buf = append(buf, d...)
	return buf, nil
}
