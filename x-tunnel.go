package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
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

	ReadBuf32K int
	ReadBuf64K int
}

type ListenList []string

func (l *ListenList) UnmarshalYAML(value *yaml.Node) error {
	if value == nil {
		return nil
	}
	var items []string
	switch value.Kind {
	case yaml.ScalarNode:
		for _, part := range strings.Split(value.Value, ",") {
			item := strings.TrimSpace(part)
			if item == "" {
				continue
			}
			items = append(items, item)
		}
	case yaml.SequenceNode:
		for _, node := range value.Content {
			item := strings.TrimSpace(node.Value)
			if item == "" {
				continue
			}
			items = append(items, item)
		}
	default:
		return fmt.Errorf("listen must be string or list")
	}
	*l = items
	return nil
}

type FileConfig struct {
	Listen          ListenList    `yaml:"listen"`
	ForwardAddr     string        `yaml:"forward"`
	IP              string        `yaml:"ip"`
	UDPBlockPorts   string        `yaml:"udp_block_ports"`
	Token           string        `yaml:"token"`
	ConnectionNum   int           `yaml:"connection_num"`
	Insecure        bool          `yaml:"insecure"`
	IPs             string        `yaml:"ips"`
	DNSServer       string        `yaml:"dns_server"`
	ECHDomain       string        `yaml:"ech_domain"`
	Fallback        bool          `yaml:"fallback"`
	CertFile        string        `yaml:"cert"`
	KeyFile         string        `yaml:"key"`
	CIDRs           string        `yaml:"cidr"`
	DialTimeout     time.Duration `yaml:"dial_timeout"`
	WSHandTimeout   time.Duration `yaml:"ws_handshake_timeout"`
	WSWriteTimeout  time.Duration `yaml:"ws_write_timeout"`
	WSReadTimeout   time.Duration `yaml:"ws_read_timeout"`
	PingInterval    time.Duration `yaml:"ping_interval"`
	ReconnectDelay  time.Duration `yaml:"reconnect_delay"`
}

func applyFileConfig(fileConfig FileConfig, commandLineSet map[string]bool) {
	if !commandLineSet["l"] && len(fileConfig.Listen) > 0 {
		listenAddr = strings.Join([]string(fileConfig.Listen), ",")
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
	if !commandLineSet["cert"] && fileConfig.CertFile != "" {
		certFile = fileConfig.CertFile
	}
	if !commandLineSet["key"] && fileConfig.KeyFile != "" {
		keyFile = fileConfig.KeyFile
	}
	if !commandLineSet["cidr"] && fileConfig.CIDRs != "" {
		cidrs = fileConfig.CIDRs
	}

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

// ======================== 全局参数 ========================

var (
	configFile       string
	listenAddr       string
	forwardAddr      string
	ipAddr           string
	udpBlockPortsStr string
	certFile         string
	keyFile          string
	token            string
	cidrs            string
	connectionNum    int
	insecure         bool
	ips              string

	dnsServer string
	echDomain string
	fallback  bool

	echListMu sync.RWMutex
	echList   []byte
	refreshMu sync.Mutex

	echPool *ECHPool

	clientID      string
	udpBlockPorts map[int]struct{}

	socks5Config *SOCKS5Config
	ipStrategy   byte
)

const (
	IPStrategyDefault  byte = 0
	IPStrategyIPv4Only byte = 1
	IPStrategyIPv6Only byte = 2
	IPStrategyPv4Pv6   byte = 3
	IPStrategyPv6Pv4   byte = 4
)

type SOCKS5Config struct {
	Host     string
	Username string
	Password string
}

func init() {
	flag.StringVar(&configFile, "config", "", "配置文件路径 (YAML格式)")
	flag.StringVar(&listenAddr, "l", "", "监听地址 (支持多个，用逗号分隔)\n格式示例:\n  socks5://[user:pass@]0.0.0.0:1080\n  http://[user:pass@]0.0.0.0:8080\n  tcp://0.0.0.0:2000/1.2.3.4:22\n  ws://0.0.0.0:80/path (服务端模式)\n  wss://0.0.0.0:443/path (服务端模式)")
	flag.StringVar(&forwardAddr, "f", "", "服务地址/代理地址 (客户端模式: wss://host:port | 服务端模式: socks5://[user:pass@]host:port)")
	flag.StringVar(&ipAddr, "ip", "", "指定解析的IP地址（仅客户端：将 wss 主机名定向到该 IP 连接，多个IP用逗号分隔）")
	flag.StringVar(&udpBlockPortsStr, "block", "443", "客户端拦截 UDP 端口列表，逗号分隔，如 443,8443")
	flag.BoolVar(&insecure, "insecure", false, "客户端 wss 模式忽略证书校验")
	flag.StringVar(&certFile, "cert", "", "TLS证书文件路径（默认:自动生成，仅服务端）")
	flag.StringVar(&keyFile, "key", "", "TLS密钥文件路径（默认:自动生成，仅服务端）")
	flag.StringVar(&token, "token", "", "身份验证令牌（WebSocket Subprotocol）")
	flag.StringVar(&cidrs, "cidr", "0.0.0.0/0,::/0", "允许的来源 IP 范围 (CIDR),多个范围用逗号分隔")
	flag.StringVar(&dnsServer, "dns", "https://doh.pub/dns-query", "查询 ECH 公钥所用的 DNS 服务器 (支持 DoH 或 UDP)")
	flag.StringVar(&echDomain, "ech", "cloudflare-ech.com", "用于查询 ECH 公钥的域名")
	flag.BoolVar(&fallback, "fallback", false, "是否禁用 ECH 并回落到普通 TLS 1.3 (默认 false)")
	flag.IntVar(&connectionNum, "n", 3, "每个IP建立的WebSocket连接数量")
	flag.StringVar(&ips, "ips", "", "服务端解析目标地址的IP偏好 (仅客户端有效)\n 4: 仅IPv4\n 6: 仅IPv6\n 4,6: IPv4优先\n 6,4: IPv6优先")
}

func loadConfigFromFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("无法读取文件: %w", err)
	}

	var fileConfig FileConfig
	if err := yaml.Unmarshal(data, &fileConfig); err != nil {
		return fmt.Errorf("YAML解析失败: %w", err)
	}

	commandLineSet := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		commandLineSet[f.Name] = true
	})

	applyFileConfig(fileConfig, commandLineSet)
	log.Printf("[客户端] 配置文件加载成功: %s", filePath)
	return nil
}

func maybeLoadConfig() error {
	if configFile == "" {
		return nil
	}
	return loadConfigFromFile(configFile)
}

func main() {
	flag.Parse()

	if err := maybeLoadConfig(); err != nil {
		log.Fatalf("[客户端] 读取配置文件失败: %v", err)
	}

	if listenAddr == "" {
		flag.Usage()
		return
	}

	ipStrategy = parseIPStrategy(ips)
	if ips != "" {
		log.Printf("[客户端] IP 访问策略: %s (code: %d)", ips, ipStrategy)
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

	listeners := strings.Split(listenAddr, ",")
	isServer := false
	for _, l := range listeners {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "ws://") || strings.HasPrefix(l, "wss://") {
			isServer = true
			listenAddr = l
			break
		}
	}

	// ================= 服务端模式 =================
	if isServer {
		if forwardAddr != "" {
			config, err := parseSOCKS5Addr(forwardAddr)
			if err != nil {
				log.Fatalf("[服务端] 解析SOCKS5代理地址失败: %v", err)
			}
			socks5Config = config
			log.Printf("[服务端] 使用SOCKS5前置代理: %s", config.Host)
			if config.Username != "" {
				log.Printf("[服务端] SOCKS5代理认证已启用")
			}
		} else {
			log.Printf("[服务端] 直连模式（未配置SOCKS5代理）")
		}
		runWebSocketServer(listenAddr)
		return
	}

	// ================= 客户端模式 =================
	if forwardAddr == "" {
		log.Fatalf("[客户端] 客户端模式必须指定服务地址 (-f wss://)")
	}

	forwardURL, err := url.Parse(forwardAddr)
	if err != nil {
		log.Fatalf("[客户端] 无效的服务地址: %v", err)
	}

	// 强制检查 wss（因此 dial 里不会出现 ws:// 分支）
	if !strings.EqualFold(forwardURL.Scheme, "wss") {
		log.Fatalf("[客户端] 安全要求：仅支持 wss:// 协议 (当前: %s)", forwardURL.Scheme)
	}

	// wss 模式：如果开启不校验证书，则自动禁用 ECH
	if insecure {
		if !fallback {
			fallback = true
			log.Printf("[客户端] wss 模式且启用不校验证书（insecure）：已自动禁用 ECH（fallback）")
		} else {
			log.Printf("[客户端] wss 模式且启用不校验证书（insecure）")
		}
	}

	if !fallback {
		if err := prepareECH(); err != nil {
			log.Fatalf("[客户端] 获取 ECH 公钥失败: %v", err)
		}
	} else {
		log.Printf("[客户端] fallback 模式已启用：禁用 ECH，使用标准 TLS 1.3")
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

	var wg sync.WaitGroup
	for _, listenerRule := range listeners {
		rule := strings.TrimSpace(listenerRule)
		if rule == "" {
			continue
		}

		if strings.HasPrefix(rule, "tcp://") {
			wg.Add(1)
			go func(r string) {
				defer wg.Done()
				runTCPListener(r)
			}(rule)
		} else if strings.HasPrefix(rule, "socks5://") {
			wg.Add(1)
			go func(r string) {
				defer wg.Done()
				runSOCKS5Listener(r)
			}(rule)
		} else if strings.HasPrefix(rule, "http://") {
			wg.Add(1)
			go func(r string) {
				defer wg.Done()
				runHTTPListener(r)
			}(rule)
		} else {
			log.Printf("[客户端] 忽略未知协议的监听地址: %s", rule)
		}
	}
	wg.Wait()
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

// ======================== 二进制协议 ========================

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
		return 0, "", nil, nil, errors.New("帧过短")
	}
	t = MessageType(b[0])
	idLen := int(b[1])
	metaLen := int(binary.BigEndian.Uint16(b[2:4]))
	payloadLen := int(binary.BigEndian.Uint32(b[4:8]))
	total := headerLen + idLen + metaLen + payloadLen
	if idLen < 0 || metaLen < 0 || payloadLen < 0 || total < headerLen || total > len(b) {
		return 0, "", nil, nil, errors.New("长度无效")
	}
	off := headerLen
	connID = string(b[off : off+idLen])
	off += idLen
	meta = b[off : off+metaLen]
	off += metaLen
	payload = b[off : off+payloadLen]
	return t, connID, meta, payload, nil
}

// ======================== SOCKS5 辅助函数 ========================

func parseSOCKS5Addr(addr string) (*SOCKS5Config, error) {
	addr = strings.TrimPrefix(addr, "socks5://")
	config := &SOCKS5Config{}

	if strings.Contains(addr, "@") {
		parts := strings.SplitN(addr, "@", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("无效的SOCKS5地址格式")
		}
		auth := parts[0]
		if strings.Contains(auth, ":") {
			authParts := strings.SplitN(auth, ":", 2)
			config.Username = authParts[0]
			config.Password = authParts[1]
		}
		config.Host = parts[1]
	} else {
		config.Host = addr
	}
	return config, nil
}

func dialViaSocks5(network, addr string) (net.Conn, error) {
	if socks5Config == nil {
		return net.DialTimeout(network, addr, cfg.DialTimeout)
	}
	proxyConn, err := net.DialTimeout("tcp", socks5Config.Host, cfg.DialTimeout)
	if err != nil {
		return nil, fmt.Errorf("连接SOCKS5代理失败: %v", err)
	}
	if err := socks5Handshake(proxyConn, socks5Config); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("SOCKS5握手失败: %v", err)
	}
	if err := socks5Connect(proxyConn, addr); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("SOCKS5 CONNECT失败: %v", err)
	}
	return proxyConn, nil
}

func socks5Handshake(conn net.Conn, config *SOCKS5Config) error {
	var methods []byte
	if config.Username != "" && config.Password != "" {
		methods = []byte{0x00, 0x02}
	} else {
		methods = []byte{0x00}
	}
	greeting := make([]byte, 2+len(methods))
	greeting[0], greeting[1] = 0x05, byte(len(methods))
	copy(greeting[2:], methods)

	if _, err := conn.Write(greeting); err != nil {
		return err
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if response[0] != 0x05 {
		return fmt.Errorf("SOCKS 版本错误: %d", response[0])
	}
	switch response[1] {
	case 0x00:
		return nil
	case 0x02:
		return socks5UserPassAuthSrv(conn, config.Username, config.Password)
	case 0xFF:
		return errors.New("服务器不接受认证")
	default:
		return fmt.Errorf("认证方法错误: %d", response[1])
	}
}

func socks5UserPassAuthSrv(conn net.Conn, username, password string) error {
	authReq := make([]byte, 3+len(username)+len(password))
	authReq[0], authReq[1] = 0x01, byte(len(username))
	copy(authReq[2:], username)
	authReq[2+len(username)] = byte(len(password))
	copy(authReq[3+len(username):], password)

	if _, err := conn.Write(authReq); err != nil {
		return err
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if response[1] != 0x00 {
		return errors.New("认证失败")
	}
	return nil
}

func socks5Connect(conn net.Conn, addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	var request []byte
	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			request = make([]byte, 10)
			request[0], request[1], request[2], request[3] = 0x05, 0x01, 0x00, 0x01
			copy(request[4:8], ip4)
			request[8], request[9] = byte(port>>8), byte(port)
		} else {
			request = make([]byte, 22)
			request[0], request[1], request[2], request[3] = 0x05, 0x01, 0x00, 0x04
			copy(request[4:20], ip)
			request[20], request[21] = byte(port>>8), byte(port)
		}
	} else {
		request = make([]byte, 7+len(host))
		request[0], request[1], request[2], request[3] = 0x05, 0x01, 0x00, 0x03
		request[4] = byte(len(host))
		copy(request[5:], host)
		request[5+len(host)], request[6+len(host)] = byte(port>>8), byte(port)
	}

	if _, err := conn.Write(request); err != nil {
		return err
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if response[1] != 0x00 {
		return fmt.Errorf("状态码: %d", response[1])
	}
	switch response[3] {
	case 0x01:
		_, _ = io.ReadFull(conn, make([]byte, 6))
	case 0x03:
		lenBuf := make([]byte, 1)
		io.ReadFull(conn, lenBuf)
		_, _ = io.ReadFull(conn, make([]byte, int(lenBuf[0])+2))
	case 0x04:
		_, _ = io.ReadFull(conn, make([]byte, 18))
	}
	return nil
}

// ======================== UDP Relayer (服务端用) ========================

type UDPRelayer interface {
	Read(buffer []byte) (int, *net.UDPAddr, error)
	Write(data []byte) (int, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

type DirectUDPRelayer struct {
	conn   *net.UDPConn
	target *net.UDPAddr
}

func (d *DirectUDPRelayer) Read(buffer []byte) (int, *net.UDPAddr, error) {
	return d.conn.ReadFromUDP(buffer)
}
func (d *DirectUDPRelayer) Write(data []byte) (int, error)    { return d.conn.WriteToUDP(data, d.target) }
func (d *DirectUDPRelayer) SetReadDeadline(t time.Time) error { return d.conn.SetReadDeadline(t) }
func (d *DirectUDPRelayer) Close() error                      { return d.conn.Close() }

type SOCKS5UDPRelay struct {
	tcpConn    net.Conn
	udpConn    *net.UDPConn
	relayAddr  *net.UDPAddr
	targetAddr *net.UDPAddr
	mu         sync.Mutex
	closed     bool
}

func newSOCKS5UDPRelay(targetAddr string) (*SOCKS5UDPRelay, error) {
	if socks5Config == nil {
		return nil, errors.New("SOCKS5配置为空")
	}
	tcpConn, err := net.DialTimeout("tcp", socks5Config.Host, cfg.DialTimeout)
	if err != nil {
		return nil, err
	}
	if err := socks5Handshake(tcpConn, socks5Config); err != nil {
		tcpConn.Close()
		return nil, err
	}
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := tcpConn.Write(req); err != nil {
		tcpConn.Close()
		return nil, err
	}
	resp := make([]byte, 4)
	if _, err := io.ReadFull(tcpConn, resp); err != nil {
		tcpConn.Close()
		return nil, err
	}
	if resp[1] != 0x00 {
		tcpConn.Close()
		return nil, fmt.Errorf("UDP ASSOCIATE拒绝: %d", resp[1])
	}
	var relayHost string
	switch resp[3] {
	case 0x01:
		ipBuf := make([]byte, 4)
		io.ReadFull(tcpConn, ipBuf)
		relayHost = net.IP(ipBuf).String()
	case 0x03:
		lenBuf := make([]byte, 1)
		io.ReadFull(tcpConn, lenBuf)
		domainBuf := make([]byte, lenBuf[0])
		io.ReadFull(tcpConn, domainBuf)
		relayHost = string(domainBuf)
	case 0x04:
		ipBuf := make([]byte, 16)
		io.ReadFull(tcpConn, ipBuf)
		relayHost = net.IP(ipBuf).String()
	}
	portBuf := make([]byte, 2)
	io.ReadFull(tcpConn, portBuf)
	relayPort := int(portBuf[0])<<8 | int(portBuf[1])

	if relayHost == "0.0.0.0" || relayHost == "::" {
		h, _, _ := net.SplitHostPort(socks5Config.Host)
		relayHost = h
	}
	rAddr, errResolve := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", relayHost, relayPort))
	if errResolve != nil {
		tcpConn.Close()
		return nil, errResolve
	}

	tAddr, errResolve := net.ResolveUDPAddr("udp", targetAddr)
	if errResolve != nil {
		tcpConn.Close()
		return nil, errResolve
	}

	localUDP, errListen := net.ListenUDP("udp", nil)
	if errListen != nil {
		tcpConn.Close()
		return nil, errListen
	}

	log.Printf("[服务端UDP] SOCKS5 UDP中继: %s -> %s", rAddr, targetAddr)
	return &SOCKS5UDPRelay{
		tcpConn:    tcpConn,
		udpConn:    localUDP,
		relayAddr:  rAddr,
		targetAddr: tAddr,
	}, nil
}

func (r *SOCKS5UDPRelay) Write(data []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, errors.New("closed")
	}
	pkt := buildSOCKS5UDPPacketData(r.targetAddr, data)
	return r.udpConn.WriteToUDP(pkt, r.relayAddr)
}

func (r *SOCKS5UDPRelay) Read(buffer []byte) (int, *net.UDPAddr, error) {
	if r.closed {
		return 0, nil, errors.New("closed")
	}
	tmpPtr := buf64kPool.Get().(*[]byte)
	tmp := *tmpPtr
	defer buf64kPool.Put(tmpPtr)

	n, _, err := r.udpConn.ReadFromUDP(tmp)
	if err != nil {
		return 0, nil, err
	}
	srcAddr, payload, err := parseSOCKS5UDPResp(tmp[:n])
	if err != nil {
		return 0, nil, err
	}
	copy(buffer, payload)
	return len(payload), srcAddr, nil
}

func (r *SOCKS5UDPRelay) SetReadDeadline(t time.Time) error { return r.udpConn.SetReadDeadline(t) }

func (r *SOCKS5UDPRelay) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	_ = r.udpConn.Close()
	_ = r.tcpConn.Close()
	return nil
}

func buildSOCKS5UDPPacketData(target *net.UDPAddr, data []byte) []byte {
	packet := []byte{0x00, 0x00, 0x00}
	if ip4 := target.IP.To4(); ip4 != nil {
		packet = append(packet, 0x01)
		packet = append(packet, ip4...)
	} else {
		packet = append(packet, 0x04)
		packet = append(packet, target.IP...)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(target.Port))
	packet = append(packet, portBytes...)
	packet = append(packet, data...)
	return packet
}

func parseSOCKS5UDPResp(packet []byte) (*net.UDPAddr, []byte, error) {
	if len(packet) < 10 {
		return nil, nil, fmt.Errorf("数据包过短")
	}
	atyp := packet[3]
	offset := 4
	var host string
	switch atyp {
	case 0x01:
		if offset+4 > len(packet) {
			return nil, nil, fmt.Errorf("IPv4地址长度过短")
		}
		host = net.IP(packet[offset : offset+4]).String()
		offset += 4
	case 0x03:
		if offset+1 > len(packet) {
			return nil, nil, fmt.Errorf("域名长度字段过短")
		}
		l := int(packet[offset])
		offset++
		if offset+l > len(packet) {
			return nil, nil, fmt.Errorf("域名长度不足")
		}
		host = string(packet[offset : offset+l])
		offset += l
	case 0x04:
		if offset+16 > len(packet) {
			return nil, nil, fmt.Errorf("IPv6地址长度过短")
		}
		host = net.IP(packet[offset : offset+16]).String()
		offset += 16
	default:
		return nil, nil, fmt.Errorf("地址类型无效: %d", atyp)
	}
	if offset+2 > len(packet) {
		return nil, nil, fmt.Errorf("端口字段过短")
	}
	port := int(packet[offset])<<8 | int(packet[offset+1])
	offset += 2
	addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if addr == nil {
		return nil, nil, fmt.Errorf("解析地址失败")
	}
	return addr, packet[offset:], nil
}

// ======================== ECH 相关（客户端） ========================

const typeHTTPS = 65

func prepareECH() error {
	for {
		log.Printf("[客户端] DNS查询 ECH: %s -> %s", dnsServer, echDomain)
		echBase64, err := queryHTTPSRecord(echDomain, dnsServer)
		if err != nil {
			log.Printf("[客户端] DNS 查询失败: %v，重试...", err)
			time.Sleep(2 * time.Second)
			continue
		}
		if echBase64 == "" {
			log.Printf("[客户端] 未找到 ECH 参数，重试...")
			time.Sleep(2 * time.Second)
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(echBase64)
		if err != nil {
			log.Printf("[客户端] ECH Base64 解码失败: %v，重试...", err)
			time.Sleep(2 * time.Second)
			continue
		}
		echListMu.Lock()
		echList = raw
		echListMu.Unlock()
		log.Printf("[客户端] ECHConfigList 长度: %d 字节", len(raw))
		return nil
	}
}

func refreshECH() error {
	if fallback {
		return nil
	}

	refreshMu.Lock()
	defer refreshMu.Unlock()
	log.Printf("[客户端] 刷新 ECH 配置...")
	return prepareECH()
}

func getECHList() ([]byte, error) {
	if fallback {
		return nil, nil
	}
	echListMu.RLock()
	defer echListMu.RUnlock()
	if len(echList) == 0 {
		return nil, errors.New("ECH 配置尚未加载")
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
			return errors.New("服务器拒绝 ECH")
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
		InsecureSkipVerify: insecure, // 修正：fallback/标准TLS也要支持 -insecure
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
		return "", fmt.Errorf("连接 DNS 服务器失败: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err = conn.Write(query); err != nil {
		return "", fmt.Errorf("发送查询失败: %v", err)
	}

	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "", fmt.Errorf("DNS 查询超时")
		}
		return "", fmt.Errorf("读取 DNS 响应失败: %v", err)
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
		return "", fmt.Errorf("DoH 状态码: %d", resp.StatusCode)
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
		return "", fmt.Errorf("响应过短")
	}
	ancount := binary.BigEndian.Uint16(response[6:8])
	if ancount == 0 {
		return "", fmt.Errorf("无答案记录")
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

// ======================== WebSocket 服务端 ========================

var serverSessions sync.Map // map[string]*ClientSession

type WSChannel struct {
	id      uint64
	conn    *websocket.Conn
	writeMu sync.Mutex
	session *ClientSession
}

func (ch *WSChannel) writeMessage(msgType int, data []byte) error {
	ch.writeMu.Lock()
	defer ch.writeMu.Unlock()
	_ = ch.conn.SetWriteDeadline(time.Now().Add(cfg.WSWriteTimeout))
	err := ch.conn.WriteMessage(msgType, data)
	_ = ch.conn.SetWriteDeadline(time.Time{})
	return err
}

type ClientSession struct {
	nextChanID uint64

	clientID string

	mu       sync.RWMutex
	channels map[uint64]*WSChannel

	conns sync.Map // map[string]*ServerConnState
}

type ServerConnState struct {
	connID string

	mu       sync.RWMutex
	uplink   *WSChannel
	downlink *WSChannel

	tcpConn  net.Conn
	udpRelay UDPRelayer

	cancel context.CancelFunc
	closed atomic.Bool

	target  string
	reqType string
	start   time.Time
}

func getOrCreateClientSession(clientID string) *ClientSession {
	if v, ok := serverSessions.Load(clientID); ok {
		return v.(*ClientSession)
	}
	s := &ClientSession{
		clientID: clientID,
		channels: make(map[uint64]*WSChannel),
	}
	actual, _ := serverSessions.LoadOrStore(clientID, s)
	return actual.(*ClientSession)
}

func (s *ClientSession) addChannel(wsConn *websocket.Conn) *WSChannel {
	newID := atomic.AddUint64(&s.nextChanID, 1)

	ch := &WSChannel{
		id:      newID,
		conn:    wsConn,
		session: s,
	}
	s.mu.Lock()
	s.channels[ch.id] = ch
	s.mu.Unlock()
	return ch
}

func (s *ClientSession) removeChannel(id uint64) {
	s.mu.Lock()
	delete(s.channels, id)
	empty := len(s.channels) == 0
	s.mu.Unlock()

	if empty {
		log.Printf("[服务端] 客户端会话 %s 断开，开始清理连接资源", s.clientID)
		serverSessions.Delete(s.clientID)
		var closed int
		s.conns.Range(func(key, value any) bool {
			st := value.(*ServerConnState)
			st.close()
			s.conns.Delete(key)
			closed++
			return true
		})
		log.Printf("[服务端] 客户端会话 %s 清理完成，共关闭 %d 条连接", s.clientID, closed)
	}
}

func (s *ClientSession) snapshotChannels() []*WSChannel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*WSChannel, 0, len(s.channels))
	for _, ch := range s.channels {
		out = append(out, ch)
	}
	return out
}

func (s *ClientSession) broadcastBinary(payload []byte) {
	for _, ch := range s.snapshotChannels() {
		_ = ch.writeMessage(websocket.BinaryMessage, payload)
	}
}

func (s *ClientSession) sendDownlinkOrBroadcast(st *ServerConnState, payload []byte) {
	st.mu.RLock()
	dl := st.downlink
	st.mu.RUnlock()
	if dl != nil {
		_ = dl.writeMessage(websocket.BinaryMessage, payload)
		return
	}
	s.broadcastBinary(payload)
}

func (st *ServerConnState) close() {
	if st.closed.Swap(true) {
		return
	}
	if st.cancel != nil {
		st.cancel()
	}
	if st.tcpConn != nil {
		_ = st.tcpConn.Close()
	}
	if st.udpRelay != nil {
		_ = st.udpRelay.Close()
	}
}

func generateSelfSignedCert() (tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"SelfSigned"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}),
	)
}

func runWebSocketServer(addr string) {
	u, err := url.Parse(addr)
	if err != nil {
		log.Fatalf("[服务端] WS 地址无效: %v", err)
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	var allowedNets []*net.IPNet
	for _, cidr := range strings.Split(cidrs, ",") {
		_, allowedNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			log.Fatalf("[服务端] CIDR 解析失败: %v", err)
		}
		allowedNets = append(allowedNets, allowedNet)
	}

	upgrader := websocket.Upgrader{
		CheckOrigin:     func(r *http.Request) bool { return true },
		ReadBufferSize:  cfg.ReadBuf64K,
		WriteBufferSize: cfg.ReadBuf64K,
	}
	if token != "" {
		upgrader.Subprotocols = []string{token}
	}

	http.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "错误的请求", http.StatusBadRequest)
			return
		}
		ip := net.ParseIP(clientIP)
		allowed := false
		for _, n := range allowedNets {
			if n.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			http.Error(w, "禁止访问", http.StatusForbidden)
			return
		}
		if token != "" {
			if r.Header.Get("Sec-WebSocket-Protocol") != token {
				log.Printf("[服务端] Token 认证失败，来源 IP: %s", clientIP)
				http.Error(w, "未授权", http.StatusUnauthorized)
				return
			}
		}
		wsConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		cid := r.URL.Query().Get("client_id")
		if cid == "" {
			cid = uuid.NewString()
		}
		session := getOrCreateClientSession(cid)
		ch := session.addChannel(wsConn)
		log.Printf("[服务端] 客户端通道 %d 连接, 客户端ID: %s, IP: %s", ch.id, cid, clientIP)
		go handleWebSocketChannel(ch)
	})

	if u.Scheme == "wss" {
		server := &http.Server{Addr: u.Host}
		if certFile != "" && keyFile != "" {
			server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
			if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
				log.Fatalf("[服务端] WSS 启动失败: %v", err)
			}
		} else {
			cert, err := generateSelfSignedCert()
			if err != nil {
				log.Fatalf("[服务端] 生成自签名证书失败: %v", err)
			}
			server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
			log.Printf("[服务端] WSS 启动 %s%s", u.Host, path)
			if err := server.ListenAndServeTLS("", ""); err != nil {
				log.Fatalf("[服务端] WSS 启动失败: %v", err)
			}
		}
	} else {
		log.Printf("[服务端] WS 启动 %s%s", u.Host, path)
		if err := http.ListenAndServe(u.Host, nil); err != nil {
			log.Fatalf("[服务端] WS 启动失败: %v", err)
		}
	}
}

func sendConnStatus(s *ClientSession, st *ServerConnState, ok bool, errMsg string) {
	status := byte(StatusOK)
	payload := []byte(nil)
	if !ok {
		status = byte(StatusERR)
		payload = []byte(errMsg)
	}
	msg := encodeMessage(MsgConnStatus, st.connID, []byte{status}, payload)
	s.sendDownlinkOrBroadcast(st, msg)
}

// 根据 IP 策略拨号 TCP
func dialTCPWithStrategy(addr string, strategy byte) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return net.DialTimeout("tcp", addr, cfg.DialTimeout)
	}

	if ip := net.ParseIP(host); ip != nil {
		return net.DialTimeout("tcp", addr, cfg.DialTimeout)
	}

	if strategy == IPStrategyIPv4Only {
		return net.DialTimeout("tcp4", addr, cfg.DialTimeout)
	}
	if strategy == IPStrategyIPv6Only {
		return net.DialTimeout("tcp6", addr, cfg.DialTimeout)
	}

	if strategy == IPStrategyPv4Pv6 || strategy == IPStrategyPv6Pv4 {
		resolver := &net.Resolver{}
		ctx, cancel := context.WithTimeout(context.Background(), cfg.DialTimeout)
		defer cancel()
		addrs, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}

		var v4, v6 net.IP
		for _, a := range addrs {
			if a.IP.To4() != nil {
				if v4 == nil {
					v4 = a.IP
				}
			} else {
				if v6 == nil {
					v6 = a.IP
				}
			}
			if v4 != nil && v6 != nil {
				break
			}
		}

		var selected net.IP
		if strategy == IPStrategyPv4Pv6 {
			if v4 != nil {
				selected = v4
			} else {
				selected = v6
			}
		} else {
			if v6 != nil {
				selected = v6
			} else {
				selected = v4
			}
		}

		if selected == nil {
			return nil, fmt.Errorf("未找到可用IP: %s", host)
		}

		target := net.JoinHostPort(selected.String(), port)
		return net.DialTimeout("tcp", target, cfg.DialTimeout)
	}

	return net.DialTimeout("tcp", addr, cfg.DialTimeout)
}

func resolveUDPWithStrategy(addr string, strategy byte) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return net.ResolveUDPAddr("udp", addr)
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: port}, nil
	}

	if strategy == IPStrategyIPv4Only {
		return net.ResolveUDPAddr("udp4", addr)
	}
	if strategy == IPStrategyIPv6Only {
		return net.ResolveUDPAddr("udp6", addr)
	}

	if strategy == IPStrategyPv4Pv6 || strategy == IPStrategyPv6Pv4 {
		resolver := &net.Resolver{}
		ctx, cancel := context.WithTimeout(context.Background(), cfg.DialTimeout)
		defer cancel()
		addrs, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}

		var v4, v6 net.IP
		for _, a := range addrs {
			if a.IP.To4() != nil {
				if v4 == nil {
					v4 = a.IP
				}
			} else {
				if v6 == nil {
					v6 = a.IP
				}
			}
			if v4 != nil && v6 != nil {
				break
			}
		}

		var selected net.IP
		if strategy == IPStrategyPv4Pv6 {
			if v4 != nil {
				selected = v4
			} else {
				selected = v6
			}
		} else {
			if v6 != nil {
				selected = v6
			} else {
				selected = v4
			}
		}

		if selected == nil {
			return nil, fmt.Errorf("未找到可用IP: %s", host)
		}
		return &net.UDPAddr{IP: selected, Port: port}, nil
	}

	return net.ResolveUDPAddr("udp", addr)
}

// ======================== WebSocket 处理逻辑 ========================

func handleWebSocketChannel(ch *WSChannel) {
	wsConn := ch.conn
	session := ch.session

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		_ = wsConn.Close()
		session.removeChannel(ch.id)
	}()

	wsConn.SetPingHandler(func(message string) error {
		return ch.writeMessage(websocket.PongMessage, []byte(message))
	})

	for {
		typ, msg, err := wsConn.ReadMessage()
		if err != nil {
			log.Printf("[服务端] 客户端通道 %d 断开", ch.id)
			return
		}
		if typ != websocket.BinaryMessage {
			continue
		}

		mt, connID, meta, payload, err := decodeMessage(msg)
		if err != nil {
			continue
		}

		switch mt {

		case MsgSelectDownlink:
			v, ok := session.conns.Load(connID)
			if !ok {
				continue
			}
			st := v.(*ServerConnState)
			st.mu.Lock()
			if st.downlink == nil {
				st.downlink = ch
			}
			st.mu.Unlock()

		case MsgTCPData:
			v, ok := session.conns.Load(connID)
			if !ok {
				continue
			}
			st := v.(*ServerConnState)
			st.mu.RLock()
			uplink := st.uplink
			tcpConn := st.tcpConn
			st.mu.RUnlock()
			if uplink != ch || tcpConn == nil {
				continue
			}
			_, _ = tcpConn.Write(payload)

		case MsgTCPClose:
			v, ok := session.conns.Load(connID)
			if !ok {
				continue
			}
			st := v.(*ServerConnState)
			st.mu.RLock()
			uplink := st.uplink
			target := st.target
			typ := st.reqType
			st.mu.RUnlock()
			if uplink != ch {
				continue
			}
			session.conns.Delete(connID)
			log.Printf("[服务端] 客户ID:%s %s 访问: %s, ID:%s, 已关闭", shortID(session.clientID), typ, target, shortID(connID))
			st.close()

		case MsgUDPData:
			v, ok := session.conns.Load(connID)
			if !ok {
				continue
			}
			st := v.(*ServerConnState)
			st.mu.RLock()
			uplink := st.uplink
			relay := st.udpRelay
			st.mu.RUnlock()
			if uplink != ch || relay == nil {
				continue
			}
			_, _ = relay.Write(payload)

		case MsgUDPClose:
			v, ok := session.conns.Load(connID)
			if !ok {
				continue
			}
			st := v.(*ServerConnState)
			st.mu.RLock()
			uplink := st.uplink
			target := st.target
			typ := st.reqType
			st.mu.RUnlock()
			if uplink != ch {
				continue
			}
			session.conns.Delete(connID)
			log.Printf("[服务端] 客户ID:%s %s 访问: %s, ID:%s, 已关闭", shortID(session.clientID), typ, target, shortID(connID))
			st.close()

		case MsgUDPConnect:
			if len(meta) < 1 {
				continue
			}
			strategy := meta[0]
			target := string(meta[1:])

			st := &ServerConnState{connID: connID}
			st.mu.Lock()
			st.uplink = ch
			st.target = target
			st.reqType = "SOCKS5 UDP"
			st.start = time.Now()
			st.mu.Unlock()

			actual, loaded := session.conns.LoadOrStore(connID, st)
			if loaded {
				continue
			}
			st = actual.(*ServerConnState)

			log.Printf("[服务端] 客户ID:%s %s 访问: %s, ID:%s", shortID(session.clientID), st.reqType, st.target, shortID(connID))

			go func() {
				var relay UDPRelayer
				var err error
				if socks5Config != nil {
					var r *SOCKS5UDPRelay
					r, err = newSOCKS5UDPRelay(target)
					relay = r
				} else {
					addr, errResolve := resolveUDPWithStrategy(target, strategy)
					if errResolve == nil {
						c, errListen := net.ListenUDP("udp", nil)
						if errListen == nil {
							relay = &DirectUDPRelayer{conn: c, target: addr}
						}
						err = errListen
					} else {
						err = errResolve
					}
				}
				if err != nil {
					sendConnStatus(session, st, false, err.Error())
					session.conns.Delete(connID)
					st.close()
					return
				}

				if st.closed.Load() {
					relay.Close()
					return
				}

				ctxConn, cancelConn := context.WithCancel(ctx)
				st.mu.Lock()
				st.udpRelay = relay
				st.cancel = cancelConn
				st.mu.Unlock()

				_ = ch.writeMessage(websocket.BinaryMessage, encodeMessage(MsgUplink, connID, nil, nil))
				sendConnStatus(session, st, true, "")

				go func() {
					defer func() {
						session.conns.Delete(connID)
						st.close()
					}()
					bufPtr := buf64kPool.Get().(*[]byte)
					buf := *bufPtr
					defer buf64kPool.Put(bufPtr)

					for {
						select {
						case <-ctxConn.Done():
							return
						default:
						}
						_ = relay.SetReadDeadline(time.Now().Add(1 * time.Second))
						n, addr, err := relay.Read(buf)
						if err != nil {
							if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
								continue
							}
							_ = ch.writeMessage(websocket.BinaryMessage, encodeMessage(MsgUDPClose, connID, nil, nil))
							return
						}
						msg := encodeMessage(MsgUDPData, connID, []byte(addr.String()), buf[:n])
						session.sendDownlinkOrBroadcast(st, msg)
					}
				}()
			}()

		case MsgTCPConnect:
			if len(meta) < 1 {
				continue
			}
			strategy := meta[0]
			target := string(meta[1:])

			st := &ServerConnState{connID: connID}
			st.mu.Lock()
			st.uplink = ch
			st.target = target
			st.reqType = "SOCKS5"
			st.start = time.Now()
			st.mu.Unlock()

			actual, loaded := session.conns.LoadOrStore(connID, st)
			if loaded {
				continue
			}
			st = actual.(*ServerConnState)

			log.Printf("[服务端] 客户ID:%s %s 访问: %s, ID:%s", shortID(session.clientID), st.reqType, st.target, shortID(connID))

			var tcpConn net.Conn
			var errDial error

			if socks5Config != nil {
				tcpConn, errDial = dialViaSocks5("tcp", target)
			} else {
				tcpConn, errDial = dialTCPWithStrategy(target, strategy)
			}

			if errDial != nil {
				sendConnStatus(session, st, false, errDial.Error())
				_ = ch.writeMessage(websocket.BinaryMessage, encodeMessage(MsgTCPClose, connID, nil, nil))
				session.conns.Delete(connID)
				st.close()
				continue
			}

			ctxConn, cancelConn := context.WithCancel(ctx)
			st.mu.Lock()
			st.tcpConn = tcpConn
			st.cancel = cancelConn
			st.mu.Unlock()

			if len(payload) > 0 {
				if _, err := tcpConn.Write(payload); err != nil {
					sendConnStatus(session, st, false, err.Error())
					_ = ch.writeMessage(websocket.BinaryMessage, encodeMessage(MsgTCPClose, connID, nil, nil))
					session.conns.Delete(connID)
					st.close()
					continue
				}
			}

			_ = ch.writeMessage(websocket.BinaryMessage, encodeMessage(MsgUplink, connID, nil, nil))
			sendConnStatus(session, st, true, "")

			go func() {
				defer func() {
					session.conns.Delete(connID)
					st.close()
				}()
				bufPtr := buf32kPool.Get().(*[]byte)
				buf := *bufPtr
				defer buf32kPool.Put(bufPtr)

				for {
					select {
					case <-ctxConn.Done():
						return
					default:
					}
					_ = tcpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
					n, err := tcpConn.Read(buf)
					if err != nil {
						if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
							continue
						}
						_ = ch.writeMessage(websocket.BinaryMessage, encodeMessage(MsgTCPClose, connID, nil, nil))
						return
					}
					session.sendDownlinkOrBroadcast(st, encodeMessage(MsgTCPData, connID, nil, buf[:n]))
				}
			}()

		default:
		}
	}
}

// ======================== 多通道客户端池 ========================

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
	logged     bool
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
		return -1, fmt.Errorf("无效的通道ID %d", chID)
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
			log.Printf("[客户端] 通道 %d (IP:%s) 连接失败: %v", chID, ip, err)
			time.Sleep(3 * time.Second)
			continue
		}
		p.wsConnsMu.Lock()
		p.wsConns[idx] = wsConn
		p.wsConnsMu.Unlock()
		log.Printf("[客户端] 通道 %d (IP:%s) 就绪", chID, ip)

		ctx, cancel := context.WithCancel(context.Background())
		go p.writeWorker(ctx, idx, wsConn)
		p.handleChannel(chID, wsConn)
		cancel()
		_ = wsConn.Close()

		p.wsConnsMu.Lock()
		p.wsConns[idx] = nil
		p.wsConnsMu.Unlock()
		p.cleanupChannel(chID)
		log.Printf("[客户端] 通道 %d 断开，重连中...", chID)
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
		return fmt.Errorf("全局写队列超限")
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
			return fmt.Errorf("通道 %d 缓冲区拥堵", chID)
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
		typ = "请求"
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
				log.Printf("[客户端] 通道 %d 异常: %v", chID, err)
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

func (p *ECHPool) WaitConnected(id string, timeout time.Duration) bool {
	p.mu.RLock()
	var ch chan bool
	if st := p.conns[id]; st != nil {
		ch = st.connected
	}
	p.mu.RUnlock()
	if ch == nil {
		return false
	}
	select {
	case <-ch:
		return true
	case <-time.After(timeout):
		return false
	}
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

// ======================== TCP Forwarder ========================

func runTCPListener(rule string) {
	rule = strings.TrimPrefix(rule, "tcp://")
	parts := strings.Split(rule, "/")
	if len(parts) != 2 {
		return
	}
	lAddr, tAddr := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	l, err := net.Listen("tcp", lAddr)
	if err != nil {
		log.Fatalf("[客户端] TCP监听失败: %v", err)
	}
	log.Printf("[客户端] TCP转发: %s -> %s", lAddr, tAddr)
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go handleLocalTCP(c, tAddr)
	}
}

func handleLocalTCP(c net.Conn, target string) {
	connID := uuid.New().String()

	bufPtr := buf32kPool.Get().(*[]byte)
	buf := *bufPtr
	defer buf32kPool.Put(bufPtr)

	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _ := c.Read(buf)
	_ = c.SetReadDeadline(time.Time{})

	var first []byte
	if n > 0 {
		first = append([]byte(nil), buf[:n]...)
	}

	echPool.RegisterAndBroadcastTCP(connID, target, first, c, "TCP转发")

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

// dialWebSocketWithECH：删掉 “ws:// 分支”，因为 main 已强制 -f 只能是 wss://
func dialWebSocketWithECH(addr string, retries int, ip string, clientID string) (*websocket.Conn, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(u.Scheme, "wss") {
		return nil, fmt.Errorf("仅支持 wss:// (当前: %s)", u.Scheme)
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
				return nil, fmt.Errorf("认证失败：Token 不匹配或未提供")
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
	return nil, fmt.Errorf("连接失败")
}

// ======================== SOCKS5 / HTTP Proxy ========================

type ProxyConfig struct {
	Username, Password, Host string
}

type ProxyError struct {
	Op     string
	ConnID string
	Err    error
}

func (e *ProxyError) Error() string {
	return fmt.Sprintf("%s [%s]: %v", e.Op, shortID(e.ConnID), e.Err)
}
func (e *ProxyError) Unwrap() error { return e.Err }

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
			return "", "", "", fmt.Errorf("格式错误")
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
	log.Printf("[客户端] SOCKS5 代理: %s", h)
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
	_ = c.SetDeadline(time.Now().Add(cfg.DialTimeout))
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

	// 增强过滤逻辑：解析 host 判断是否为 IP，从而覆盖 ATYP=0x03 但内容为 IP 的情况
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
	return errors.New("认证失败")
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
		if !a.pool.WaitConnected(a.connID, cfg.DialTimeout) {
			a.Close()
			return
		}
		if id, ok := a.pool.GetUplinkChannel(a.connID); ok {
			a.mu.Lock()
			a.channelID = id
			chID = id
			a.mu.Unlock()
		}
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
		return "", nil, errors.New("数据不合法")
	}
	off := 4
	var h string
	switch b[3] {
	case 0x01:
		if off+4 > len(b) {
			return "", nil, errors.New("IPv4地址长度过短")
		}
		h = net.IP(b[off : off+4]).String()
		off += 4
	case 0x03:
		if off+1 > len(b) {
			return "", nil, errors.New("域名长度不足")
		}
		l := int(b[off])
		off++
		if off+l > len(b) {
			return "", nil, errors.New("域名长度不足")
		}
		h = string(b[off : off+l])
		off += l
	case 0x04:
		if off+16 > len(b) {
			return "", nil, errors.New("IPv6地址长度过短")
		}
		h = net.IP(b[off : off+16]).String()
		off += 16
	default:
		return "", nil, errors.New("地址类型无效")
	}
	if off+2 > len(b) {
		return "", nil, errors.New("端口字段过短")
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

func runHTTPListener(addr string) {
	h, u, p, _ := parseAuthAndAddr(strings.TrimPrefix(addr, "http://"))
	l, err := net.Listen("tcp", h)
	if err != nil {
		log.Fatalf("[客户端] HTTP监听失败: %v", err)
	}
	log.Printf("[客户端] HTTP 代理: %s", h)
	cfgp := &ProxyConfig{u, p, h}
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go handleHTTP(c, cfgp)
	}
}

func handleHTTP(c net.Conn, cfgp *ProxyConfig) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(cfg.DialTimeout))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	if cfgp.Username != "" {
		auth := req.Header.Get("Proxy-Authorization")
		ok := false
		if strings.HasPrefix(auth, "Basic ") {
			p, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
			pair := strings.SplitN(string(p), ":", 2)
			if len(pair) == 2 && pair[0] == cfgp.Username && pair[1] == cfgp.Password {
				ok = true
			}
		}
		if !ok {
			_, _ = c.Write([]byte("HTTP/1.1 407 需要认证\r\nProxy-Authenticate: Basic realm=\"代理\"\r\n\r\n"))
			return
		}
	}

	target := req.Host
	if !strings.Contains(target, ":") {
		if req.Method == "CONNECT" {
			target += ":443"
		} else {
			target += ":80"
		}
	}

	connID := uuid.New().String()
	var first []byte

	if req.Method == "CONNECT" {
		_, _ = c.Write([]byte("HTTP/1.1 200 连接已建立\r\n\r\n"))
	} else {
		req.RequestURI = ""
		req.URL.Scheme = ""
		req.URL.Host = ""
		var buf bytes.Buffer
		_ = req.Write(&buf)
		first = buf.Bytes()
	}

	echPool.RegisterAndBroadcastTCP(connID, target, first, c, "HTTP")

	defer func() {
		if chID, ok := echPool.GetUplinkChannel(connID); ok {
			_ = echPool.SendCloseDirect(chID, connID)
		} else {
			echPool.broadcastWrite(websocket.BinaryMessage, encodeMessage(MsgTCPClose, connID, nil, nil))
		}
		_ = c.Close()
		echPool.Unregister(connID)
	}()

	bufPtr := buf32kPool.Get().(*[]byte)
	buf := *bufPtr
	defer buf32kPool.Put(bufPtr)

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
