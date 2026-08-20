package translate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/imroc/req/v3"
	"github.com/redis/go-redis/v9"
	"github.com/tidwall/gjson"
)

const (
	defaultIPCheckURL = "https://ipcheck.102465.xyz/"
	defaultResinPlatform = "7d9e1c7b-00a2-47f6-a858-d59a1111269b"
	defaultCooldown       = 30 * time.Minute
	defaultMaxRetries     = 3
)

type blacklist interface {
	Add(context.Context, string, time.Duration) error
	Has(context.Context, string) (bool, error)
}

type memoryBlacklist struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

func newMemoryBlacklist() *memoryBlacklist {
	return &memoryBlacklist{entries: make(map[string]time.Time)}
}

func (b *memoryBlacklist) Add(_ context.Context, ip string, ttl time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries[ip] = time.Now().Add(ttl)
	return nil
}

func (b *memoryBlacklist) Has(_ context.Context, ip string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	expires, ok := b.entries[ip]
	if !ok {
		return false, nil
	}
	if time.Now().After(expires) {
		delete(b.entries, ip)
		return false, nil
	}
	return true, nil
}

type redisBlacklist struct {
	client *redis.Client
	prefix string
}

func (b *redisBlacklist) key(ip string) string {
	return b.prefix + ip
}

func (b *redisBlacklist) Add(ctx context.Context, ip string, ttl time.Duration) error {
	return b.client.Set(ctx, b.key(ip), "1", ttl).Err()
}

func (b *redisBlacklist) Has(ctx context.Context, ip string) (bool, error) {
	result := b.client.Exists(ctx, b.key(ip))
	return result.Val() == 1, result.Err()
}

type proxyManager struct {
	mu          sync.Mutex
	baseURL     string
	stickyURL   string
	apiBase     string
	adminToken  string
	platform    string
	stickyPrefix string
	account     string
	ipCheckURL  string
	cooldown    time.Duration
	maxRetries  int
	blacklist   blacklist
	client      *req.Client
	ip          string
}

var proxyManagers sync.Map // map[string]*proxyManager

func getProxyManager(proxyURL string) (*proxyManager, error) {
	if proxyURL == "" {
		return nil, nil
	}
	if manager, ok := proxyManagers.Load(proxyURL); ok {
		return manager.(*proxyManager), nil
	}
	manager, err := newProxyManager(proxyURL)
	if err != nil {
		return nil, err
	}
	actual, loaded := proxyManagers.LoadOrStore(proxyURL, manager)
	if loaded {
		return actual.(*proxyManager), nil
	}
	return manager, nil
}

func newProxyManager(proxyURL string) (*proxyManager, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}
	if u.Host == "" {
		return nil, fmt.Errorf("invalid proxy URL: host is required")
	}
	if internalHost := os.Getenv("RESIN_PROXY_HOST"); internalHost != "" {
		u.Host = internalHost
	}

	platform := envOrDefault("RESIN_PLATFORM_ID", defaultResinPlatform)
	stickyPrefix := envOrDefault("RESIN_STICKY_PREFIX", "DLX")
	account := os.Getenv("RESIN_ACCOUNT")
	if account == "" {
		account = "dlx"
	}
	password := ""
	sticky := *u
	sticky.User = url.UserPassword(stickyPrefix+"."+account, password)

	apiBase := os.Getenv("RESIN_API_BASE")
	if apiBase == "" {
		apiURL := *u
		apiURL.User = nil
		apiURL.Path = ""
		apiURL.RawPath = ""
		apiURL.RawQuery = ""
		apiURL.Fragment = ""
		apiBase = strings.TrimRight(apiURL.String(), "/")
	}

	ttl := defaultCooldown
	if value := os.Getenv("RESIN_COOLDOWN"); value != "" {
		if parsed, parseErr := time.ParseDuration(value); parseErr == nil && parsed > 0 {
			ttl = parsed
		}
	}
	maxRetries := defaultMaxRetries
	if value := os.Getenv("RESIN_MAX_RETRIES"); value != "" {
		if parsed, parseErr := strconv.Atoi(value); parseErr == nil && parsed >= 0 {
			maxRetries = parsed
		}
	}

	var blocked blacklist = newMemoryBlacklist()
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		options, parseErr := redis.ParseURL(redisURL)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid REDIS_URL: %w", parseErr)
		}
		blocked = &redisBlacklist{
			client: redis.NewClient(options),
			prefix: envOrDefault("REDIS_PREFIX", "dlx:deepl:blacklist:"),
		}
	}

	return &proxyManager{
		baseURL:     proxyURL,
		stickyURL:   sticky.String(),
		apiBase:     apiBase,
		adminToken:  os.Getenv("RESIN_ADMIN_TOKEN"),
		platform:    platform,
		stickyPrefix: stickyPrefix,
		account:     account,
		ipCheckURL:  envOrDefault("IPCHECK_URL", defaultIPCheckURL),
		cooldown:    ttl,
		maxRetries:  maxRetries,
		blacklist:   blocked,
	}, nil
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func (m *proxyManager) currentClient() (*req.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.client != nil {
		return m.client, nil
	}
	client, err := newOneshotClient(m.stickyURL)
	if err != nil {
		return nil, err
	}
	m.client = client
	go warmCookies(client)
	return client, nil
}

func (m *proxyManager) currentIP(_ *req.Client) (string, error) {
	proxy, err := url.Parse(m.stickyURL)
	if err != nil {
		return "", err
	}
	// The IP checker may reject the iOS TLS/User-Agent profile used for
	// DeepL. Use a plain HTTP client for identification only; translation
	// requests continue to use the iOS-shaped req client.
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxy)},
		Timeout:   10 * time.Second,
	}
	request, err := http.NewRequest(http.MethodGet, m.ipCheckURL, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "Mozilla/5.0")
	response, err := client.Do(request)
	if err != nil {
		return m.leaseIP(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return m.leaseIP(err)
	}
	if ip := parseIP(raw); ip != "" {
		return ip, nil
	}
	return m.leaseIP(fmt.Errorf("IP check returned an empty address"))
}

func parseIP(raw []byte) string {
	var payload struct {
		IP string `json:"ip"`
	}
	if json.Unmarshal(raw, &payload) == nil && strings.TrimSpace(payload.IP) != "" {
		return strings.TrimSpace(payload.IP)
	}
	if ip := strings.TrimSpace(gjson.ParseBytes(raw).Get("ip").String()); ip != "" {
		return ip
	}
	return ""
}

func (m *proxyManager) leaseIP(checkErr error) (string, error) {
	if m.adminToken == "" {
		return "", checkErr
	}
	endpoint := fmt.Sprintf("%s/api/v1/platforms/%s/leases/%s", strings.TrimRight(m.apiBase, "/"), url.PathEscape(m.platform), url.PathEscape(m.account))
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return "", checkErr
	}
	request.Header.Set("Authorization", "Bearer "+m.adminToken)
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		return "", checkErr
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err == nil {
		var lease struct {
			EgressIP string `json:"egress_ip"`
		}
		if json.Unmarshal(raw, &lease) == nil && strings.TrimSpace(lease.EgressIP) != "" {
			return strings.TrimSpace(lease.EgressIP), nil
		}
	}
	return "", checkErr
}

func (m *proxyManager) releaseLease(ctx context.Context) error {
	endpoint := fmt.Sprintf("%s/api/v1/platforms/%s/leases/%s", strings.TrimRight(m.apiBase, "/"), url.PathEscape(m.platform), url.PathEscape(m.account))
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}
	if m.adminToken != "" {
		request.Header.Set("Authorization", "Bearer "+m.adminToken)
	}
	// The lease API is the proxy provider's control plane. It must be reached
	// directly; service.Router configures http.DefaultTransport for upstream
	// translation traffic and would otherwise proxy this DELETE through Resin.
	apiClient := &http.Client{Transport: &http.Transport{}}
	response, err := apiClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("resin lease release returned HTTP %d", response.StatusCode)
	}
	return nil
}

// rotate releases the current sticky lease and creates a fresh client. The
// mutex keeps concurrent 429 responses from releasing the same lease twice.
func (m *proxyManager) rotate() (*req.Client, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	client := m.client
	if client == nil {
		var err error
		client, err = newOneshotClient(m.stickyURL)
		if err != nil {
			return nil, "", err
		}
		m.client = client
	}
	oldIP, ipErr := m.currentIP(client)
	if ipErr == nil {
		m.ip = oldIP
		_ = m.blacklist.Add(context.Background(), oldIP, m.cooldown)
	}
	if err := m.releaseLease(context.Background()); err != nil {
		// A proxy CONNECT can be rejected before Resin creates a lease.
		// In that case there is nothing to release; continue by creating a
		// fresh client so the sticky account can acquire a new exit.
		if !strings.Contains(err.Error(), "HTTP 404") {
			return nil, "", err
		}
	}

	newClient, err := newOneshotClient(m.stickyURL)
	if err != nil {
		return nil, "", err
	}
	m.client = newClient
	go warmCookies(newClient)
	newIP, err := m.currentIP(newClient)
	if err != nil {
		return newClient, "", err
	}
	m.ip = newIP
	return newClient, newIP, nil
}

func (m *proxyManager) isBlocked(ip string) bool {
	if ip == "" {
		return false
	}
	blocked, err := m.blacklist.Has(context.Background(), ip)
	return err == nil && blocked
}
