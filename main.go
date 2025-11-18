package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	dockerHubUpstream = "https://registry-1.docker.io"
	serviceName       = "docker-proxy"
	defaultListenAddr = ":8080"
	defaultTimeout    = 30 * time.Second
)

type proxyServer struct {
	cfg              config
	routes           map[string]string
	clientFollow     *http.Client
	clientNoRedirect *http.Client
	metricsRegistry  *prometheus.Registry
	metricsHandler   http.Handler
	requestsTotal    *prometheus.CounterVec
	requestDuration  *prometheus.HistogramVec
	bytesTransferred *prometheus.CounterVec
	imagePulls       *prometheus.CounterVec
}

type config struct {
	CustomDomain   string
	ListenAddr     string
	RequestTimeout time.Duration
}

type responseRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (rw *responseRecorder) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseRecorder) Write(b []byte) (int, error) {
	if rw.status == 0 {
		rw.status = http.StatusOK
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.bytes += int64(n)
	return n, err
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("配置错误: %v", err)
	}

	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        256,
		MaxIdleConnsPerHost: 128,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	reg := prometheus.NewRegistry()
	srv := &proxyServer{
		cfg:    cfg,
		routes: buildRoutes(cfg.CustomDomain),
		clientFollow: &http.Client{
			Transport: transport,
			Timeout:   cfg.RequestTimeout,
		},
		clientNoRedirect: &http.Client{
			Transport: transport,
			Timeout:   cfg.RequestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		metricsRegistry: reg,
		requestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "docker_proxy_requests_total", Help: "Total requests"},
			[]string{"source_ip", "domain", "status"},
		),
		requestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{Name: "docker_proxy_request_duration_seconds", Help: "Request duration"},
			[]string{"domain", "status"},
		),
		bytesTransferred: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "docker_proxy_bytes_transferred_total", Help: "Bytes transferred"},
			[]string{"domain", "direction"},
		),
		imagePulls: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "docker_proxy_image_pulls_total", Help: "Image pulls"},
			[]string{"image", "domain", "registry"},
		),
	}

	reg.MustRegister(srv.requestsTotal, srv.requestDuration, srv.bytesTransferred, srv.imagePulls)
	srv.metricsHandler = promhttp.HandlerFor(reg, promhttp.HandlerOpts{})

	log.Printf("启动服务 addr=%s domain=%s timeout=%s", cfg.ListenAddr, cfg.CustomDomain, cfg.RequestTimeout)
	for host, upstream := range srv.routes {
		log.Printf("路由 %s -> %s", host, upstream)
	}

	if err := http.ListenAndServe(cfg.ListenAddr, srv); err != nil {
		log.Fatalf("启动失败: %v", err)
	}
}

func loadConfig() (config, error) {
	domain := normalizeHost(os.Getenv("CUSTOM_DOMAIN"))
	if domain == "" {
		return config{}, errors.New("CUSTOM_DOMAIN 必须设置")
	}

	addr := strings.TrimSpace(os.Getenv("LISTEN_ADDR"))
	if addr == "" {
		addr = defaultListenAddr
	}

	timeout := defaultTimeout
	if raw := os.Getenv("REQUEST_TIMEOUT"); raw != "" {
		if t, err := time.ParseDuration(raw); err == nil && t > 0 {
			timeout = t
		}
	}

	return config{CustomDomain: domain, ListenAddr: addr, RequestTimeout: timeout}, nil
}

func buildRoutes(domain string) map[string]string {
	return map[string]string{
		"docker." + domain:         dockerHubUpstream,
		"docker-staging." + domain: dockerHubUpstream,
		"quay." + domain:           "https://quay.io",
		"gcr." + domain:            "https://gcr.io",
		"k8s-gcr." + domain:        "https://k8s.gcr.io",
		"k8s." + domain:            "https://registry.k8s.io",
		"ghcr." + domain:           "https://ghcr.io",
		"cloudsmith." + domain:     "https://docker.cloudsmith.io",
		"ecr." + domain:            "https://public.ecr.aws",
	}
}

func (ps *proxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec := &responseRecorder{ResponseWriter: w}
	start := time.Now()
	ip := getClientIP(r)
	host := normalizeHost(r.Host)

	defer func() {
		duration := time.Since(start)
		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}
		statusStr := strconv.Itoa(status)

		ps.requestsTotal.WithLabelValues(ip, host, statusStr).Inc()
		ps.requestDuration.WithLabelValues(host, statusStr).Observe(duration.Seconds())
		if rec.bytes > 0 {
			ps.bytesTransferred.WithLabelValues(host, "downstream").Add(float64(rec.bytes))
		}

		log.Printf("%s %s %s -> %d (%d bytes, %s) [%s]",
			r.Method, r.Host, r.URL.Path, status, rec.bytes, duration.Round(time.Millisecond), ip)
	}()

	// 特殊端点
	if r.URL.Path == "/metrics" {
		ps.metricsHandler.ServeHTTP(rec, r)
		return
	}
	if r.URL.Path == "/health" || r.URL.Path == "/" {
		ps.jsonResponse(rec, http.StatusOK, map[string]string{"status": "ok"})
		return
	}

	// 路由验证
	upstream := ps.routes[host]
	if upstream == "" {
		log.Printf("拒绝 host=%s path=%s ip=%s", r.Host, r.URL.Path, ip)
		ps.jsonResponse(rec, http.StatusForbidden, map[string]string{"error": "Forbidden"})
		return
	}

	// 记录镜像拉取
	if img := extractImage(r.URL.Path); img != "" {
		ps.imagePulls.WithLabelValues(img, host, strings.Split(host, ".")[0]).Inc()
	}

	ctx, cancel := context.WithTimeout(r.Context(), ps.cfg.RequestTimeout)
	defer cancel()

	// 处理请求
	switch r.URL.Path {
	case "/v2/":
		ps.proxyV2Root(rec, r.WithContext(ctx), upstream)
	case "/v2/auth":
		ps.proxyAuth(rec, r.WithContext(ctx), upstream)
	default:
		// Docker Hub library 前缀
		if upstream == dockerHubUpstream {
			if newPath := ensureLibrary(r.URL.Path); newPath != "" {
				scheme := "http"
				if r.TLS != nil {
					scheme = "https"
				} else if s := r.Header.Get("X-Forwarded-Proto"); s != "" {
					scheme = strings.Split(s, ",")[0]
				}
				http.Redirect(rec, r, scheme+"://"+r.Host+newPath, http.StatusMovedPermanently)
				return
			}
		}
		ps.proxyForward(rec, r.WithContext(ctx), upstream)
	}
}

func (ps *proxyServer) proxyV2Root(w http.ResponseWriter, r *http.Request, upstream string) {
	req, err := http.NewRequestWithContext(r.Context(), "GET", upstream+"/v2/", nil)
	if err != nil {
		ps.errorResponse(w, err)
		return
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}

	resp, err := ps.clientFollow.Do(req)
	if err != nil {
		ps.errorResponse(w, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		ps.unauthorizedResponse(w, r)
		return
	}
	ps.copyResponse(w, resp)
}

func (ps *proxyServer) proxyAuth(w http.ResponseWriter, r *http.Request, upstream string) {
	req, err := http.NewRequestWithContext(r.Context(), "GET", upstream+"/v2/", nil)
	if err != nil {
		ps.errorResponse(w, err)
		return
	}

	resp, err := ps.clientFollow.Do(req)
	if err != nil {
		ps.errorResponse(w, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		ps.copyResponse(w, resp)
		return
	}

	authHdr := resp.Header.Get("Www-Authenticate")
	if authHdr == "" {
		ps.copyResponse(w, resp)
		return
	}

	realm, service := parseAuth(authHdr)
	if realm == "" {
		ps.errorResponse(w, errors.New("invalid auth header"))
		return
	}

	scope := r.URL.Query().Get("scope")
	if scope != "" && upstream == dockerHubUpstream {
		parts := strings.SplitN(scope, ":", 3)
		if len(parts) == 3 && !strings.Contains(parts[1], "/") {
			scope = parts[0] + ":library/" + parts[1] + ":" + parts[2]
		}
	}

	tokenURL, _ := url.Parse(realm)
	q := tokenURL.Query()
	if service != "" {
		q.Set("service", service)
	}
	if scope != "" {
		q.Set("scope", scope)
	}
	tokenURL.RawQuery = q.Encode()

	tokenReq, _ := http.NewRequestWithContext(r.Context(), "GET", tokenURL.String(), nil)
	if auth := r.Header.Get("Authorization"); auth != "" {
		tokenReq.Header.Set("Authorization", auth)
	}

	tokenResp, err := ps.clientFollow.Do(tokenReq)
	if err != nil {
		ps.errorResponse(w, err)
		return
	}
	defer tokenResp.Body.Close()
	ps.copyResponse(w, tokenResp)
}

func (ps *proxyServer) proxyForward(w http.ResponseWriter, r *http.Request, upstream string) {
	target, _ := url.Parse(upstream)
	outURL := target.ResolveReference(&url.URL{Path: r.URL.Path, RawQuery: r.URL.RawQuery})

	req, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), r.Body)
	if err != nil {
		ps.errorResponse(w, err)
		return
	}
	req.Header = r.Header.Clone()
	req.Host = target.Host

	client := ps.clientFollow
	if upstream == dockerHubUpstream {
		client = ps.clientNoRedirect
	}

	resp, err := client.Do(req)
	if err != nil {
		ps.errorResponse(w, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		ps.unauthorizedResponse(w, r)
		return
	}

	// Docker Hub 重定向处理
	if upstream == dockerHubUpstream && resp.StatusCode == http.StatusTemporaryRedirect {
		if loc := resp.Header.Get("Location"); loc != "" {
			redirectReq, _ := http.NewRequestWithContext(r.Context(), "GET", loc, nil)
			redirectResp, err := ps.clientFollow.Do(redirectReq)
			if err != nil {
				ps.errorResponse(w, err)
				return
			}
			defer redirectResp.Body.Close()
			ps.copyResponse(w, redirectResp)
			return
		}
	}

	ps.copyResponse(w, resp)
}

func (ps *proxyServer) unauthorizedResponse(w http.ResponseWriter, r *http.Request) {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	} else if s := r.Header.Get("X-Forwarded-Proto"); s != "" {
		scheme = strings.Split(s, ",")[0]
	}

	host := normalizeHost(r.Host)
	if host == "" {
		host = ps.cfg.CustomDomain
	}

	w.Header().Set("Www-Authenticate", fmt.Sprintf(`Bearer realm="%s://%s/v2/auth",service="%s"`, scheme, host, serviceName))
	ps.jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
}

func (ps *proxyServer) copyResponse(w http.ResponseWriter, resp *http.Response) {
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (ps *proxyServer) errorResponse(w http.ResponseWriter, err error) {
	log.Printf("上游错误: %v", err)
	ps.jsonResponse(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
}

func (ps *proxyServer) jsonResponse(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// 工具函数

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}
	return r.RemoteAddr
}

func extractImage(path string) string {
	// /v2/{name}/(manifests|blobs|tags)/{ref}
	if !strings.HasPrefix(path, "/v2/") {
		return ""
	}
	parts := strings.Split(path, "/")
	if len(parts) < 5 {
		return ""
	}
	action := parts[len(parts)-2]
	if action == "manifests" || action == "blobs" || action == "tags" {
		return strings.Join(parts[2:len(parts)-2], "/")
	}
	return ""
}

func ensureLibrary(path string) string {
	// /v2/{name}/{action}/{ref} -> /v2/library/{name}/{action}/{ref}
	parts := strings.Split(path, "/")
	if len(parts) == 5 && parts[0] == "" && parts[1] == "v2" && parts[2] != "" && parts[2] != "library" {
		return "/v2/library/" + parts[2] + "/" + parts[3] + "/" + parts[4]
	}
	return ""
}

func parseAuth(header string) (realm, service string) {
	header = strings.TrimSpace(header)
	if strings.HasPrefix(strings.ToLower(header), "bearer ") {
		header = header[7:]
	}

	inQuote := false
	escape := false
	var key, val strings.Builder

	flush := func() {
		k := strings.ToLower(strings.TrimSpace(key.String()))
		v := strings.Trim(strings.TrimSpace(val.String()), `"`)
		if k == "realm" {
			realm = v
		} else if k == "service" {
			service = v
		}
		key.Reset()
		val.Reset()
	}

	inValue := false
	for _, c := range header {
		if escape {
			val.WriteRune(c)
			escape = false
			continue
		}
		if c == '\\' && inQuote {
			escape = true
			continue
		}
		if c == '"' {
			inQuote = !inQuote
			val.WriteRune(c)
			continue
		}
		if c == '=' && !inQuote {
			inValue = true
			continue
		}
		if c == ',' && !inQuote {
			flush()
			inValue = false
			continue
		}
		if inValue {
			val.WriteRune(c)
		} else {
			key.WriteRune(c)
		}
	}
	flush()
	return
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	if strings.HasPrefix(host, "[") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			return h
		}
		return strings.Trim(host, "[]")
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	if i := strings.Index(host, ":"); i > 0 {
		return host[:i]
	}
	return host
}
