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
)

const (
	dockerHubUpstream = "https://registry-1.docker.io"
	serviceName       = "docker-proxy"
	defaultListenAddr = ":8080"
)

type config struct {
	CustomDomain   string
	Mode           string
	TargetUpstream string
	ListenAddr     string
	RequestTimeout time.Duration
}

type proxyServer struct {
	cfg              config
	routes           map[string]string
	clientFollow     *http.Client
	clientNoRedirect *http.Client
}

type authenticateHeader struct {
	Realm   string
	Service string
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

	clientFollow := &http.Client{
		Transport: transport,
		Timeout:   cfg.RequestTimeout,
	}

	clientNoRedirect := &http.Client{
		Transport: transport,
		Timeout:   cfg.RequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	srv := &proxyServer{
		cfg:              cfg,
		routes:           buildRoutes(cfg.CustomDomain),
		clientFollow:     clientFollow,
		clientNoRedirect: clientNoRedirect,
	}

	log.Printf("Docker proxy server started on %s (mode=%s)", cfg.ListenAddr, cfg.Mode)
	if err := http.ListenAndServe(cfg.ListenAddr, srv); err != nil {
		log.Fatalf("服务器运行失败: %v", err)
	}
}

func loadConfig() (config, error) {
	customDomain := strings.TrimSpace(os.Getenv("CUSTOM_DOMAIN"))
	if customDomain == "" {
		return config{}, errors.New("必须设置环境变量 CUSTOM_DOMAIN")
	}
	customDomain = normalizeHost(customDomain)
	if customDomain == "" {
		return config{}, errors.New("CUSTOM_DOMAIN 格式不正确")
	}

	mode := strings.TrimSpace(os.Getenv("MODE"))
	if mode == "" {
		mode = "production"
	}

	targetUpstream := strings.TrimSpace(os.Getenv("TARGET_UPSTREAM"))
	if targetUpstream == "" {
		targetUpstream = dockerHubUpstream
	}

	listenAddr := strings.TrimSpace(os.Getenv("LISTEN_ADDR"))
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}

	timeout := 30 * time.Second
	if raw := strings.TrimSpace(os.Getenv("REQUEST_TIMEOUT")); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil {
			timeout = parsed
		}
	}

	return config{
		CustomDomain:   customDomain,
		Mode:           strings.ToLower(mode),
		TargetUpstream: targetUpstream,
		ListenAddr:     listenAddr,
		RequestTimeout: timeout,
	}, nil
}

func buildRoutes(customDomain string) map[string]string {
	return map[string]string{
		"docker." + customDomain:         dockerHubUpstream,
		"quay." + customDomain:           "https://quay.io",
		"gcr." + customDomain:            "https://gcr.io",
		"k8s-gcr." + customDomain:        "https://k8s.gcr.io",
		"k8s." + customDomain:            "https://registry.k8s.io",
		"ghcr." + customDomain:           "https://ghcr.io",
		"cloudsmith." + customDomain:     "https://docker.cloudsmith.io",
		"ecr." + customDomain:            "https://public.ecr.aws",
		"docker-staging." + customDomain: dockerHubUpstream,
	}
}

func (ps *proxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), ps.cfg.RequestTimeout)
	defer cancel()
	r = r.WithContext(ctx)

	if r.URL.Path == "/" {
		target := fmt.Sprintf("%s://%s/v2/", schemeFromRequest(r), r.Host)
		http.Redirect(w, r, target, http.StatusMovedPermanently)
		return
	}

	upstream := ps.routeByHost(normalizeHost(r.Host))
	if upstream == "" {
		ps.respondJSON(w, http.StatusNotFound, map[string]any{"routes": ps.routes})
		return
	}

	switch r.URL.Path {
	case "/v2/":
		ps.handleV2Root(w, r, upstream)
		return
	case "/v2/auth":
		ps.handleToken(w, r, upstream)
		return
	}

	if upstream == dockerHubUpstream {
		if newPath, ok := ensureLibraryPath(r.URL.Path); ok {
			target := fmt.Sprintf("%s://%s%s", schemeFromRequest(r), r.Host, newPath)
			http.Redirect(w, r, target, http.StatusMovedPermanently)
			return
		}
	}

	ps.forwardRequest(w, r, upstream)
}

func (ps *proxyServer) routeByHost(host string) string {
	if upstream, ok := ps.routes[host]; ok {
		return upstream
	}
	if ps.cfg.Mode == "debug" {
		return ps.cfg.TargetUpstream
	}
	return ""
}

func (ps *proxyServer) handleV2Root(w http.ResponseWriter, r *http.Request, upstream string) {
	target, err := url.Parse(upstream + "/v2/")
	if err != nil {
		ps.gatewayError(w, err)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target.String(), nil)
	if err != nil {
		ps.gatewayError(w, err)
		return
	}

	if auth := r.Header.Get("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}

	resp, err := ps.clientFollow.Do(req)
	if err != nil {
		ps.gatewayError(w, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		ps.responseUnauthorized(w, r)
		return
	}

	copyResponse(w, resp)
}

func (ps *proxyServer) handleToken(w http.ResponseWriter, r *http.Request, upstream string) {
	checkURL, err := url.Parse(upstream + "/v2/")
	if err != nil {
		ps.gatewayError(w, err)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, checkURL.String(), nil)
	if err != nil {
		ps.gatewayError(w, err)
		return
	}

	resp, err := ps.clientFollow.Do(req)
	if err != nil {
		ps.gatewayError(w, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		copyResponse(w, resp)
		return
	}

	headerValue := resp.Header.Get("Www-Authenticate")
	if headerValue == "" {
		copyResponse(w, resp)
		return
	}

	parsed, err := parseAuthenticate(headerValue)
	if err != nil {
		ps.gatewayError(w, err)
		return
	}

	scope := r.URL.Query().Get("scope")
	if scope != "" && upstream == dockerHubUpstream {
		scope = ensureLibraryScope(scope)
	}

	tokenResp, err := ps.fetchToken(r.Context(), parsed, scope, r.Header.Get("Authorization"))
	if err != nil {
		ps.gatewayError(w, err)
		return
	}
	defer tokenResp.Body.Close()

	copyResponse(w, tokenResp)
}

func (ps *proxyServer) fetchToken(ctx context.Context, authenticate authenticateHeader, scope, authorization string) (*http.Response, error) {
	tokenURL, err := url.Parse(authenticate.Realm)
	if err != nil {
		return nil, err
	}

	query := tokenURL.Query()
	if authenticate.Service != "" {
		query.Set("service", authenticate.Service)
	}
	if scope != "" {
		query.Set("scope", scope)
	}
	tokenURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL.String(), nil)
	if err != nil {
		return nil, err
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}

	return ps.clientFollow.Do(req)
}

func (ps *proxyServer) forwardRequest(w http.ResponseWriter, r *http.Request, upstream string) {
	targetBase, err := url.Parse(upstream)
	if err != nil {
		ps.gatewayError(w, err)
		return
	}

	outURL := targetBase.ResolveReference(&url.URL{
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	})

	req, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), r.Body)
	if err != nil {
		ps.gatewayError(w, err)
		return
	}

	req.Header = r.Header.Clone()
	req.Host = targetBase.Host

	client := ps.clientFollow
	if upstream == dockerHubUpstream {
		client = ps.clientNoRedirect
	}

	resp, err := client.Do(req)
	if err != nil {
		ps.gatewayError(w, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		ps.responseUnauthorized(w, r)
		return
	}

	if upstream == dockerHubUpstream && resp.StatusCode == http.StatusTemporaryRedirect {
		location := resp.Header.Get("Location")
		if location == "" {
			copyResponse(w, resp)
			return
		}
		redirectReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, location, nil)
		if err != nil {
			ps.gatewayError(w, err)
			return
		}
		redirectResp, err := ps.clientFollow.Do(redirectReq)
		if err != nil {
			ps.gatewayError(w, err)
			return
		}
		defer redirectResp.Body.Close()
		copyResponse(w, redirectResp)
		return
	}

	copyResponse(w, resp)
}

func parseAuthenticate(header string) (authenticateHeader, error) {
	var result authenticateHeader
	header = strings.TrimSpace(header)
	if header == "" {
		return result, errors.New("空的 WWW-Authenticate 头")
	}

	lower := strings.ToLower(header)
	if strings.HasPrefix(lower, "bearer ") {
		header = header[len("Bearer "):]
	} else if strings.HasPrefix(lower, "bearer\t") {
		header = header[len("Bearer\t"):]
	}

	for _, token := range splitAuthParams(header) {
		if token == "" {
			continue
		}
		keyValue := strings.SplitN(token, "=", 2)
		if len(keyValue) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(keyValue[0]))
		value := strings.TrimSpace(keyValue[1])
		if decoded, err := strconv.Unquote(value); err == nil {
			value = decoded
		} else {
			value = strings.Trim(value, `"`)
		}
		switch key {
		case "realm":
			result.Realm = value
		case "service":
			result.Service = value
		}
	}

	if result.Realm == "" {
		return result, fmt.Errorf("无效的 WWW-Authenticate 头: %s", header)
	}
	return result, nil
}

func splitAuthParams(header string) []string {
	var parts []string
	var buf strings.Builder
	inQuotes := false
	escape := false

	for _, r := range header {
		switch {
		case escape:
			buf.WriteRune(r)
			escape = false
		case r == '\\' && inQuotes:
			escape = true
		case r == '"':
			inQuotes = !inQuotes
			buf.WriteRune(r)
		case r == ',' && !inQuotes:
			parts = append(parts, strings.TrimSpace(buf.String()))
			buf.Reset()
		default:
			buf.WriteRune(r)
		}
	}
	if buf.Len() > 0 {
		parts = append(parts, strings.TrimSpace(buf.String()))
	}
	return parts
}

func ensureLibraryPath(path string) (string, bool) {
	parts := strings.Split(path, "/")
	if len(parts) == 5 && parts[0] == "" && parts[1] == "v2" && parts[2] != "library" {
		newParts := append([]string{}, parts[:2]...)
		newParts = append(newParts, "library")
		newParts = append(newParts, parts[2:]...)
		return strings.Join(newParts, "/"), true
	}
	return "", false
}

func ensureLibraryScope(scope string) string {
	splits := strings.Split(scope, ":")
	if len(splits) == 3 && !strings.Contains(splits[1], "/") {
		splits[1] = "library/" + splits[1]
		return strings.Join(splits, ":")
	}
	return scope
}

func (ps *proxyServer) responseUnauthorized(w http.ResponseWriter, r *http.Request) {
	scheme := "https"
	host := r.Host
	if ps.cfg.Mode == "debug" {
		scheme = "http"
	}
	if ps.cfg.Mode != "debug" {
		host = normalizeHost(host)
	}
	realm := fmt.Sprintf(`Bearer realm="%s://%s/v2/auth",service="%s"`, scheme, host, serviceName)
	w.Header().Set("Www-Authenticate", realm)
	ps.respondJSON(w, http.StatusUnauthorized, map[string]string{"message": "UNAUTHORIZED"})
}

func (ps *proxyServer) gatewayError(w http.ResponseWriter, err error) {
	log.Printf("上游请求失败: %v", err)
	ps.respondJSON(w, http.StatusBadGateway, map[string]string{
		"message": "BAD_GATEWAY",
		"error":   err.Error(),
	})
}

func (ps *proxyServer) respondJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func copyResponse(w http.ResponseWriter, resp *http.Response) {
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
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
	if idx := strings.Index(host, ":"); idx > 0 {
		return host[:idx]
	}
	return host
}

func schemeFromRequest(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if scheme := r.Header.Get("X-Forwarded-Proto"); scheme != "" {
		if idx := strings.Index(scheme, ","); idx > 0 {
			return strings.TrimSpace(scheme[:idx])
		}
		return strings.TrimSpace(scheme)
	}
	return "http"
}
