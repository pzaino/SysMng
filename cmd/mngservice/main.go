// Package main (SysMng) implements the CROWler VDI System Management.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/time/rate"

	cmn "github.com/pzaino/sysmng/pkg/common"
	cfg "github.com/pzaino/sysmng/pkg/config"
)

const (
	errTooManyRequests = "Too Many Requests"
	errRateLimitExceed = "Rate limit exceeded"
)

var (
	configFile  *string
	config      cfg.Config
	configMutex = &sync.Mutex{}
	limiter     *rate.Limiter
)

func main() {
	// Parse the command line arguments
	configFile = flag.String("config", "./config.yaml", "Path to the configuration file")
	flag.Parse()

	// Initialize the logger
	cmn.InitLogger("TheCROWlerSysMng")
	cmn.DebugMsg(cmn.DbgLvlInfo, "The CROWler VDI System Manager is starting...")

	// Setting up a channel to listen for termination signals
	cmn.DebugMsg(cmn.DbgLvlInfo, "Setting up termination signals listener...")
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)

	// Define signal handling
	go func() {
		for {
			sig := <-signals
			switch sig {
			case syscall.SIGINT:
				// Handle SIGINT (Ctrl+C)
				cmn.DebugMsg(cmn.DbgLvlInfo, "SIGINT received, shutting down...")
				os.Exit(0)

			case syscall.SIGTERM:
				// Handle SIGTERM
				cmn.DebugMsg(cmn.DbgLvlInfo, "SIGTERM received, shutting down...")
				os.Exit(0)

			case syscall.SIGQUIT:
				// Handle SIGQUIT
				cmn.DebugMsg(cmn.DbgLvlInfo, "SIGQUIT received, shutting down...")
				os.Exit(0)

			case syscall.SIGHUP:
				// Handle SIGHUP
				cmn.DebugMsg(cmn.DbgLvlInfo, "SIGHUP received, will reload configuration as soon as all pending jobs are completed...")
				configMutex.Lock()
				err := initAll(configFile, &config, &limiter)
				if err != nil {
					configMutex.Unlock()
					cmn.DebugMsg(cmn.DbgLvlFatal, "Error initializing the crawler: %v", err)
				}
				configMutex.Unlock()
			}
		}
	}()

	// Initialize the configuration
	err := initAll(configFile, &config, &limiter)
	if err != nil {
		cmn.DebugMsg(cmn.DbgLvlFatal, "Error initializing the crawler: %v", err)
		os.Exit(-1)
	}

	srv := &http.Server{
		Addr: config.API.Host + ":" + fmt.Sprintf("%d", config.API.Port),

		// ReadHeaderTimeout is the amount of time allowed to read
		// request headers. The connection's read deadline is reset
		// after reading the headers and the Handler can decide what
		// is considered too slow for the body. If ReadHeaderTimeout
		// is zero, the value of ReadTimeout is used. If both are
		// zero, there is no timeout.
		ReadHeaderTimeout: time.Duration(config.API.ReadHeaderTimeout) * time.Second,

		// ReadTimeout is the maximum duration for reading the entire
		// request, including the body. A zero or negative value means
		// there will be no timeout.
		//
		// Because ReadTimeout does not let Handlers make per-request
		// decisions on each request body's acceptable deadline or
		// upload rate, most users will prefer to use
		// ReadHeaderTimeout. It is valid to use them both.
		ReadTimeout: time.Duration(config.API.ReadTimeout) * time.Second,

		// WriteTimeout is the maximum duration before timing out
		// writes of the response. It is reset whenever a new
		// request's header is read. Like ReadTimeout, it does not
		// let Handlers make decisions on a per-request basis.
		// A zero or negative value means there will be no timeout.
		WriteTimeout: time.Duration(config.API.WriteTimeout) * time.Second,

		// IdleTimeout is the maximum amount of time to wait for the
		// next request when keep-alive are enabled. If IdleTimeout
		// is zero, the value of ReadTimeout is used. If both are
		// zero, there is no timeout.
		IdleTimeout: time.Duration(config.API.Timeout) * time.Second,
	}

	runtime.GOMAXPROCS(runtime.NumCPU())

	// Set the handlers
	initAPIv1()

	cmn.DebugMsg(cmn.DbgLvlInfo, "Starting server on %s:%d", config.API.Host, config.API.Port)
	if strings.ToLower(strings.TrimSpace(config.API.SSLMode)) == "enable" {
		cmn.DebugMsg(cmn.DbgLvlFatal, "Server return: %v", srv.ListenAndServeTLS(config.API.CertFile, config.API.KeyFile))
	}
	cmn.DebugMsg(cmn.DbgLvlFatal, "Server return: %v", srv.ListenAndServe())
}

func initAll(configFile *string, config *cfg.Config, lmt **rate.Limiter) error {
	// Reading the configuration file
	var err error
	*config, err = cfg.LoadConfig(*configFile)
	if err != nil {
		cmn.DebugMsg(cmn.DbgLvlFatal, "Error reading config file: %v", err)
	}
	if cfg.IsEmpty(*config) {
		cmn.DebugMsg(cmn.DbgLvlFatal, "Config file is empty")
	}

	// Set the OS variable
	config.OS = runtime.GOOS

	// Set the rate limiter
	var rl, bl int
	if strings.TrimSpace(config.API.RateLimit) == "" {
		config.API.RateLimit = "10,10"
	}
	if !strings.Contains(config.API.RateLimit, ",") {
		config.API.RateLimit = config.API.RateLimit + ",10"
	}
	rlStr := strings.Split(config.API.RateLimit, ",")[0]
	if rlStr == "" {
		rlStr = "10"
	}
	rl, err = strconv.Atoi(rlStr)
	if err != nil {
		rl = 10
	}
	blStr := strings.Split(config.API.RateLimit, ",")[1]
	if blStr == "" {
		blStr = "10"
	}
	bl, err = strconv.Atoi(blStr)
	if err != nil {
		bl = 10
	}
	*lmt = rate.NewLimiter(rate.Limit(rl), bl)

	return nil
}

// initAPIv1 initializes the API v1 handlers
func initAPIv1() {
	// Health check
	healthCheckWithMiddlewares := SecurityHeadersMiddleware(RateLimitMiddleware(http.HandlerFunc(healthCheckHandler)))
	http.Handle("/v1/health", healthCheckWithMiddlewares)

	// Set System Proxy
	proxyWithMiddlewares := SecurityHeadersMiddleware(RateLimitMiddleware(http.HandlerFunc(proxyHandler)))
	http.Handle("/v1/set_proxy", proxyWithMiddlewares)

}

// RateLimitMiddleware is a middleware for rate limiting
func RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			cmn.DebugMsg(cmn.DbgLvlDebug, errRateLimitExceed)
			http.Error(w, errTooManyRequests, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SecurityHeadersMiddleware adds security-related headers to responses
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add various security headers here
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")

		next.ServeHTTP(w, r)
	})
}

func healthCheckHandler(w http.ResponseWriter, _ *http.Request) {
	// Create a JSON document with the health status
	healthStatus := HealthCheck{
		Status: "OK",
	}

	// Respond with the health status
	handleErrorAndRespond(w, nil, healthStatus, "Error in health Check: ", http.StatusInternalServerError, http.StatusOK)
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleGetProxy(w)
	case http.MethodPost:
		handleSetProxy(w, r)
	case http.MethodDelete:
		handleDeleteProxy(w)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleGetProxy(w http.ResponseWriter) {
	// Respond with the proxy settings
	handleErrorAndRespond(w, nil, json.NewEncoder(w).Encode(currentProxy), "Error getting proxy settings: ", http.StatusInternalServerError, http.StatusOK)
}

func handleSetProxy(w http.ResponseWriter, r *http.Request) {
	var newProxy ProxySettings
	err := json.NewDecoder(r.Body).Decode(&newProxy)
	if err != nil {
		handleErrorAndRespond(w, nil, json.NewEncoder(w).Encode(currentProxy), "Error decoding JSON: "+err.Error(), http.StatusBadRequest, http.StatusOK)
		return
	}

	handleUpdateNoProxy(w, r)

	currentProxy = newProxy

	// Respond with the proxy settings
	handleErrorAndRespond(w, nil, json.NewEncoder(w).Encode(currentProxy), "Error setting proxy settings: ", http.StatusInternalServerError, http.StatusOK)
}

func handleDeleteProxy(w http.ResponseWriter) {
	settings := ProxySettings{}
	if err := setProxy(settings); err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete proxy: %v", err), http.StatusInternalServerError)
		return
	}

	currentProxy = settings

	// Respond with the proxy settings
	handleErrorAndRespond(w, nil, json.NewEncoder(w).Encode(currentProxy), "Error deleting proxy settings: ", http.StatusInternalServerError, http.StatusOK)
}

func setProxy(settings ProxySettings) error {
	noProxy := ""
	if len(settings.NoProxy) > 0 {
		noProxy = fmt.Sprintf("'%s'", settings.NoProxy[0]) // Start building string
		for _, np := range settings.NoProxy[1:] {
			noProxy += fmt.Sprintf(",%s", np)
		}
	}

	commands := []string{
		fmt.Sprintf("echo 'http_proxy=%s' | sudo tee /etc/environment > /dev/null", settings.HTTPProxy),
		fmt.Sprintf("echo 'https_proxy=%s' | sudo tee /etc/environment > /dev/null", settings.HTTPSProxy),
		fmt.Sprintf("echo 'no_proxy=%s' | sudo tee -a /etc/environment > /dev/null", noProxy),
	}

	for _, cmd := range commands {
		if err := exec.Command("bash", "-c", cmd).Run(); err != nil { //nolint:gosec // This is a trusted command
			return fmt.Errorf("command failed: %s, error: %v", cmd, err)
		}
	}
	return nil
}

// LoadProxySettings loads the proxy settings from a file
func LoadProxySettings(filename string) {
	file, err := os.Open(filename) //nolint:gosec // This is a trusted path
	if err != nil {
		cmn.DebugMsg(cmn.DbgLvlError, "No existing proxy configuration found: %v", err)
		return
	}
	defer file.Close() //nolint:errcheck // We can't check returned error when using defer

	if err := json.NewDecoder(file).Decode(&currentProxy); err != nil {
		cmn.DebugMsg(cmn.DbgLvlError, "Failed to load proxy settings: %v", err)
	}
}

// SaveProxySettings saves the proxy settings to a file
func SaveProxySettings(filename string) {
	file, err := os.Create(filename) //nolint:gosec // This is a trusted path
	if err != nil {
		log.Printf("Failed to save proxy configuration: %v", err)
		return
	}
	defer file.Close() //nolint:errcheck // We can't check returned error when using defer

	if err := json.NewEncoder(file).Encode(currentProxy); err != nil {
		cmn.DebugMsg(cmn.DbgLvlError, "Failed to write proxy settings: %v", err)
	}
}

func handleUpdateNoProxy(w http.ResponseWriter, r *http.Request) {
	var update struct {
		Add    []string `json:"add"`
		Remove []string `json:"remove"`
	}

	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		handleErrorAndRespond(w, err, json.NewEncoder(w).Encode(currentProxy), fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest, http.StatusOK)
		return
	}

	noProxy := currentProxy.NoProxy
	for _, addr := range update.Add {
		if !contains(noProxy, addr) {
			noProxy = append(noProxy, addr)
		}
	}
	for _, addr := range update.Remove {
		noProxy = remove(noProxy, addr)
	}

	currentProxy.NoProxy = noProxy
	if err := setProxy(currentProxy); err != nil {
		handleErrorAndRespond(w, err, json.NewEncoder(w).Encode(currentProxy), fmt.Sprintf("Failed to update no_proxy: %v", err), http.StatusInternalServerError, http.StatusOK)
		return
	}

	// Respond with the proxy settings
	handleErrorAndRespond(w, nil, json.NewEncoder(w).Encode(currentProxy), "Error deleting proxy settings: ", http.StatusInternalServerError, http.StatusOK)
}

func contains(list []string, item string) bool {
	for _, elem := range list {
		if elem == item {
			return true
		}
	}
	return false
}

func remove(list []string, item string) []string {
	result := []string{}
	for _, elem := range list {
		if elem != item {
			result = append(result, elem)
		}
	}
	return result
}

func determineLocalNetworks() ([]string, error) {
	var localNetworks []string

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %v", err)
	}

	for _, iface := range interfaces {
		// Skip interfaces that are down or don't support IPs
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("failed to get addresses for interface %s: %v", iface.Name, err)
		}

		for _, addr := range addrs {
			// Only process IPNet addresses (IP + subnet mask)
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() {
				continue
			}

			// Check if the IP is in a private range
			if isPrivateIP(ipNet.IP) {
				localNetworks = append(localNetworks, ipNet.String())
			}
		}
	}

	return localNetworks, nil
}

func isPrivateIP(ip net.IP) bool {
	privateBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, block := range privateBlocks {
		_, cidr, _ := net.ParseCIDR(block)
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}
