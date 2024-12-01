// Package main (sysmng) implements the CROWler VDI System Management.
package main

// HealthCheck is a struct that holds the health status of the application.
type HealthCheck struct {
	Status string `json:"status"`
}

// ProxySettings is a struct that holds the proxy settings for the application.
type ProxySettings struct {
	HTTPProxy  string   `json:"http_proxy"`
	HTTPSProxy string   `json:"https_proxy"`
	NoProxy    []string `json:"no_proxy"` // Array for multiple exceptions
}

var currentProxy ProxySettings
