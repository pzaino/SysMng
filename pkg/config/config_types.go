// Copyright 2023 Paolo Fabio Zaino
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package config is used to store functions and variables used to process the configuration
package config

// Config is the configuration structure
type Config struct {
	Remote Remote `json:"remote" yaml:"remote"` // Remote configuration

	API APIConfig `json:"api" yaml:"api"` // API configuration

	Events EventsConfig `json:"events" yaml:"events"` // Events configuration

	Prometheus PrometheusConfig `json:"prometheus" yaml:"prometheus"` // Prometheus configuration

	OS         string // Operating system name
	DebugLevel int    `json:"debug_level" yaml:"debug_level"` // Debug level for logging
}

// Remote represents a way to tell the CROWler to load a remote configuration
type Remote struct {
	Host    string `yaml:"host"`    // Hostname of the API server
	Path    string `yaml:"path"`    // Path to the storage (e.g., "/tmp/images" or Bucket name)
	Port    int    `yaml:"port"`    // Port number of the API server
	Region  string `yaml:"region"`  // Region of the storage (e.g., "us-east-1" when using S3 like services)
	Token   string `yaml:"token"`   // Token for API authentication (e.g., API key or token, AWS access key ID)
	Secret  string `yaml:"secret"`  // Secret for API authentication (e.g., AWS secret access key)
	Timeout int    `yaml:"timeout"` // Timeout for API requests (in seconds)
	Type    string `yaml:"type"`    // Type of storage (e.g., "local", "http", "volume", "queue", "s3")
	SSLMode string `yaml:"sslmode"` // SSL mode for API connection (e.g., "disable")
}

// APIConfig represents the system management API configuration
type APIConfig struct {
	Host              string `json:"host" yaml:"host"`                             // Hostname of the system management server
	Port              int    `json:"port" yaml:"port"`                             // Port number of the system management server
	Timeout           int    `json:"timeout" yaml:"timeout"`                       // Timeout for system management requests (in seconds)
	SSLMode           string `json:"sslmode" yaml:"sslmode"`                       // SSL mode for system management connection (e.g., "disable")
	CertFile          string `json:"cert_file" yaml:"cert_file"`                   // Path to the SSL certificate file
	KeyFile           string `json:"key_file" yaml:"key_file"`                     // Path to the SSL key file
	RateLimit         string `json:"rate_limit" yaml:"rate_limit"`                 // Rate limit values are tuples (for ex. "1,3") where 1 means allows 1 request per second with a burst of 3 requests
	ReadHeaderTimeout int    `json:"readheader_timeout" yaml:"readheader_timeout"` // ReadHeaderTimeout is the amount of time allowed to read request headers.
	ReadTimeout       int    `json:"read_timeout" yaml:"read_timeout"`             // ReadTimeout is the maximum duration for reading the entire request
	WriteTimeout      int    `json:"write_timeout" yaml:"write_timeout"`           // WriteTimeout
}

// EventsConfig represents the events service configuration
type EventsConfig struct {
	Enabled bool   `json:"enabled" yaml:"enabled"` // Whether to enable the events service or not
	Host    string `json:"host" yaml:"host"`       // Hostname of the events server
	Port    int    `json:"port" yaml:"port"`       // Port number of the events server
	SSLMode string `json:"sslmode" yaml:"sslmode"` // SSL mode for events connection (e.g., "disable")
	Timeout int    `json:"timeout" yaml:"timeout"` // Timeout for events requests (in seconds)
}

// PrometheusConfig represents the Prometheus configuration
type PrometheusConfig struct {
	Enabled bool   `json:"enabled" yaml:"enabled"` // Whether to enable Prometheus or not
	Host    string `json:"host" yaml:"host"`       // Hostname of the Prometheus server
	Port    int    `json:"port" yaml:"port"`       // Port number of the Prometheus server
}

// FileReader is an interface to read files
type FileReader interface {
	ReadFile(filename string) ([]byte, error)
}
