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

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	cmn "github.com/pzaino/thecrowler/pkg/common"

	"gopkg.in/yaml.v2"
)

const (
	//nolint:errcheck // Don't lint for error not checked, this is a defer statement
	// PluginsDefaultPath Default plugins path
	PluginsDefaultPath = "./plugins/*.js"
	// JSONRulesDefaultPath Default rules path for json rules
	JSONRulesDefaultPath = "./rules/*.json"
	// YAMLRulesDefaultPath1 Default rules path for yaml rules
	YAMLRulesDefaultPath1 = "./rules/*.yaml"
	// YAMLRulesDefaultPath2 Default rules path for yaml rules
	YAMLRulesDefaultPath2 = "./rules/*.yml"
	// DataDefaultPath Default data path
	DataDefaultPath = "./data"
	// SSDefaultTimeProfile Default time profile for service scout
	SSDefaultTimeProfile = 3
	// SSDefaultTimeout Default timeout for service scout
	SSDefaultTimeout = 3600
	// SSDefaultDelayTime Default delay time for service scout
	SSDefaultDelayTime = 100
)

// RemoteFetcher is an interface for fetching remote files.
type RemoteFetcher interface {
	FetchRemoteFile(url string, timeout int, sslMode string) (string, error)
}

// CMNFetcher is a fetcher that uses the common package to fetch remote files.
type CMNFetcher struct{}

// FetchRemoteFile fetches a remote file using the common package.
func (f *CMNFetcher) FetchRemoteFile(url string, timeout int, sslMode string) (string, error) {
	return cmn.FetchRemoteFile(url, timeout, sslMode)
}

// OsFileReader is a file reader that uses the os package to read files.
type OsFileReader struct{}

// ReadFile reads a file using the os package.
func (OsFileReader) ReadFile(filename string) ([]byte, error) {
	return os.ReadFile(filename)
}

// fileExists checks if a file exists at the given filename.
// It returns true if the file exists and is not a directory, and false otherwise.
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// recursiveInclude processes the include statements in the YAML content.
func recursiveInclude(yamlContent string, baseDir string, reader FileReader) (string, error) {
	includePattern := regexp.MustCompile(`include:\s*["']?([^"'\s]+)["']?`)
	matches := includePattern.FindAllStringSubmatch(yamlContent, -1)

	for _, match := range matches {
		includePath := cmn.InterpolateEnvVars(match[1])
		includePath = filepath.Join(baseDir, includePath)

		includedContentBytes, err := reader.ReadFile(includePath)
		if err != nil {
			return "", err
		}

		includedContent := string(includedContentBytes)
		if strings.Contains(includedContent, "include:") {
			includedContent, err = recursiveInclude(includedContent, filepath.Dir(includePath), reader)
			if err != nil {
				return "", err
			}
		}

		yamlContent = strings.Replace(yamlContent, match[0], includedContent, 1)
	}

	return yamlContent, nil
}

// getConfigFile reads and unmarshals a configuration file with the given name.
// It checks if the file exists, reads its contents, and unmarshals it into a Config struct.
// If the file does not exist or an error occurs during reading or unmarshaling, an error is returned.
func getConfigFile(confName string) (Config, error) {

	// Create a new configuration object
	config := *NewConfig()

	// Check if the configuration file exists
	if !fileExists(confName) {
		return Config{}, fmt.Errorf("file does not exist: %s", confName)
	}

	// Read the configuration file
	data, err := os.ReadFile(confName)
	if err != nil {
		return Config{}, err
	}

	baseDir := filepath.Dir(confName)

	// Interpolate environment variables and process includes
	interpolatedData := cmn.InterpolateEnvVars(string(data))

	finalData, err := recursiveInclude(interpolatedData, baseDir, OsFileReader{})
	if err != nil {
		return Config{}, err
	}

	// If the configuration file has been found and is not empty, unmarshal it
	if (finalData != "") && (finalData != "\n") && (finalData != "\r\n") {
		err = yaml.Unmarshal([]byte(finalData), &config)
	}

	return config, err
}

// NewConfig returns a new Config struct with default values.
func NewConfig() *Config {
	return &Config{
		Remote: Remote{
			Host:    "localhost",
			Path:    "/",
			Port:    0,
			Region:  "nowhere",
			Token:   "",
			Secret:  "",
			Timeout: 15,
			Type:    "local",
			SSLMode: "disable",
		},
		API: APIConfig{
			Host:              "localhost",
			Port:              8080,
			Timeout:           60,
			SSLMode:           "disable",
			CertFile:          "",
			KeyFile:           "",
			RateLimit:         "10,10",
			ReadHeaderTimeout: 15,
			ReadTimeout:       15,
			WriteTimeout:      30,
		},
		Prometheus: PrometheusConfig{
			Enabled: false,
			Port:    9091,
		},
		Events: EventsConfig{
			Host:    "localhost",
			Port:    8082,
			SSLMode: "disable",
			Timeout: 60,
		},
		OS:         runtime.GOOS,
		DebugLevel: 0,
	}
}

// LoadConfig is responsible for loading the configuration file
// and return the Config struct
func LoadConfig(confName string) (Config, error) {

	// Get the configuration file
	config, err := getConfigFile(confName)
	if err != nil {
		return Config{}, err
	}

	// Check if the configuration file is empty
	if IsEmpty(config) {
		return Config{}, fmt.Errorf("configuration file is empty")
	}

	if (config.Remote != (Remote{})) && (config.Remote.Type == "remote") {
		// This local configuration references a remote configuration
		// Load the remote configuration
		fetcher := &CMNFetcher{}
		config, err = LoadRemoteConfig(config, fetcher)
		if err != nil {
			return config, err
		}
	}

	// Check if the configuration file contains valid values
	if !config.IsEmpty() {
		err = config.Validate()
		if err != nil {
			return config, err
		}
	}

	// cast config.DebugLevel to common.DbgLevel
	var dbgLvl cmn.DbgLevel = cmn.DbgLevel(config.DebugLevel)

	// Set the debug level
	cmn.SetDebugLevel(dbgLvl)

	cmn.DebugMsg(cmn.DbgLvlDebug5, "Configuration file loaded: %#v", config)

	return config, err
}

// LoadRemoteConfig is responsible for retrieving the configuration file
// from a "remote" distribution server and return the Config struct
func LoadRemoteConfig(cfg Config, fetcher RemoteFetcher) (Config, error) {
	// Create a new configuration object
	config := *NewConfig()

	// Check if the remote configuration is empty
	if cfg.Remote == (Remote{}) {
		return Config{}, fmt.Errorf("remote configuration is empty")
	}

	// Check if the remote configuration contains valid values
	err := cfg.validateRemote()
	if err != nil {
		return Config{}, err
	}

	// Create a RESTClient object
	if strings.TrimSpace(config.Remote.Path) == "/" {
		config.Remote.Path = ""
	}
	url := fmt.Sprintf("http://%s/%s", config.Remote.Host, config.Remote.Path)
	rulesetBody, err := fetcher.FetchRemoteFile(url, config.Remote.Timeout, config.Remote.SSLMode)
	if err != nil {
		return config, fmt.Errorf("failed to fetch rules from %s: %v", url, err)
	}

	// Process ENV variables
	interpolatedData := cmn.InterpolateEnvVars(rulesetBody)

	// If the configuration file has been found and is not empty, unmarshal it
	interpolatedData = strings.TrimSpace(interpolatedData)
	if (interpolatedData != "") && (interpolatedData != "\n") && (interpolatedData != "\r\n") {
		err = yaml.Unmarshal([]byte(interpolatedData), &config)
		if err != nil {
			return config, err
		}
	}

	// Check if the configuration is correct:
	err = config.Validate()
	if err != nil {
		return config, err
	}

	return config, nil
}

// ParseConfig parses the configuration file and returns a Config struct.
func ParseConfig(data []byte) (*Config, error) {
	var cfg Config
	err := yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}
	err = cfg.Validate()
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks if the configuration file contains valid values.
// Where possible, if a provided value is wrong, it's replaced with a default value.
func (c *Config) Validate() error {
	c.validateAPI()
	c.validatePrometheus()
	c.validateOS()
	c.validateDebugLevel()

	return nil
}

func (c *Config) validateRemote() error {
	c.validateRemoteHost()
	c.validateRemotePath()
	c.validateRemotePort()
	c.validateRemoteRegion()
	c.validateRemoteToken()
	c.validateRemoteSecret()
	c.validateRemoteTimeout()
	c.validateRemoteType()
	c.validateRemoteSSLMode()
	return nil
}

func (c *Config) validateRemoteHost() {
	if strings.TrimSpace(c.Remote.Host) == "" {
		c.Remote.Host = "localhost"
	} else {
		c.Remote.Host = strings.TrimSpace(c.Remote.Host)
	}
}

func (c *Config) validateRemotePath() {
	if strings.TrimSpace(c.Remote.Path) == "" {
		c.Remote.Path = "/"
	} else {
		c.Remote.Path = strings.TrimSpace(c.Remote.Path)
	}
}

func (c *Config) validateRemotePort() {
	if c.Remote.Port < 1 || c.Remote.Port > 65535 {
		c.Remote.Port = 8081
	}
}

func (c *Config) validateRemoteRegion() {
	if strings.TrimSpace(c.Remote.Region) == "" {
		c.Remote.Region = ""
	} else {
		c.Remote.Region = strings.TrimSpace(c.Remote.Region)
	}
}

func (c *Config) validateRemoteToken() {
	if strings.TrimSpace(c.Remote.Token) == "" {
		c.Remote.Token = ""
	} else {
		c.Remote.Token = strings.TrimSpace(c.Remote.Token)
	}
}

func (c *Config) validateRemoteSecret() {
	if strings.TrimSpace(c.Remote.Secret) == "" {
		c.Remote.Secret = ""
	} else {
		c.Remote.Secret = strings.TrimSpace(c.Remote.Secret)
	}
}

func (c *Config) validateRemoteTimeout() {
	if c.Remote.Timeout < 1 {
		c.Remote.Timeout = 15
	}
}

func (c *Config) validateRemoteType() {
	if strings.TrimSpace(c.Remote.Type) == "" {
		c.Remote.Type = "local"
	} else {
		c.Remote.Type = strings.TrimSpace(c.Remote.Type)
	}
}

func (c *Config) validateRemoteSSLMode() {
	if strings.TrimSpace(c.Remote.SSLMode) == "" {
		c.Remote.SSLMode = "disable"
	} else {
		c.Remote.SSLMode = strings.ToLower(strings.TrimSpace(c.Remote.SSLMode))
	}
}

func (c *Config) validateAPI() {
	// Check API
	if strings.TrimSpace(c.API.Host) == "" {
		c.API.Host = "0.0.0.0"
	} else {
		c.API.Host = strings.TrimSpace(c.API.Host)
	}
	if c.API.Port < 1 || c.API.Port > 65535 {
		c.API.Port = 8080
	}
	if c.API.Timeout < 1 {
		c.API.Timeout = 60
	}
	if strings.TrimSpace(c.API.RateLimit) == "" {
		c.API.RateLimit = "10,10"
	} else {
		c.API.RateLimit = strings.TrimSpace(c.API.RateLimit)
	}
	if c.API.ReadHeaderTimeout < 1 {
		c.API.ReadHeaderTimeout = 15
	}
	if c.API.ReadTimeout < 1 {
		c.API.ReadTimeout = 15
	}
	if c.API.WriteTimeout < 1 {
		c.API.WriteTimeout = 30
	}
}

func (c *Config) validatePrometheus() {
	// Check Prometheus
	if c.Prometheus.Port < 1 || c.Prometheus.Port > 65535 {
		c.Prometheus.Port = 9090
	}
	if strings.TrimSpace(c.Prometheus.Host) == "" {
		c.Prometheus.Host = "localhost"
	} else {
		c.Prometheus.Host = strings.TrimSpace(c.Prometheus.Host)
	}
}

func (c *Config) validateOS() {
	// Check OS
	if strings.TrimSpace(c.OS) == "" {
		c.OS = runtime.GOOS
	} else {
		c.OS = strings.TrimSpace(c.OS)
	}
}

func (c *Config) validateDebugLevel() {
	// Check DebugLevel
	if c.DebugLevel < 0 {
		c.DebugLevel = 0
	}
}

func (c *Config) String() string {
	return fmt.Sprintf("Config{Remote: %v, API: %v, Prometheus: %v, OS: %v, DebugLevel: %v}",
		c.Remote, c.API, c.Prometheus, c.OS, c.DebugLevel)
}

// IsEmpty checks if the given config is empty.
// It returns true if the config is empty, false otherwise.
func IsEmpty(config Config) bool {
	if config.API != (APIConfig{}) {
		return false
	}

	if config.Prometheus != (PrometheusConfig{}) {
		return false
	}

	if config.OS != "" {
		return false
	}

	if config.DebugLevel != 0 {
		return false
	}

	// If all checks pass, the struct is considered empty
	return true
}

// IsEmpty checks if the given Config is empty.
func (c *Config) IsEmpty() bool {
	return IsEmpty(*c)
}
