// Package config loads and validates deployment configuration.
package config

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	// HTTPAddressEnv names the environment variable for the HTTP listen address.
	HTTPAddressEnv = "GOWEB_HTTP_ADDR"
	// DefaultHTTPAddress is used when HTTPAddressEnv is not set.
	DefaultHTTPAddress = ":8080"
)

// ErrInvalidHTTPAddress identifies an invalid HTTP listen address.
var ErrInvalidHTTPAddress = errors.New("config: invalid http address")

// Config contains validated process configuration.
type Config struct {
	HTTPAddress string
}

// Load reads configuration through getenv and rejects invalid listen addresses.
// Passing getenv explicitly keeps configuration deterministic in tests.
func Load(getenv func(string) string) (Config, error) {
	if getenv == nil {
		return Config{}, errors.New("config: nil environment lookup")
	}

	address := strings.TrimSpace(getenv(HTTPAddressEnv))
	if address == "" {
		address = DefaultHTTPAddress
	}
	if err := validateHTTPAddress(address); err != nil {
		return Config{}, fmt.Errorf("%w: %v", ErrInvalidHTTPAddress, err)
	}

	return Config{HTTPAddress: address}, nil
}

func validateHTTPAddress(address string) error {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%q: %w", address, err)
	}

	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}

	return nil
}
