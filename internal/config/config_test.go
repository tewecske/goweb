package config

import (
	"errors"
	"testing"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		expected    string
		wantErr     bool
	}{
		{name: "default address", expected: DefaultHTTPAddress},
		{name: "configured address", environment: "127.0.0.1:9090", expected: "127.0.0.1:9090"},
		{name: "invalid address", environment: "localhost", wantErr: true},
		{name: "invalid port", environment: ":not-a-port", wantErr: true},
		{name: "out of range port", environment: ":65536", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, err := Load(func(string) string { return test.environment })
			if test.wantErr {
				if err == nil {
					t.Fatal("Load() error = nil, want error")
				}
				if !errors.Is(err, ErrInvalidHTTPAddress) {
					t.Fatalf("Load() error = %v, want ErrInvalidHTTPAddress", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Load() error = %v, want nil", err)
			}
			if config.HTTPAddress != test.expected {
				t.Errorf("HTTPAddress = %q, want %q", config.HTTPAddress, test.expected)
			}
		})
	}
}

func TestLoadNilEnvironmentLookup(t *testing.T) {
	_, err := Load(nil)
	if err == nil {
		t.Fatal("Load(nil) error = nil, want error")
	}
}
