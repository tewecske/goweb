package service

import (
	"errors"
	"testing"
)

func TestProviderRegistryStoresConfiguredProviders(t *testing.T) {
	github := providerStub{name: "GitHub"}
	google := providerStub{name: "google"}
	registry, err := NewProviderRegistry(google, github)
	if err != nil {
		t.Fatalf("NewProviderRegistry() error = %v, want nil", err)
	}

	provider, ok := registry.Get(" GITHUB ")
	if !ok || provider != github {
		t.Fatalf("Get(github) = %#v/%t, want github/true", provider, ok)
	}
	if got, want := registry.Names(), []string{"github", "google"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("Names() = %#v, want %#v", got, want)
	}
	providers := registry.List()
	if len(providers) != 2 || providers[0] != github || providers[1] != google {
		t.Fatalf("List() = %#v, want github/google order", providers)
	}
	providers[0] = nil
	if got, ok := registry.Get("github"); !ok || got != github {
		t.Error("List() exposed registry storage")
	}
}

func TestProviderRegistryOmitsUnconfiguredProviders(t *testing.T) {
	registry, err := NewProviderRegistry()
	if err != nil {
		t.Fatalf("NewProviderRegistry() error = %v, want nil", err)
	}
	if provider, ok := registry.Get("github"); ok || provider != nil {
		t.Fatalf("Get(unconfigured) = %#v/%t, want nil/false", provider, ok)
	}
	if len(registry.Names()) != 0 || len(registry.List()) != 0 {
		t.Fatal("empty registry exposed configured providers")
	}
}

func TestNewProviderRegistryRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name      string
		providers []OAuthProvider
		expected  error
	}{
		{name: "nil provider", providers: []OAuthProvider{nil}, expected: ErrInvalidOAuthProvider},
		{name: "empty name", providers: []OAuthProvider{providerStub{}}, expected: ErrInvalidOAuthProvider},
		{name: "invalid name", providers: []OAuthProvider{providerStub{name: "google.com"}}, expected: ErrInvalidOAuthProvider},
		{name: "duplicate normalized name", providers: []OAuthProvider{providerStub{name: "Google"}, providerStub{name: "google"}}, expected: ErrDuplicateOAuthProvider},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewProviderRegistry(test.providers...); !errors.Is(err, test.expected) {
				t.Fatalf("NewProviderRegistry() error = %v, want errors.Is(_, %v)", err, test.expected)
			}
		})
	}
}

func TestProviderRegistryRejectsInvalidLookupName(t *testing.T) {
	registry, err := NewProviderRegistry(providerStub{name: "google"})
	if err != nil {
		t.Fatalf("NewProviderRegistry() error = %v, want nil", err)
	}
	for _, name := range []string{"", "google.com", "google/provider", "google\n"} {
		if provider, ok := registry.Get(name); ok || provider != nil {
			t.Errorf("Get(%q) = %#v/%t, want nil/false", name, provider, ok)
		}
	}
}

type providerStub struct {
	name string
}

func (p providerStub) Name() string {
	return p.name
}
