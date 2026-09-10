package service

import (
	"errors"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"
)

const maxOAuthProviderNameLength = 32

var (
	// ErrInvalidProviderRegistry identifies unusable registry configuration.
	ErrInvalidProviderRegistry = errors.New("service: invalid provider registry")
	// ErrInvalidOAuthProvider identifies a provider with an unusable name.
	ErrInvalidOAuthProvider = errors.New("service: invalid oauth provider")
	// ErrDuplicateOAuthProvider identifies repeated provider configuration.
	ErrDuplicateOAuthProvider = errors.New("service: duplicate oauth provider")
)

// OAuthProvider is the registry-facing provider identity. Provider-specific
// exchange behavior belongs to the consuming authentication service.
type OAuthProvider interface {
	Name() string
}

// ProviderRegistry contains only providers configured for this deployment.
// Its contents are immutable after construction and safe for concurrent reads.
type ProviderRegistry struct {
	providers map[string]OAuthProvider
}

// NewProviderRegistry constructs a registry from independently configured
// providers. An empty provider list is valid and means external sign-in is
// unavailable.
func NewProviderRegistry(providers ...OAuthProvider) (*ProviderRegistry, error) {
	registry := &ProviderRegistry{providers: make(map[string]OAuthProvider, len(providers))}
	for _, provider := range providers {
		if isNilOAuthProvider(provider) {
			return nil, ErrInvalidOAuthProvider
		}
		name, err := normalizeOAuthProviderName(provider.Name())
		if err != nil {
			return nil, err
		}
		if _, exists := registry.providers[name]; exists {
			return nil, ErrDuplicateOAuthProvider
		}
		registry.providers[name] = provider
	}
	return registry, nil
}

// Get returns a configured provider by its canonical name.
func (r *ProviderRegistry) Get(name string) (OAuthProvider, bool) {
	if r == nil || r.providers == nil {
		return nil, false
	}
	canonical, err := normalizeOAuthProviderName(name)
	if err != nil {
		return nil, false
	}
	provider, ok := r.providers[canonical]
	return provider, ok
}

// Names returns configured provider names in deterministic display order.
func (r *ProviderRegistry) Names() []string {
	if r == nil || r.providers == nil {
		return nil
	}
	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// List returns configured providers in canonical name order.
func (r *ProviderRegistry) List() []OAuthProvider {
	if r == nil || r.providers == nil {
		return nil
	}
	names := r.Names()
	providers := make([]OAuthProvider, 0, len(names))
	for _, name := range names {
		providers = append(providers, r.providers[name])
	}
	return providers
}

func normalizeOAuthProviderName(raw string) (string, error) {
	if strings.ContainsAny(raw, "\x00\r\n") {
		return "", ErrInvalidOAuthProvider
	}
	name := strings.ToLower(strings.TrimSpace(raw))
	if name == "" || utf8.RuneCountInString(name) > maxOAuthProviderNameLength {
		return "", ErrInvalidOAuthProvider
	}
	for _, character := range name {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' && character != '_' {
			return "", ErrInvalidOAuthProvider
		}
	}
	return name, nil
}

func isNilOAuthProvider(provider OAuthProvider) bool {
	if provider == nil {
		return true
	}
	value := reflect.ValueOf(provider)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
