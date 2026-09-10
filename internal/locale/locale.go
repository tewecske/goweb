// Package locale defines supported language codes and canonical URL paths.
package locale

import (
	"errors"
	"net/url"
	"strings"
)

var (
	// ErrUnsupported identifies a language code outside the application catalog.
	ErrUnsupported = errors.New("locale: unsupported language")
	// ErrInvalidPath identifies a route that cannot be localized safely.
	ErrInvalidPath = errors.New("locale: invalid path")
)

// Code identifies one supported language.
type Code string

const (
	// English is the default language.
	English Code = "en"
	// Hungarian is the second supported language.
	Hungarian Code = "hu"
)

// Default is used for URLs without an explicit language prefix.
const Default = English

// Supported reports whether code has a catalog and can appear in a URL.
func Supported(code Code) bool {
	return code == English || code == Hungarian
}

// Codes returns supported language codes in stable display order.
func Codes() []Code {
	return []Code{English, Hungarian}
}

// ParsePath extracts a language prefix and route from a URL path.
func ParsePath(path string) (Code, string, bool) {
	if path == "" || !strings.HasPrefix(path, "/") {
		return "", "", false
	}
	trimmed := strings.TrimPrefix(path, "/")
	if trimmed == "" {
		return "", "", false
	}
	parts := strings.SplitN(trimmed, "/", 2)
	code := Code(parts[0])
	if !Supported(code) {
		return "", "", false
	}
	if len(parts) == 1 {
		return code, "/", true
	}
	if parts[1] == "" {
		return code, "/", true
	}
	if strings.HasPrefix(parts[1], "/") {
		return "", "", false
	}
	return code, "/" + parts[1], true
}

// Path returns the canonical internal URL for route under code.
func Path(code Code, route string) (string, error) {
	if !Supported(code) {
		return "", ErrUnsupported
	}
	parsed, err := url.Parse(route)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || !strings.HasPrefix(parsed.Path, "/") {
		return "", ErrInvalidPath
	}
	if strings.HasPrefix(parsed.Path, "//") {
		return "", ErrInvalidPath
	}
	path := strings.TrimPrefix(parsed.Path, "/")
	if path == "" {
		path = "/"
	} else {
		path = "/" + path
	}
	parsed.Path = "/" + string(code) + path
	return parsed.String(), nil
}
