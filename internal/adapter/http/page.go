package httpadapter

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/tewecske/goweb/templates"
)

var (
	// ErrInvalidPage identifies page data that cannot be rendered safely.
	ErrInvalidPage = errors.New("http: invalid page")
	// ErrPageNotFound identifies a template name that is not embedded.
	ErrPageNotFound = errors.New("http: page template not found")
	// ErrNilRequest identifies a missing request for response-mode selection.
	ErrNilRequest = errors.New("http: nil request")
)

// PageData contains escaped, server-owned data for a full HTML document.
type PageData struct {
	Language         string
	Title            string
	Heading          string
	Template         string
	FragmentTemplate string
	Navigation       []NavigationItem
	Account          *AccountMenu
	Alerts           []Alert
}

// NavigationItem describes one internal navigation link.
type NavigationItem struct {
	Label string
	URL   string
}

// AccountMenu contains links shown to an authenticated account.
type AccountMenu struct {
	Label       string
	SettingsURL string
	SignOutURL  string
}

// Alert is a user-facing status message. Level accepts info, success, warning,
// or error; unknown levels render as info.
type Alert struct {
	Level   string
	Message string
}

// PageRenderer executes embedded HTML templates after buffering the output.
type PageRenderer struct {
	templates *template.Template
}

// NewPageRenderer parses the embedded application templates.
func NewPageRenderer() (*PageRenderer, error) {
	parsed, err := template.ParseFS(templates.FS, "*.html")
	if err != nil {
		return nil, fmt.Errorf("parse page templates: %w", err)
	}
	return &PageRenderer{templates: parsed}, nil
}

// Render writes one complete HTML document. It buffers template execution so a
// template failure cannot leave a partially rendered response.
func (r *PageRenderer) Render(writer http.ResponseWriter, name string, page PageData) error {
	if r == nil || r.templates == nil {
		return fmt.Errorf("%w: renderer is nil", ErrInvalidPage)
	}
	if page.Language == "" || page.Title == "" || page.Heading == "" {
		return fmt.Errorf("%w: language, title, and heading are required", ErrInvalidPage)
	}
	if r.templates.Lookup(name) == nil {
		return fmt.Errorf("%w: %s", ErrPageNotFound, name)
	}

	var output bytes.Buffer
	if err := r.templates.ExecuteTemplate(&output, name, page); err != nil {
		return fmt.Errorf("execute page template %q: %w", name, err)
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err := writer.Write(output.Bytes())
	return err
}

// RenderRequest serves a complete document for normal requests and an
// accessible fragment for HTMX requests.
func (r *PageRenderer) RenderRequest(writer http.ResponseWriter, request *http.Request, page PageData) error {
	if request == nil {
		return ErrNilRequest
	}
	if page.Language == "" || page.Title == "" || page.Heading == "" {
		return fmt.Errorf("%w: language, title, and heading are required", ErrInvalidPage)
	}
	name := page.Template
	if IsHTMX(request) {
		name = page.FragmentTemplate
	}
	if name == "" {
		return fmt.Errorf("%w: response template is required", ErrInvalidPage)
	}
	writer.Header().Add("Vary", "HX-Request")
	return r.render(writer, name, page)
}

// IsHTMX reports whether request asks for an HTMX response fragment.
func IsHTMX(request *http.Request) bool {
	if request == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(request.Header.Get("HX-Request")), "true")
}

func (r *PageRenderer) render(writer http.ResponseWriter, name string, page PageData) error {
	if r == nil || r.templates == nil {
		return fmt.Errorf("%w: renderer is nil", ErrInvalidPage)
	}
	if r.templates.Lookup(name) == nil {
		return fmt.Errorf("%w: %s", ErrPageNotFound, name)
	}

	var output bytes.Buffer
	if err := r.templates.ExecuteTemplate(&output, name, page); err != nil {
		return fmt.Errorf("execute page template %q: %w", name, err)
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err := writer.Write(output.Bytes())
	return err
}
