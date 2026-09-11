package httpadapter

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/tewecske/goweb/internal/locale"
	"github.com/tewecske/goweb/templates"
)

var (
	// ErrInvalidPage identifies page data that cannot be rendered safely.
	ErrInvalidPage = errors.New("http: invalid page")
	// ErrPageNotFound identifies a template name that is not embedded.
	ErrPageNotFound = errors.New("http: page template not found")
	// ErrNilRequest identifies a missing request for response-mode selection.
	ErrNilRequest = errors.New("http: nil request")
	// ErrInvalidPageState identifies an unsupported localized state page.
	ErrInvalidPageState = errors.New("http: invalid page state")
)

// PageState identifies a localized non-success page.
type PageState string

const (
	PageStateNotFound       PageState = "not-found"
	PageStateAccessDenied   PageState = "access-denied"
	PageStateValidation     PageState = "validation"
	PageStateConflict       PageState = "conflict"
	PageStateSessionExpired PageState = "session-expired"
)

// PageData contains escaped, server-owned data for a full HTML document.
type PageData struct {
	Language          string
	Title             string
	Heading           string
	Kind              string
	Message           string
	Description       string
	CSRFToken         string
	Form              FormData
	FormAction        string
	FormMethod        string
	SubmitLabel       string
	Template          string
	FragmentTemplate  string
	Navigation        []NavigationItem
	Account           *AccountMenu
	SignInURL         string
	SignUpURL         string
	OAuthProviders    []OAuthProviderView
	GuestBanner       bool
	GuestOwned        bool
	GuestTransferCode string
	Alerts            []Alert
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
	Theme       string
	ThemeURL    string
}

// Alert is a user-facing status message. Level accepts info, success, warning,
// or error; unknown levels render as info.
type Alert struct {
	Level   string
	Message string
}

// OAuthProviderView contains only safe provider display data and its local
// authorization-start URL.
type OAuthProviderView struct {
	Name string
	URL  string
}

// FormData contains submitted values and server-side field errors.
type FormData struct {
	Submitted bool
	Values    map[string]string
	Errors    []FieldError
}

// FieldError associates one safe validation message with a form field.
type FieldError struct {
	Field   string
	Message string
}

// Value returns a submitted value after the form has been submitted.
func (f FormData) Value(field string) string {
	if !f.Submitted || f.Values == nil {
		return ""
	}
	return f.Values[field]
}

// Error returns a field error after the form has been submitted.
func (f FormData) Error(field string) string {
	if !f.Submitted {
		return ""
	}
	for _, fieldError := range f.Errors {
		if fieldError.Field == field {
			return fieldError.Message
		}
	}
	return ""
}

// HasErrors reports whether submitted form data contains validation errors.
func (f FormData) HasErrors() bool {
	return f.Submitted && len(f.Errors) > 0
}

// PageRenderer executes embedded HTML templates after buffering the output.
type PageRenderer struct {
	templates *template.Template
	catalogs  *locale.Catalogs
}

// NewPageRenderer parses the embedded application templates.
func NewPageRenderer() (*PageRenderer, error) {
	parsed, err := template.ParseFS(templates.FS, "*.html")
	if err != nil {
		return nil, fmt.Errorf("parse page templates: %w", err)
	}
	catalogs, err := locale.LoadEmbeddedCatalogs()
	if err != nil {
		return nil, fmt.Errorf("load page catalogs: %w", err)
	}
	if err := catalogs.ValidateCompleteness(); err != nil {
		return nil, fmt.Errorf("validate page catalogs: %w", err)
	}
	return &PageRenderer{templates: parsed, catalogs: catalogs}, nil
}

// Translate resolves one validated catalog message for a page handler.
func (r *PageRenderer) Translate(language locale.Code, id string) (string, error) {
	if r == nil || r.catalogs == nil {
		return "", fmt.Errorf("%w: renderer is nil", ErrInvalidPage)
	}
	return r.catalogs.Translate(language, id, nil)
}

// RenderState renders a localized error or recovery state in full-page or
// fragment mode according to request headers.
func (r *PageRenderer) RenderState(writer http.ResponseWriter, request *http.Request, language locale.Code, state PageState) error {
	if r == nil || r.catalogs == nil {
		return fmt.Errorf("%w: renderer is nil", ErrInvalidPageState)
	}
	if !locale.Supported(language) {
		return fmt.Errorf("%w: unsupported language %q", ErrInvalidPageState, language)
	}
	ids, ok := pageStateMessages[state]
	if !ok {
		return fmt.Errorf("%w: %q", ErrInvalidPageState, state)
	}
	title, err := r.catalogs.Translate(language, ids.title, nil)
	if err != nil {
		return fmt.Errorf("translate page title: %w", err)
	}
	heading, err := r.catalogs.Translate(language, ids.heading, nil)
	if err != nil {
		return fmt.Errorf("translate page heading: %w", err)
	}
	message, err := r.catalogs.Translate(language, ids.message, nil)
	if err != nil {
		return fmt.Errorf("translate page message: %w", err)
	}
	return r.RenderRequest(writer, request, PageData{
		Language:         string(language),
		Title:            title,
		Heading:          heading,
		Kind:             "state",
		Message:          message,
		Template:         "state",
		FragmentTemplate: "state-fragment",
	})
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
	return r.RenderRequestStatus(writer, request, page, http.StatusOK)
}

// RenderRequestStatus renders a full page or fragment with an explicit HTTP
// status after buffering template execution.
func (r *PageRenderer) RenderRequestStatus(writer http.ResponseWriter, request *http.Request, page PageData, status int) error {
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
	return r.renderStatus(writer, name, page, status)
}

// IsHTMX reports whether request asks for an HTMX response fragment.
func IsHTMX(request *http.Request) bool {
	if request == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(request.Header.Get("HX-Request")), "true")
}

func (r *PageRenderer) render(writer http.ResponseWriter, name string, page PageData) error {
	return r.renderStatus(writer, name, page, http.StatusOK)
}

func (r *PageRenderer) renderStatus(writer http.ResponseWriter, name string, page PageData, status int) error {
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
	writer.WriteHeader(status)
	_, err := writer.Write(output.Bytes())
	return err
}

type pageStateMessageIDs struct {
	title   string
	heading string
	message string
}

var pageStateMessages = map[PageState]pageStateMessageIDs{
	PageStateNotFound:       {title: "errors.not_found.title", heading: "errors.not_found.heading", message: "errors.not_found.message"},
	PageStateAccessDenied:   {title: "errors.access_denied.title", heading: "errors.access_denied.heading", message: "errors.access_denied.message"},
	PageStateValidation:     {title: "errors.validation.title", heading: "errors.validation.heading", message: "errors.validation.message"},
	PageStateConflict:       {title: "errors.conflict.title", heading: "errors.conflict.heading", message: "errors.conflict.message"},
	PageStateSessionExpired: {title: "errors.session_expired.title", heading: "errors.session_expired.heading", message: "errors.session_expired.message"},
}
