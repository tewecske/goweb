// Package httpadapter provides the HTTP transport adapter.
package httpadapter

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/tewecske/goweb/internal/adapter/http/middleware"
	"github.com/tewecske/goweb/internal/locale"
)

// NewHandler builds the HTTP handler for public foundation routes.
func NewHandler() http.Handler {
	return NewRouter()
}

// NewRouter builds public routes and applies shared transport boundaries.
func NewRouter(extra ...middleware.Middleware) http.Handler {
	return newRouter(slog.Default(), nil, extra...)
}

// NewLoggedRouter builds routes with structured request logging.
func NewLoggedRouter(logger *Logger, extra ...middleware.Middleware) http.Handler {
	if logger == nil {
		return NewRouter(extra...)
	}
	return newRouter(logger.Application(), logger, extra...)
}

func newRouter(recoveryLogger *slog.Logger, requestLogger middleware.RequestLogger, extra ...middleware.Middleware) http.Handler {
	mux := http.NewServeMux()
	renderer, err := NewPageRenderer()
	if err != nil {
		panic(err)
	}
	mux.HandleFunc("GET /", defaultLocale)
	mux.HandleFunc("GET /{language}", home(renderer))
	mux.HandleFunc("GET /{language}/{path...}", localized(renderer))
	mux.HandleFunc("GET /healthz", health)

	shared := []middleware.Middleware{
		middleware.WithRequestID(nil),
		middleware.WithRequestInfo(),
		middleware.Recover(recoveryLogger),
	}
	if requestLogger != nil {
		shared = append(shared, middleware.Log(requestLogger))
	}
	shared = append(shared, extra...)
	handler, err := middleware.Chain(mux, shared...)
	if err != nil {
		panic(err)
	}
	return handler
}

func defaultLocale(writer http.ResponseWriter, request *http.Request) {
	language := resolveRequestLanguage(request, "")
	path, err := locale.Path(language, "/")
	if err != nil {
		http.Error(writer, "internal server error", http.StatusInternalServerError)
		return
	}
	http.Redirect(writer, request, path, http.StatusFound)
}

const localeCookieName = "goweb_locale"

func resolveRequestLanguage(request *http.Request, accountLanguage locale.Code) locale.Code {
	var browserLanguage locale.Code
	if cookie, err := request.Cookie(localeCookieName); err == nil {
		browserLanguage = locale.Code(cookie.Value)
	}
	var urlLanguage locale.Code
	if language, _, ok := locale.ParsePath(request.URL.Path); ok {
		urlLanguage = language
	}
	language, _ := locale.Resolve(locale.Preferences{
		URL:            urlLanguage,
		Account:        accountLanguage,
		Browser:        browserLanguage,
		AcceptLanguage: request.Header.Get("Accept-Language"),
	})
	return language
}

func home(renderer *PageRenderer) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		language, route, ok := locale.ParsePath(request.URL.Path)
		if !ok || route != "/" {
			renderNotFound(renderer, writer, request)
			return
		}
		if !strings.HasSuffix(request.URL.Path, "/") {
			path, err := locale.Path(language, "/")
			if err != nil {
				http.Error(writer, "internal server error", http.StatusInternalServerError)
				return
			}
			http.Redirect(writer, request, path, http.StatusFound)
			return
		}

		page := PageData{
			Language:         string(language),
			Title:            "GoWeb",
			Heading:          "Welcome to GoWeb",
			Kind:             "home",
			Template:         "home",
			FragmentTemplate: "home-fragment",
		}
		for _, item := range []struct {
			label string
			route string
		}{
			{label: "Home", route: "/"},
			{label: "Sign in", route: "/sign-in"},
			{label: "Create account", route: "/sign-up"},
		} {
			path, err := locale.Path(language, item.route)
			if err != nil {
				http.Error(writer, "internal server error", http.StatusInternalServerError)
				return
			}
			page.Navigation = append(page.Navigation, NavigationItem{Label: item.label, URL: path})
		}
		if err := renderer.RenderRequest(writer, request, page); err != nil {
			http.Error(writer, "internal server error", http.StatusInternalServerError)
		}
	}
}

func localized(renderer *PageRenderer) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		_, route, ok := locale.ParsePath(request.URL.Path)
		if ok && route == "/" {
			home(renderer).ServeHTTP(writer, request)
			return
		}
		renderNotFound(renderer, writer, request)
	}
}

func renderNotFound(renderer *PageRenderer, writer http.ResponseWriter, request *http.Request) {
	language, _, ok := locale.ParsePath(request.URL.Path)
	if !ok {
		http.NotFound(writer, request)
		return
	}
	if err := renderer.RenderState(writer, request, language, PageStateNotFound); err != nil {
		http.Error(writer, "internal server error", http.StatusInternalServerError)
	}
}

func health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}
