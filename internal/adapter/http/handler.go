// Package httpadapter provides the HTTP transport adapter.
package httpadapter

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/tewecske/goweb/internal/adapter/http/middleware"
	"github.com/tewecske/goweb/internal/locale"
	staticassets "github.com/tewecske/goweb/static"
)

// NewHandler builds the HTTP handler for public foundation routes.
func NewHandler() http.Handler {
	return NewRouter()
}

// NewRouter builds public routes and applies shared transport boundaries.
func NewRouter(extra ...middleware.Middleware) http.Handler {
	return newRouter(slog.Default(), nil, extra...)
}

// NewRouterWithServices builds public routes while retaining application
// dependencies for future feature handlers.
func NewRouterWithServices(services any, extra ...middleware.Middleware) http.Handler {
	return newRouterWithServices(slog.Default(), nil, services, extra...)
}

// NewLoggedRouter builds routes with structured request logging.
func NewLoggedRouter(logger *Logger, extra ...middleware.Middleware) http.Handler {
	return NewLoggedRouterWithServices(logger, nil, extra...)
}

// NewLoggedRouterWithServices retains the application graph at HTTP
// composition time. Feature handlers will consume its ports as routes land;
// this foundation still exposes only public routes.
func NewLoggedRouterWithServices(logger *Logger, services any, extra ...middleware.Middleware) http.Handler {
	if logger == nil {
		return NewRouterWithServices(services, extra...)
	}
	return newRouterWithServices(logger.Application(), logger, services, extra...)
}

func newRouter(recoveryLogger *slog.Logger, requestLogger middleware.RequestLogger, extra ...middleware.Middleware) http.Handler {
	return newRouterWithServices(recoveryLogger, requestLogger, nil, extra...)
}

func newRouterWithServices(recoveryLogger *slog.Logger, requestLogger middleware.RequestLogger, services any, extra ...middleware.Middleware) http.Handler {
	mux := http.NewServeMux()
	dependencies, _ := services.(Dependencies)
	renderer, err := NewPageRenderer()
	if err != nil {
		panic(err)
	}
	mux.HandleFunc("GET /", defaultLocale)
	mux.HandleFunc("GET /{language}", home(renderer))
	mux.HandleFunc("GET /{language}/{path...}", localized(renderer))
	auth := newAuthHandler(renderer, dependencies)
	for _, language := range locale.Codes() {
		prefix := "/" + string(language)
		mux.HandleFunc("GET "+prefix+"/sign-up", auth.signUp)
		mux.HandleFunc("POST "+prefix+"/sign-up", auth.signUp)
		mux.HandleFunc("GET "+prefix+"/sign-in", auth.signIn)
		mux.HandleFunc("POST "+prefix+"/sign-in", auth.signIn)
		mux.HandleFunc("GET "+prefix+"/home", auth.home)
		mux.HandleFunc("POST "+prefix+"/sign-out", auth.signOut)
	}
	mux.Handle("GET /static/{path...}", http.StripPrefix("/static/", http.FileServer(http.FS(staticassets.Files()))))
	mux.HandleFunc("GET /healthz", health)

	shared := []middleware.Middleware{
		middleware.WithRequestID(nil),
		middleware.WithRequestInfo(),
		middleware.Recover(recoveryLogger),
		middleware.CSRF(),
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
			SignInURL:        mustLocalePath(language, "/sign-in"),
			SignUpURL:        mustLocalePath(language, "/sign-up"),
		}
		page.CSRFToken, _ = middleware.CSRFTokenFromContext(request.Context())
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

func mustLocalePath(language locale.Code, route string) string {
	path, _ := locale.Path(language, route)
	return path
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
