// Package static contains browser assets embedded into the application.
package static

import (
	"embed"
	"io/fs"
)

// FS contains the generated browser assets served by the HTTP adapter.
//
//go:embed app.css
var FS embed.FS

// Files returns the embedded asset filesystem without its package directory.
func Files() fs.FS {
	return FS
}
