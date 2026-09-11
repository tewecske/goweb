package static

import (
	"io/fs"
	"testing"
)

func TestFilesContainsGeneratedStylesheet(t *testing.T) {
	info, err := fs.Stat(Files(), "app.css")
	if err != nil {
		t.Fatalf("stat app.css: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("app.css is empty")
	}
}
