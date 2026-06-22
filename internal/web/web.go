// Package web serves the embedded browser UI.
package web

import (
	"embed"
	"net/http"
)

//go:embed static
var assets embed.FS

// Handler serves the create page at /, the unwrap page at /s, the share-combine
// page at /combine, and static assets. The unwrap token rides in the URL
// fragment and Shamir shares are pasted client-side, so requests for /s and
// /combine carry no secret material.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", servePage("static/index.html"))
	mux.HandleFunc("GET /s", servePage("static/s.html"))
	mux.HandleFunc("GET /combine", servePage("static/combine.html"))
	mux.HandleFunc("GET /static/", func(w http.ResponseWriter, r *http.Request) {
		http.FileServerFS(assets).ServeHTTP(w, r)
	})
	return mux
}

func servePage(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := assets.ReadFile(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(b)
	}
}
