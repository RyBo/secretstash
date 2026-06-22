// Package web serves the embedded browser UI.
package web

import (
	"embed"
	"net/http"
)

//go:embed static
var assets embed.FS

// Handler serves the create page at /, the reveal page at /s and /unwrap, the
// share-combine page at /combine, and static assets. Reveal tokens ride in the
// URL fragment or are pasted client-side, and Shamir shares are pasted
// client-side, so none of these requests carry secret material.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", servePage("static/index.html"))
	mux.HandleFunc("GET /s", servePage("static/unwrap.html"))
	mux.HandleFunc("GET /unwrap", servePage("static/unwrap.html"))
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
