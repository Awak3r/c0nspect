package render

import (
	"embed"
	"io/fs"
)

//go:embed static
var embeddedAssets embed.FS

// Assets exposes the vendored reader files at the filesystem root. Serve it at
// /assets/reader/ with http.StripPrefix and http.FileServer(http.FS(Assets())).
func Assets() fs.FS {
	assets, err := fs.Sub(embeddedAssets, "static")
	if err != nil {
		panic(err) // The embedded directory is guaranteed to exist at build time.
	}
	return assets
}
