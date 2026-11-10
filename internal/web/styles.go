package web

import (
	"crypto/sha256"
	_ "embed"
	"fmt"
)

//go:embed static/app.css
var appCSS string

// Content-addressing prevents a cached stylesheet from hiding a deployed redesign.
var appStylesheetURL = func() string {
	digest := sha256.Sum256([]byte(appCSS))
	return fmt.Sprintf("/assets/app.css?v=%x", digest[:8])
}()

func stylesheetURL() string { return appStylesheetURL }
