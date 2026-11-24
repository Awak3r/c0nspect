package web

import (
	"crypto/sha256"
	_ "embed"
	"fmt"
	"strings"
)

//go:embed static/app.css
var appCSSSource string

// Golos Text from google/fonts at c1eda9233c33ad7775b27efd794f931095cf6133,
// converted from the upstream variable TTF to WOFF2 without subsetting.
//
//go:embed static/golos-text.woff2
var appFont []byte

//go:embed static/LICENSE-Golos-Text.txt
var appFontLicense []byte

var appFontURL = func() string {
	digest := sha256.Sum256(appFont)
	return fmt.Sprintf("/assets/fonts/golos-text-%x.woff2", digest[:8])
}()

var appCSS = strings.Replace(appCSSSource, "url(golos-text.woff2)", "url("+appFontURL+")", 1)

// Content-addressing prevents a cached stylesheet from hiding a deployed redesign.
var appStylesheetURL = func() string {
	digest := sha256.Sum256([]byte(appCSS))
	return fmt.Sprintf("/assets/app.css?v=%x", digest[:8])
}()

func stylesheetURL() string { return appStylesheetURL }
