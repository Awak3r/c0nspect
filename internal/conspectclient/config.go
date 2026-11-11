package conspectclient

import (
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
)

const (
	defaultBaseURL = "https://conspect.awak3r.ru"
	maxKeyBytes    = 4096
)

// ConfigFromEnv reads trusted startup settings. It validates credentials without
// replacing APIKeyFile with its contents; New revalidates and reads that file.
func ConfigFromEnv() (Config, error) {
	return ConfigFromLookup(os.Getenv)
}

// ConfigFromLookup is ConfigFromEnv with an injected environment source, so a
// caller can merge a private local config file underneath real variables.
func ConfigFromLookup(getenv func(string) string) (Config, error) {
	cfg := Config{
		BaseURL:    getenv("CONSPECT_URL"),
		APIKey:     getenv("CONSPECT_API_KEY"),
		APIKeyFile: getenv("CONSPECT_API_KEY_FILE"),
		FilesRoot:  getenv("CONSPECT_FILES_ROOT"),
	}
	cfg, _, err := prepareConfig(cfg)
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func prepareConfig(cfg Config) (Config, string, error) {
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultBaseURL
	}
	origin, err := normalizeOrigin(cfg.BaseURL)
	if err != nil {
		return Config{}, "", err
	}
	cfg.BaseURL = origin
	if cfg.APIBaseURL == "" {
		cfg.APIBaseURL = origin
	} else if cfg.APIBaseURL, err = normalizeOrigin(cfg.APIBaseURL); err != nil {
		return Config{}, "", err
	}
	if (cfg.APIKey == "") == (cfg.APIKeyFile == "") {
		return Config{}, "", errors.New("configure exactly one of CONSPECT_API_KEY or CONSPECT_API_KEY_FILE")
	}
	key := cfg.APIKey
	if cfg.APIKeyFile != "" {
		key, err = readAPIKeyFile(cfg.APIKeyFile)
		if err != nil {
			return Config{}, "", err
		}
	}
	if !validAPIKey(key) {
		return Config{}, "", errors.New("Conspect API key must be a nonempty csp_ secret without whitespace or control characters")
	}
	return cfg, key, nil
}

func normalizeOrigin(raw string) (string, error) {
	invalid := errors.New("CONSPECT_URL must be an HTTPS origin (HTTP is allowed only for localhost or a loopback IP), optionally ending in /api/v1")
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.Host == "" || u.Hostname() == "" ||
		strings.ContainsAny(raw, "?#\\") || u.RawPath != "" || u.ForceQuery {
		return "", invalid
	}
	if u.Path != "" && u.Path != "/" && u.Path != "/api/v1" && u.Path != "/api/v1/" {
		return "", invalid
	}
	if strings.HasSuffix(u.Host, ":") {
		return "", invalid
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", invalid
		}
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || (!strings.EqualFold(u.Hostname(), "localhost") && (ip == nil || !ip.IsLoopback())) {
			return "", invalid
		}
	}
	u.Path = ""
	return u.String(), nil
}

func validAPIKey(key string) bool {
	if len(key) <= len("csp_") || len(key) > maxKeyBytes || !strings.HasPrefix(key, "csp_") {
		return false
	}
	for _, c := range key {
		if c < '!' || c > '~' {
			return false
		}
	}
	return true
}

func readAPIKeyFile(name string) (string, error) {
	invalid := errors.New("API key file must be a readable regular file of at most 4 KiB, not a symlink, with Unix permissions 0600 (restrict its ACL on Windows)")
	before, err := os.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Size() > maxKeyBytes || !privateKeyPermissions(before) {
		return "", invalid
	}
	f, err := os.OpenFile(name, readOnlyFlags(), 0)
	if err != nil {
		return "", invalid
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(before, info) || info.Size() > maxKeyBytes || !privateKeyPermissions(info) {
		return "", invalid
	}
	data, err := io.ReadAll(io.LimitReader(f, maxKeyBytes+1))
	if err != nil || len(data) > maxKeyBytes {
		return "", invalid
	}
	return strings.TrimSpace(string(data)), nil
}

func privateKeyPermissions(info os.FileInfo) bool {
	return runtime.GOOS == "windows" || info.Mode().Perm() == 0600
}
