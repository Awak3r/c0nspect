package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"conspect/internal/store"
	"conspect/internal/web"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	if err := run(); err != nil {
		slog.Error("startup failed", "error", err)
		os.Exit(1)
	}
}
func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
func limit(name string, fallback int64) (int64, error) {
	s := os.Getenv(name)
	if s == "" {
		return fallback, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || n > 1<<40 {
		return 0, fmt.Errorf("%s must be a positive number of bytes (at most 1 TiB)", name)
	}
	return n, nil
}
func run() error {
	secret, err := hex.DecodeString(os.Getenv("APP_SECRET"))
	if err != nil || len(secret) != 32 {
		return errors.New("APP_SECRET is required: use a stable 64-character hexadecimal secret")
	}
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	cfg := web.Config{BaseURL: env("APP_BASE_URL", "http://localhost:8080"), Secret: secret, DataDir: env("DATA_DIR", "data")}
	if cfg.MaxMarkdownBytes, err = limit("MAX_MARKDOWN_BYTES", 2<<20); err != nil {
		return err
	}
	if cfg.MaxImageBytes, err = limit("MAX_IMAGE_BYTES", 10<<20); err != nil {
		return err
	}
	if cfg.MaxStorageBytes, err = limit("MAX_STORAGE_BYTES", 1<<30); err != nil {
		return err
	}
	if s := os.Getenv("TRUST_PROXY"); s != "" {
		cfg.TrustProxy, err = strconv.ParseBool(s)
		if err != nil {
			return errors.New("TRUST_PROXY must be true or false")
		}
	}
	if s := os.Getenv("MCP_ENABLED"); s != "" {
		cfg.MCPEnabled, err = strconv.ParseBool(s)
		if err != nil {
			return errors.New("MCP_ENABLED must be true or false")
		}
	}
	cfg.MCPAPIURL = env("MCP_API_URL", "http://127.0.0.1:8080")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	db, err := store.Open(ctx, databaseURL)
	cancel()
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()
	if cfg.MCPEnabled {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err := db.InitOAuth(ctx)
		cancel()
		if err != nil {
			return fmt.Errorf("initialize OAuth: %w", err)
		}
	}
	ctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err = db.Owner(ctx)
	if errors.Is(err, store.ErrNotFound) {
		username, password := strings.TrimSpace(env("OWNER_USERNAME", "admin")), os.Getenv("OWNER_PASSWORD")
		if username == "" || len(username) > 100 {
			return errors.New("OWNER_USERNAME must contain 1 to 100 bytes")
		}
		if len(password) < 12 || len(password) > 72 {
			return errors.New("first startup requires OWNER_PASSWORD containing 12 to 72 bytes")
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		if err := db.EnsureOwner(ctx, username, string(hash)); err != nil {
			return fmt.Errorf("create owner: %w", err)
		}
	} else if err != nil {
		return err
	}
	app, err := web.New(db, cfg)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: env("APP_ADDR", ":8080"), Handler: app.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	stopped, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	failures := make(chan error, 1)
	go func() { slog.Info("conspect listening", "address", server.Addr); failures <- server.ListenAndServe() }()
	select {
	case err := <-failures:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-stopped.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}
