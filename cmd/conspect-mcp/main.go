// conspect-mcp is a stdio MCP adapter; it does not start an HTTP listener.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"conspect/internal/conspectclient"
	"conspect/internal/mcpserver"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "conspect-mcp:", err)
		os.Exit(1)
	}
}

func run() error {
	version := flag.Bool("version", false, "show the MCP server version")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Conspect MCP: stdio server, without an HTTP listener")
		fmt.Fprintln(os.Stderr, "Configuration: CONSPECT_URL, exactly one of CONSPECT_API_KEY / CONSPECT_API_KEY_FILE,")
		fmt.Fprintln(os.Stderr, "optional CONSPECT_FILES_ROOT. See docs/MCP.md. Do not pass credentials as arguments.")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("unexpected command arguments; see -help")
	}
	if *version {
		fmt.Fprintln(os.Stdout, "conspect-mcp", mcpserver.Version)
		return nil
	}
	cfg, err := conspectclient.ConfigFromEnv()
	if err != nil {
		return err
	}
	client, err := conspectclient.New(cfg)
	if err != nil {
		return err
	}
	defer client.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := mcpserver.New(client).Run(ctx, &mcp.StdioTransport{}); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		// Protocol errors can contain caller-supplied text. Keep it off logs.
		return errors.New("MCP session stopped; check client configuration and protocol")
	}
	return nil
}
