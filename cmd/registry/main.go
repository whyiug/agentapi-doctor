package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/whyiug/agentapi-doctor/internal/buildinfo"
	domain "github.com/whyiug/agentapi-doctor/internal/registry"
	"github.com/whyiug/agentapi-doctor/internal/registry/httpapi"
	"github.com/whyiug/agentapi-doctor/internal/registry/store"
)

type serverOptions struct {
	listenAddress    string
	allowNonLoopback bool
	allowEphemeral   bool
	database         string
	tokenEnv         string
	principalID      string
	tokenTTL         time.Duration
	rateLimit        int
}

type bearerTokenConfigurer interface {
	SetBearerToken(string, domain.Principal, time.Time) error
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		log.Printf("registry stopped: %v", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) > 0 {
		switch arguments[0] {
		case "version":
			return writeVersion(arguments[1:], os.Stdout)
		case "serve":
			arguments = arguments[1:]
		case "backup":
			return runBackup(arguments[1:])
		}
	}
	options, err := parseServerOptions(arguments, os.Stderr)
	if err != nil {
		return err
	}
	return serve(options)
}

func writeVersion(arguments []string, output io.Writer) error {
	if len(arguments) != 0 {
		return errors.New("usage: registry version")
	}
	return json.NewEncoder(output).Encode(buildinfo.Current())
}

func parseServerOptions(arguments []string, output io.Writer) (serverOptions, error) {
	var options serverOptions
	flags := flag.NewFlagSet("registry serve", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.StringVar(&options.listenAddress, "listen", "127.0.0.1:8080", "TCP address for the Registry HTTP service")
	flags.BoolVar(&options.allowNonLoopback, "allow-non-loopback", false, "explicitly permit a non-loopback plaintext development listener")
	flags.BoolVar(&options.allowEphemeral, "allow-ephemeral", false, "explicitly acknowledge that all Registry data is memory-only")
	flags.StringVar(&options.database, "database", "", "SQLite database path (relative paths are resolved before opening)")
	flags.StringVar(&options.tokenEnv, "token-env", "AGENTAPI_REGISTRY_TOKEN", "environment variable holding the local Bearer token; never pass the token as a CLI argument")
	flags.StringVar(&options.principalID, "principal", "local-operator", "principal ID assigned to the local Bearer token")
	flags.DurationVar(&options.tokenTTL, "token-ttl", 8*time.Hour, "lifetime assigned to the configured local Bearer token")
	flags.IntVar(&options.rateLimit, "rate-limit", 120, "requests per source address per minute")
	if err := flags.Parse(arguments); err != nil {
		return serverOptions{}, err
	}
	if flags.NArg() != 0 {
		return serverOptions{}, fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}
	if err := validateListenAddress(options.listenAddress, options.allowNonLoopback); err != nil {
		return serverOptions{}, err
	}
	if options.rateLimit < 1 {
		return serverOptions{}, errors.New("rate-limit must be positive")
	}
	if options.tokenTTL <= 0 {
		return serverOptions{}, errors.New("token-ttl must be positive")
	}
	if options.tokenEnv == "" || options.tokenEnv != strings.TrimSpace(options.tokenEnv) || strings.ContainsRune(options.tokenEnv, '=') {
		return serverOptions{}, errors.New("token-env must be a nonempty environment variable name")
	}
	resolved, err := validateStorageMode(options.database, options.allowEphemeral)
	if err != nil {
		return serverOptions{}, err
	}
	options.database = resolved
	return options, nil
}

func validateStorageMode(database string, allowEphemeral bool) (string, error) {
	if allowEphemeral && database != "" {
		return "", errors.New("-database and -allow-ephemeral are mutually exclusive")
	}
	if database == "" {
		if allowEphemeral {
			return "", nil
		}
		return "", errors.New("configure durable storage with -database or explicitly acknowledge memory-only mode with -allow-ephemeral")
	}
	if database != strings.TrimSpace(database) || strings.IndexByte(database, 0) >= 0 {
		return "", errors.New("database path must not have surrounding whitespace or NUL bytes")
	}
	absolute, err := filepath.Abs(database)
	if err != nil {
		return "", fmt.Errorf("resolve database path: %w", err)
	}
	return filepath.Clean(absolute), nil
}

func serve(options serverOptions) error {
	registryStore, tokenConfigurer, closeStore, storageDescription, err := openStore(options)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := closeStore(); closeErr != nil {
			log.Printf("close Registry storage: %v", closeErr)
		}
	}()

	if token := os.Getenv(options.tokenEnv); token != "" {
		principal, err := domain.NewPrincipal(domain.PrincipalID(options.principalID),
			domain.ScopeObservationPrepare,
			domain.ScopeObservationCommit,
			domain.ScopeOwnershipManage,
			domain.ScopeDisputeCreate,
		)
		if err != nil {
			return fmt.Errorf("configure local principal: %w", err)
		}
		if err := tokenConfigurer.SetBearerToken(token, principal, time.Now().Add(options.tokenTTL)); err != nil {
			return fmt.Errorf("configure local Bearer token: %w", err)
		}
	} else {
		log.Printf("warning: %s is unset; write endpoints will reject every request", options.tokenEnv)
	}

	handler, err := httpapi.New(httpapi.Config{
		Store:      registryStore,
		RateLimit:  options.rateLimit,
		RateWindow: time.Minute,
	})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", options.listenAddress)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	shutdownContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-shutdownContext.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("registry graceful shutdown: %v", err)
		}
	}()
	log.Printf("Registry listening on %s with %s storage", listener.Addr(), storageDescription)
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func openStore(options serverOptions) (store.Store, bearerTokenConfigurer, func() error, string, error) {
	if options.database == "" {
		memory := store.NewMemory()
		return memory, memory, func() error { return nil }, "explicitly enabled ephemeral memory", nil
	}
	sqliteStore, err := store.OpenSQLite(options.database)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("open SQLite Registry database: %w", err)
	}
	return sqliteStore, sqliteStore, sqliteStore.Close, "durable SQLite", nil
}

func runBackup(arguments []string) error {
	flags := flag.NewFlagSet("registry backup", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var database string
	var destination string
	flags.StringVar(&database, "database", "", "existing SQLite Registry database path")
	flags.StringVar(&destination, "output", "", "new standalone SQLite backup path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}
	if database == "" || destination == "" {
		return errors.New("backup requires both -database and -output")
	}
	source, err := filepath.Abs(database)
	if err != nil {
		return fmt.Errorf("resolve database path: %w", err)
	}
	target, err := filepath.Abs(destination)
	if err != nil {
		return fmt.Errorf("resolve backup path: %w", err)
	}
	if filepath.Clean(source) == filepath.Clean(target) {
		return errors.New("backup output must differ from the source database")
	}
	info, err := os.Lstat(source)
	if err != nil {
		return fmt.Errorf("inspect source database: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("source database must be an existing regular non-symlink file")
	}
	sqliteStore, err := store.OpenSQLite(filepath.Clean(source))
	if err != nil {
		return fmt.Errorf("open source database: %w", err)
	}
	defer sqliteStore.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := sqliteStore.Backup(ctx, filepath.Clean(target)); err != nil {
		return fmt.Errorf("create backup: %w", err)
	}
	log.Printf("created consistent SQLite backup at %s", filepath.Clean(target))
	return nil
}

func validateListenAddress(address string, allowNonLoopback bool) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return fmt.Errorf("listen must be a host:port address")
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip != nil && ip.IsLoopback() {
		return nil
	}
	if !allowNonLoopback {
		return errors.New("non-loopback listen address requires -allow-non-loopback")
	}
	return nil
}
