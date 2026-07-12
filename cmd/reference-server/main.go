package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	mutantserver "github.com/whyiug/agentapi-doctor/reference/mutant-server"
	referenceserver "github.com/whyiug/agentapi-doctor/reference/server"
)

func main() {
	if err := run(); err != nil {
		log.Printf("reference server stopped: %v", err)
		os.Exit(1)
	}
}

func run() error {
	listenAddress := flag.String("listen", "127.0.0.1:8090", "TCP address for the local fixture")
	allowNonLoopback := flag.Bool("allow-non-loopback", false, "explicitly permit a non-loopback synthetic fixture listener")
	mutationID := flag.String("mutant", "", "enable one stable primary mutation ID")
	listMutants := flag.Bool("list-mutants", false, "list stable mutation IDs and exit")
	maxBodyBytes := flag.Int64("max-body-bytes", 1<<20, "maximum JSON request bytes")
	requestTimeout := flag.Duration("request-timeout", 2*time.Second, "per-request fixture deadline")
	flag.Parse()

	if *listMutants {
		for _, entry := range mutantserver.Catalog() {
			fmt.Printf("%s\t%s\n", entry.ID, entry.Description)
		}
		return nil
	}
	if err := validateListenAddress(*listenAddress, *allowNonLoopback); err != nil {
		return err
	}
	var transformer referenceserver.Transformer
	if *mutationID != "" {
		plan, err := mutantserver.New(mutantserver.ID(*mutationID))
		if err != nil {
			return err
		}
		transformer = plan
	}
	handler, err := referenceserver.New(referenceserver.Config{
		MaxBodyBytes:   *maxBodyBytes,
		RequestTimeout: *requestTimeout,
		Transformer:    transformer,
	})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			log.Printf("reference server graceful shutdown: %v", err)
		}
	}()
	mode := "reference"
	if *mutationID != "" {
		mode = "mutant=" + *mutationID
	}
	log.Printf("non-authoritative synthetic %s fixture listening on %s", mode, listener.Addr())
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func validateListenAddress(address string, allowNonLoopback bool) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return errors.New("listen must be a host:port address")
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
