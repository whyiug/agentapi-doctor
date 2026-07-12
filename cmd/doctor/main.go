package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/whyiug/agentapi-doctor/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(cli.Run(ctx, os.Args[1:], cli.Dependencies{Stdout: os.Stdout, Stderr: os.Stderr}))
}
