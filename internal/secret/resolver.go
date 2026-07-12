// Package secret resolves explicit secret references without placing secret
// values in command-line arguments, reports, or configuration documents.
package secret

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/whyiug/agentapi-doctor/internal/config"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

const MaxSecretBytes = 64 << 10

var (
	ErrNotFound     = errors.New("secret not found")
	ErrExecDisabled = errors.New("exec secret resolver is disabled")
	ErrKeyring      = errors.New("keyring resolver is not available in this build")
)

type Resolver struct {
	LookupEnv       func(string) (string, bool)
	ExecEnabled     bool
	ExecDigests     map[string]schema.Digest
	ExecTimeout     time.Duration
	ExecEnvironment []string
	ExecDirectory   string
	ExecArguments   map[string][]string
}

func (resolver Resolver) Resolve(ctx context.Context, reference string) ([]byte, error) {
	parsed, err := config.ParseSecretReference(reference)
	if err != nil {
		return nil, err
	}
	switch parsed.Scheme {
	case config.SecretEnv:
		lookup := resolver.LookupEnv
		if lookup == nil {
			lookup = os.LookupEnv
		}
		value, ok := lookup(parsed.Value)
		if !ok {
			return nil, ErrNotFound
		}
		return validateSecret([]byte(value))
	case config.SecretFile:
		return resolveFile(parsed.Value)
	case config.SecretKeyring:
		return nil, ErrKeyring
	case config.SecretExec:
		return resolver.resolveExec(ctx, parsed.Value)
	default:
		return nil, errors.New("unsupported secret reference")
	}
}

func resolveFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("file secret path must be absolute")
	}
	clean := filepath.Clean(path)
	info, err := os.Lstat(clean)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("stat secret file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("secret file must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("secret file permissions %04o expose group or other bits", info.Mode().Perm())
	}
	if info.Size() <= 0 || info.Size() > MaxSecretBytes {
		return nil, fmt.Errorf("secret file size must be between 1 and %d bytes", MaxSecretBytes)
	}
	value, err := os.ReadFile(clean)
	if err != nil {
		return nil, fmt.Errorf("read secret file: %w", err)
	}
	return validateSecret(value)
}

func (resolver Resolver) resolveExec(ctx context.Context, path string) ([]byte, error) {
	if !resolver.ExecEnabled {
		return nil, ErrExecDisabled
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("exec secret helper path must be absolute")
	}
	clean := filepath.Clean(path)
	if resolver.ExecDirectory == "" || !filepath.IsAbs(resolver.ExecDirectory) {
		return nil, errors.New("exec secret resolver requires an absolute working directory")
	}
	directoryInfo, err := os.Lstat(filepath.Clean(resolver.ExecDirectory))
	if err != nil || directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() {
		return nil, errors.New("exec secret resolver working directory must be a non-symlink directory")
	}
	expected, ok := resolver.ExecDigests[clean]
	if !ok {
		return nil, errors.New("exec secret helper has no approved digest")
	}
	actual, err := fileDigest(clean)
	if err != nil {
		return nil, err
	}
	if actual != expected {
		return nil, errors.New("exec secret helper digest mismatch")
	}
	timeout := resolver.ExecTimeout
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = 5 * time.Second
	}
	commandContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	arguments := append([]string(nil), resolver.ExecArguments[clean]...)
	for _, argument := range arguments {
		if strings.ContainsRune(argument, '\x00') {
			return nil, errors.New("exec secret helper argument contains NUL")
		}
	}
	command := exec.CommandContext(commandContext, clean, arguments...)
	command.Env = append([]string(nil), resolver.ExecEnvironment...)
	command.Dir = resolver.ExecDirectory
	stdout := &boundedBuffer{limit: MaxSecretBytes}
	command.Stdout = stdout
	command.Stderr = io.Discard
	command.Stdin = nil
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("exec secret helper failed: %w", err)
	}
	if stdout.overflow {
		Wipe(stdout.data)
		return nil, errors.New("exec secret helper output exceeded limit")
	}
	return validateSecret(stdout.data)
}

func fileDigest(path string) (schema.Digest, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("stat exec secret helper: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("exec secret helper must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o100 == 0 {
		return "", errors.New("exec secret helper must be owner-executable and not group/other writable")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open exec secret helper: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash exec secret helper: %w", err)
	}
	return schema.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}

func validateSecret(value []byte) ([]byte, error) {
	if len(value) == 0 {
		return nil, errors.New("secret is empty")
	}
	if len(value) > MaxSecretBytes {
		return nil, errors.New("secret exceeds size limit")
	}
	if indexByte(value, 0) >= 0 {
		return nil, errors.New("secret contains a NUL byte")
	}
	return append([]byte(nil), value...), nil
}

func indexByte(value []byte, target byte) int {
	for index, current := range value {
		if current == target {
			return index
		}
	}
	return -1
}

// Wipe overwrites a mutable secret buffer.  Go does not guarantee removal of
// all compiler/runtime copies, so this is defense in depth rather than an
// absolute memory-erasure claim.
func Wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

type boundedBuffer struct {
	data     []byte
	limit    int
	overflow bool
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := buffer.limit - len(buffer.data)
	if remaining <= 0 {
		buffer.overflow = true
		return original, nil
	}
	if len(value) > remaining {
		buffer.data = append(buffer.data, value[:remaining]...)
		buffer.overflow = true
		return original, nil
	}
	buffer.data = append(buffer.data, value...)
	return original, nil
}
