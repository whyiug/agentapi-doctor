package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

func makeTLSConfig(input TLSConfig) (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: input.ServerName}
	if input.RootCAsFile == "" {
		return config, nil
	}
	info, err := os.Lstat(input.RootCAsFile)
	if err != nil {
		return nil, fmt.Errorf("stat CA file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 4<<20 {
		return nil, errors.New("CA file must be a bounded regular non-symlink file")
	}
	data, err := os.ReadFile(input.RootCAsFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("CA file contains no parseable certificates")
	}
	config.RootCAs = pool
	return config, nil
}
