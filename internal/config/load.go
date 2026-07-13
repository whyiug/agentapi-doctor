package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const MaxConfigBytes = 1 << 20

func Decode(raw []byte) (Config, error) {
	if len(raw) == 0 || len(raw) > MaxConfigBytes {
		return Config{}, fmt.Errorf("config size must be between 1 and %d bytes", MaxConfigBytes)
	}
	var header struct {
		APIVersion string `yaml:"apiVersion"`
	}
	if err := yaml.Unmarshal(raw, &header); err == nil && header.APIVersion == legacyAPIVersion {
		return Config{}, legacyMigrationError()
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			return Config{}, fmt.Errorf("decode trailing config document: %w", err)
		}
		return Config{}, errors.New("config must contain exactly one YAML document")
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func LoadFile(path string) (Config, error) {
	clean := filepath.Clean(path)
	info, err := os.Lstat(clean)
	if err != nil {
		return Config{}, fmt.Errorf("stat config: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Config{}, errors.New("config must be a regular non-symlink file")
	}
	if info.Size() <= 0 || info.Size() > MaxConfigBytes {
		return Config{}, fmt.Errorf("config size must be between 1 and %d bytes", MaxConfigBytes)
	}
	raw, err := os.ReadFile(clean)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	return Decode(raw)
}

func SaveFile(path string, config Config, overwrite bool) error {
	if err := config.Validate(); err != nil {
		return err
	}
	encoded, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		absolute, err := filepath.Abs(clean)
		if err != nil {
			return fmt.Errorf("resolve config path: %w", err)
		}
		clean = absolute
	}
	if err := os.MkdirAll(filepath.Dir(clean), 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	if info, err := os.Lstat(clean); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("existing config must be a regular non-symlink file")
		}
		if !overwrite {
			return os.ErrExist
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat config destination: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(clean), ".config-*")
	if err != nil {
		return fmt.Errorf("create config temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if overwrite {
		if err := os.Rename(temporaryName, clean); err != nil {
			return fmt.Errorf("replace config: %w", err)
		}
	} else {
		if err := os.Link(temporaryName, clean); err != nil {
			return fmt.Errorf("create config without overwrite: %w", err)
		}
		if err := os.Remove(temporaryName); err != nil {
			return err
		}
	}
	committed = true
	return nil
}

func Default() Config {
	return Config{
		APIVersion: APIVersion,
		Targets: map[string]Target{
			"local-reference": {
				BaseURL:  "http://127.0.0.1:8090/v1",
				Protocol: "openai-responses",
				Model:    "synthetic-model",
			},
		},
	}
}
