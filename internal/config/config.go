package config

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

const (
	APIVersion        = "urn:agentapi-doctor:config:v1beta2"
	legacyAPIVersion  = "urn:agentapi-doctor:config:v1beta1"
	TargetNamePattern = `^[a-z0-9][a-z0-9._-]{0,127}$`
)

var targetNamePattern = regexp.MustCompile(TargetNamePattern)

type Config struct {
	APIVersion string            `yaml:"apiVersion" json:"apiVersion"`
	Targets    map[string]Target `yaml:"targets" json:"targets"`
}

type Target struct {
	BaseURL  string            `yaml:"baseURL" json:"baseURL"`
	Protocol string            `yaml:"protocol" json:"protocol"`
	Model    string            `yaml:"model" json:"model"`
	Auth     *Auth             `yaml:"auth,omitempty" json:"auth,omitempty"`
	Metadata map[string]string `yaml:"metadata,omitempty" json:"metadata,omitempty"`
}

type Auth struct {
	Type   string          `yaml:"type" json:"type"`
	Token  SecretReference `yaml:"token" json:"token"`
	Header string          `yaml:"header,omitempty" json:"header,omitempty"`
}

type SecretReference struct {
	Ref string `yaml:"ref" json:"ref"`
}

func (config Config) Validate() error {
	if config.APIVersion == legacyAPIVersion {
		return legacyMigrationError()
	}
	if config.APIVersion != APIVersion {
		return fmt.Errorf("unsupported config apiVersion %q", config.APIVersion)
	}
	if len(config.Targets) == 0 {
		return errors.New("config requires at least one target")
	}
	for name, target := range config.Targets {
		if !targetNamePattern.MatchString(name) {
			return fmt.Errorf("invalid target name %q", name)
		}
		if err := target.Validate(); err != nil {
			return fmt.Errorf("target %s: %w", name, err)
		}
	}
	return nil
}

func legacyMigrationError() error {
	return fmt.Errorf("config apiVersion %q is no longer supported; remove the top-level defaults field and change apiVersion to %q", legacyAPIVersion, APIVersion)
}

func (target Target) Validate() error {
	parsed, err := url.Parse(target.BaseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("baseURL %q must be an absolute HTTP(S) URL without credentials, query, or fragment", target.BaseURL)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("baseURL scheme must be http or https")
	}
	if target.Protocol == "" || target.Model == "" {
		return errors.New("protocol and model are required")
	}
	if target.Auth != nil {
		if err := target.Auth.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (auth Auth) Validate() error {
	if !slices.Contains([]string{"bearer", "header"}, auth.Type) {
		return fmt.Errorf("unsupported auth type %q", auth.Type)
	}
	if auth.Type == "header" && auth.Header == "" {
		return errors.New("header auth requires a header name")
	}
	_, err := ParseSecretReference(auth.Token.Ref)
	return err
}

type SecretScheme string

const (
	SecretEnv     SecretScheme = "env"
	SecretKeyring SecretScheme = "keyring"
	SecretFile    SecretScheme = "file"
	SecretExec    SecretScheme = "exec"
)

type ParsedSecretReference struct {
	Scheme SecretScheme
	Value  string
}

func ParseSecretReference(reference string) (ParsedSecretReference, error) {
	index := strings.Index(reference, "://")
	if index <= 0 || index+3 >= len(reference) {
		return ParsedSecretReference{}, errors.New("secret ref must use env://, keyring://, file://, or exec://")
	}
	parsed := ParsedSecretReference{Scheme: SecretScheme(reference[:index]), Value: reference[index+3:]}
	if !slices.Contains([]SecretScheme{SecretEnv, SecretKeyring, SecretFile, SecretExec}, parsed.Scheme) {
		return ParsedSecretReference{}, fmt.Errorf("unsupported secret ref scheme %q", parsed.Scheme)
	}
	if strings.ContainsAny(parsed.Value, "\x00\r\n") {
		return ParsedSecretReference{}, errors.New("secret ref contains forbidden control characters")
	}
	if parsed.Scheme == SecretEnv && strings.ContainsAny(parsed.Value, "/\\") {
		return ParsedSecretReference{}, errors.New("env secret ref must name one variable")
	}
	return parsed, nil
}
