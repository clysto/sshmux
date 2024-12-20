package common

import (
	"github.com/BurntSushi/toml"
)

type SSOConfig struct {
	Name         string   `toml:"name"`
	Label        string   `toml:"label"`
	ClientID     string   `toml:"client_id"`
	ClientSecret string   `toml:"client_secret"`
	IssuerURL    string   `toml:"issuer_url"`
	Scopes       []string `toml:"scopes"`
}

type Config struct {
	Port                    int         `toml:"http_port"`
	SSHPort                 int         `toml:"ssh_port"`
	SSHHost                 string      `toml:"ssh_host"`
	ExternalURL             string      `toml:"external_url"`
	SSOProviders            []SSOConfig `toml:"sso_providers"`
	DB                      string      `toml:"db"`
	PrivateKey              string      `toml:"private_key"`
	SessionSecret           string      `toml:"session_secret"`
	RecordingsDir           string      `toml:"recordings_dir"`
	RecordingsRetentionDays int         `toml:"recordings_retention_days"`
}

func LoadConfig(path string) (*Config, error) {
	var config Config
	if _, err := toml.DecodeFile(path, &config); err != nil {
		return nil, err
	}
	return &config, nil
}
