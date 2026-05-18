// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package config

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadServerConfigWithOverridesAppliesFlagPrecedence(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "server_config.toml")

	if err := os.WriteFile(configPath, []byte(`
PROTOCOL_TYPE = "SOCKS5"
UDP_PORT = 53
DOMAIN = ["config.example.com"]
DATA_ENCRYPTION_METHOD = 1
SUPPORTED_UPLOAD_COMPRESSION_TYPES = [0, 3]
SUPPORTED_DOWNLOAD_COMPRESSION_TYPES = [0, 3]
`), 0o644); err != nil {
		t.Fatalf("WriteFile config failed: %v", err)
	}

	cfg, err := LoadServerConfigWithOverrides(configPath, ServerConfigOverrides{
		Values: map[string]any{
			"UDPPort":                           5300,
			"Domain":                            []string{"flag.example.com", "alt.example.com"},
			"DataEncryptionMethod":              2,
			"SupportedUploadCompressionTypes":   []int{0, 1},
			"SupportedDownloadCompressionTypes": []int{0, 1, 3},
		},
	})
	if err != nil {
		t.Fatalf("LoadServerConfigWithOverrides returned error: %v", err)
	}

	if cfg.UDPPort != 5300 {
		t.Fatalf("unexpected udp port override: got=%d want=%d", cfg.UDPPort, 5300)
	}
	if len(cfg.Domain) != 2 || cfg.Domain[0] != "flag.example.com" || cfg.Domain[1] != "alt.example.com" {
		t.Fatalf("unexpected domain override: %+v", cfg.Domain)
	}
	if cfg.DataEncryptionMethod != 2 {
		t.Fatalf("unexpected data encryption override: got=%d want=%d", cfg.DataEncryptionMethod, 2)
	}
	if len(cfg.SupportedUploadCompressionTypes) != 2 || cfg.SupportedUploadCompressionTypes[0] != 0 || cfg.SupportedUploadCompressionTypes[1] != 1 {
		t.Fatalf("unexpected upload compression override: %+v", cfg.SupportedUploadCompressionTypes)
	}
	if len(cfg.SupportedDownloadCompressionTypes) != 3 {
		t.Fatalf("unexpected download compression override: %+v", cfg.SupportedDownloadCompressionTypes)
	}
}

func TestServerConfig_V2Keys(t *testing.T) {
	body := `
[server]
host = "auth.example.com"
encryption_key_file = "encrypt_key.txt"

[protocol]
accept = ["v1", "v2"]

[auth]
domains = ["a.example.com", "b.example.net"]

[v2]
data_encryption = "chacha20poly1305"
rekey_bytes = "256MB"
rekey_interval = "1h"

[v2.antidpi]
allow_rrtypes = ["A", "AAAA", "HTTPS", "SVCB", "TXT"]
accept_padding = true
`
	cfg, err := LoadServerConfigFromString(body)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Protocol.Accept) != 2 || cfg.Protocol.Accept[1] != "v2" {
		t.Fatalf("protocol.accept = %+v", cfg.Protocol.Accept)
	}
	if len(cfg.Auth.Domains) != 2 || cfg.Auth.Domains[0] != "a.example.com" {
		t.Fatalf("auth.domains = %+v", cfg.Auth.Domains)
	}
	if cfg.V2.DataEncryption != "chacha20poly1305" {
		t.Fatalf("v2.data_encryption = %q", cfg.V2.DataEncryption)
	}
	if !cfg.V2.AntiDPI.AcceptPadding {
		t.Fatalf("expected accept_padding = true")
	}
}

func TestServerConfigFlagBinderBuildsOverridesForSetFlagsOnly(t *testing.T) {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	binder, err := NewServerConfigFlagBinder(fs)
	if err != nil {
		t.Fatalf("NewServerConfigFlagBinder returned error: %v", err)
	}

	if err := fs.Parse([]string{
		"-udp-port=5300",
		"-domain=a.example.com,b.example.com",
		"-use-external-socks5",
		"-supported-upload-compression-types=0,1",
		"-data-encryption-method=2",
	}); err != nil {
		t.Fatalf("flag parse failed: %v", err)
	}

	overrides := binder.Overrides()
	if got, ok := overrides.Values["UDPPort"].(int); !ok || got != 5300 {
		t.Fatalf("unexpected udp port override: %#v", overrides.Values["UDPPort"])
	}
	if got, ok := overrides.Values["UseExternalSOCKS5"].(bool); !ok || !got {
		t.Fatalf("unexpected socks5 override: %#v", overrides.Values["UseExternalSOCKS5"])
	}
	if got, ok := overrides.Values["DataEncryptionMethod"].(int); !ok || got != 2 {
		t.Fatalf("unexpected encryption method override: %#v", overrides.Values["DataEncryptionMethod"])
	}
	gotDomains, ok := overrides.Values["Domain"].([]string)
	if !ok || len(gotDomains) != 2 || gotDomains[0] != "a.example.com" || gotDomains[1] != "b.example.com" {
		t.Fatalf("unexpected domains override: %#v", overrides.Values["Domain"])
	}
	gotCompressions, ok := overrides.Values["SupportedUploadCompressionTypes"].([]int)
	if !ok || len(gotCompressions) != 2 || gotCompressions[0] != 0 || gotCompressions[1] != 1 {
		t.Fatalf("unexpected compression override: %#v", overrides.Values["SupportedUploadCompressionTypes"])
	}
	if _, exists := overrides.Values["UDPHost"]; exists {
		t.Fatalf("did not expect unset flag to appear in overrides: %#v", overrides.Values["UDPHost"])
	}
}
