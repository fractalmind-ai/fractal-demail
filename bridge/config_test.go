package bridge

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

const cfgSecret = "whsec_c2VjcmV0LWtleS0zMi1ieXRlcy1sb25nLXRlc3QhIQ=="

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cfg.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func validCfg(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk := base64.StdEncoding.EncodeToString(pub)
	return `{
	  "bind": ":8080",
	  "packageId": "0x65c96400535e97f9a5c444c284dfb531590f2119f5de4a1253f15f1a99b72e82",
	  "orgs": [{
	    "domain": "algonius.ai",
	    "bridgeAddress": "0xeedfe046af0c10613356dea725fbe22af969a58077f27622936a6c4d9ec2fce3",
	    "gasCoin": "0xaefda11d73d84d396efc835f68f4d0b243109c3ceede1f64528f1358a9cac902",
	    "allowedSenders": ["owner@gmail.com"],
	    "agents": [{"localpart":"agent","suiAddress":"0xf4fafecc95c2e7c984f8d26db9b692cf58da977ee0119be38b84904b394e82e2","pubKey":"` + pk + `"}]
	  }]
	}`
}

func TestLoadAndBuildValid(t *testing.T) {
	cfg, err := LoadRelayerConfig(writeCfg(t, validCfg(t)))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	srv, err := cfg.BuildServer(cfgSecret)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if srv == nil || srv.Handler() == nil {
		t.Fatal("server not built")
	}
}

func TestBuildRejectsBadWebhookSecret(t *testing.T) {
	cfg, _ := LoadRelayerConfig(writeCfg(t, validCfg(t)))
	if _, err := cfg.BuildServer("not-base64!!!"); err == nil {
		t.Fatal("bad secret must be rejected")
	}
}

func TestBuildRejectsBadPubKey(t *testing.T) {
	body := `{
	  "packageId": "0x65c96400535e97f9a5c444c284dfb531590f2119f5de4a1253f15f1a99b72e82",
	  "orgs": [{
	    "domain": "algonius.ai",
	    "bridgeAddress": "0xeedfe046af0c10613356dea725fbe22af969a58077f27622936a6c4d9ec2fce3",
	    "gasCoin": "0xaefda11d73d84d396efc835f68f4d0b243109c3ceede1f64528f1358a9cac902",
	    "allowedSenders": ["owner@gmail.com"],
	    "agents": [{"localpart":"agent","suiAddress":"0xf4fafecc95c2e7c984f8d26db9b692cf58da977ee0119be38b84904b394e82e2","pubKey":"short"}]
	  }]
	}`
	cfg, _ := LoadRelayerConfig(writeCfg(t, body))
	if _, err := cfg.BuildServer(cfgSecret); err == nil {
		t.Fatal("bad pubkey must be rejected")
	}
}

func TestBuildRejectsNoOrgs(t *testing.T) {
	cfg, _ := LoadRelayerConfig(writeCfg(t, `{"packageId":"0x65c96400535e97f9a5c444c284dfb531590f2119f5de4a1253f15f1a99b72e82","orgs":[]}`))
	if _, err := cfg.BuildServer(cfgSecret); err == nil {
		t.Fatal("no orgs must be rejected")
	}
}

func TestLoadRejectsMissingFile(t *testing.T) {
	if _, err := LoadRelayerConfig("/no/such/file.json"); err == nil {
		t.Fatal("missing file must error")
	}
}

func TestBuildRejectsDuplicateOrgDomains(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pk := base64.StdEncoding.EncodeToString(pub)
	org := `{
	  "domain": "algonius.ai",
	  "bridgeAddress": "0xeedfe046af0c10613356dea725fbe22af969a58077f27622936a6c4d9ec2fce3",
	  "gasCoin": "0xaefda11d73d84d396efc835f68f4d0b243109c3ceede1f64528f1358a9cac902",
	  "allowedSenders": ["owner@gmail.com"],
	  "agents": [{"localpart":"agent","suiAddress":"0xf4fafecc95c2e7c984f8d26db9b692cf58da977ee0119be38b84904b394e82e2","pubKey":"` + pk + `"}]
	}`
	body := `{"packageId":"0x65c96400535e97f9a5c444c284dfb531590f2119f5de4a1253f15f1a99b72e82","orgs":[` + org + `,` + org + `]}`
	cfg, _ := LoadRelayerConfig(writeCfg(t, body))
	if _, err := cfg.BuildServer(cfgSecret); err == nil {
		t.Fatal("duplicate org domains must be rejected, not silently collapsed")
	}
}
