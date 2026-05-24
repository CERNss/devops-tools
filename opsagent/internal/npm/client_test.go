package npm

import (
	"testing"

	"opsagent/internal/api"
)

func TestProxyPayloadDefaultsAndValidation(t *testing.T) {
	disabled := false
	req := api.NPMProxyHostRequest{
		DomainNames:      []string{"demo.example.com"},
		ForwardHost:      "127.0.0.1",
		ForwardPort:      18080,
		BlockExploits:    &disabled,
		WebsocketUpgrade: &disabled,
		Enabled:          &disabled,
	}
	if err := ValidateProxyHost(req); err != nil {
		t.Fatal(err)
	}

	payload := ProxyPayload(req)
	if payload["block_exploits"] != false {
		t.Fatalf("expected block_exploits false, got %#v", payload["block_exploits"])
	}
	if payload["allow_websocket_upgrade"] != false {
		t.Fatalf("expected websocket false, got %#v", payload["allow_websocket_upgrade"])
	}
	if payload["enabled"] != false {
		t.Fatalf("expected enabled false, got %#v", payload["enabled"])
	}
}
