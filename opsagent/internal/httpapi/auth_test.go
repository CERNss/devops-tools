package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestReadAndVerify(t *testing.T) {
	secret := "test-secret"
	body := `{"app_name":"demo-app"}`
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req, err := http.NewRequest(http.MethodPost, "/deploy", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Signature", sign(ts, body, secret))

	got, err := readAndVerify(req, secret)
	if err != nil {
		t.Fatalf("readAndVerify failed: %v", err)
	}
	if string(got) != body {
		t.Fatalf("body mismatch: got %q", string(got))
	}
}

func TestReadAndVerifyRejectsBadSignature(t *testing.T) {
	secret := "test-secret"
	body := `{"app_name":"demo-app"}`
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req, err := http.NewRequest(http.MethodPost, "/deploy", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Signature", "bad")

	if _, err := readAndVerify(req, secret); err == nil {
		t.Fatal("expected bad signature error")
	}
}

func sign(ts, body, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(ts + "." + body))
	return hex.EncodeToString(mac.Sum(nil))
}
