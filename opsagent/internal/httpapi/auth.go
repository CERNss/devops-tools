package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const signatureWindow = 5 * time.Minute

type AuthConfig struct {
	WebhookSecret string
	APIKey        string
}

func readAndVerify(r *http.Request, auth AuthConfig) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	if auth.APIKey != "" {
		got := r.Header.Get("X-API-Key")
		if hmac.Equal([]byte(got), []byte(auth.APIKey)) {
			return body, nil
		}
	}

	ts := r.Header.Get("X-Timestamp")
	sig := strings.TrimPrefix(r.Header.Get("X-Signature"), "sha256=")
	if ts == "" || sig == "" {
		return nil, errors.New("missing api key or signature")
	}

	timestamp, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return nil, errors.New("invalid timestamp")
	}

	now := time.Now()
	signedAt := time.Unix(timestamp, 0)
	if signedAt.Before(now.Add(-signatureWindow)) || signedAt.After(now.Add(signatureWindow)) {
		return nil, errors.New("timestamp expired")
	}

	payload := ts + "." + string(body)
	mac := hmac.New(sha256.New, []byte(auth.WebhookSecret))
	_, _ = mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(expected), []byte(sig)) {
		return nil, errors.New("bad signature")
	}

	return body, nil
}
