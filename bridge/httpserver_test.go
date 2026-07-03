package bridge

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type stubRelayer struct {
	res        RelayResult
	err        error
	gotHeaders map[string]string
	gotBody    []byte
	calls      int
}

func (s *stubRelayer) Handle(_ context.Context, headers map[string]string, body []byte) (RelayResult, error) {
	s.calls++
	s.gotHeaders = headers
	s.gotBody = body
	return s.res, s.err
}

func doPost(t *testing.T, h http.Handler, body string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/inbound", strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestWebhookServerDeliveredReturns200(t *testing.T) {
	sr := &stubRelayer{res: RelayResult{Delivered: true, TxDigest: "0xDIGEST"}}
	h := NewWebhookServer(sr, 0, nil).Handler()
	rec := doPost(t, h, `{"x":1}`, map[string]string{
		"svix-id": "m1", "svix-timestamp": "1", "svix-signature": "v1,sig",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if sr.calls != 1 || string(sr.gotBody) != `{"x":1}` {
		t.Fatalf("relayer got calls=%d body=%q", sr.calls, sr.gotBody)
	}
	// Signature headers must be forwarded to the verifier.
	if sr.gotHeaders["svix-signature"] != "v1,sig" {
		t.Fatalf("signature header not forwarded: %+v", sr.gotHeaders)
	}
}

func TestWebhookServerUnverifiedReturns401(t *testing.T) {
	sr := &stubRelayer{res: RelayResult{Drop: DropUnverified}, err: errors.New("bad sig")}
	h := NewWebhookServer(sr, 0, nil).Handler()
	rec := doPost(t, h, `{}`, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unverified status = %d, want 401", rec.Code)
	}
}

func TestWebhookServerSendFailedReturns502(t *testing.T) {
	sr := &stubRelayer{res: RelayResult{Drop: DropSendFailed}, err: errors.New("rpc")}
	h := NewWebhookServer(sr, 0, nil).Handler()
	rec := doPost(t, h, `{}`, nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("send-failed status = %d, want 502", rec.Code)
	}
}

func TestWebhookServerDroppedReturns200NoRetry(t *testing.T) {
	for _, d := range []DropReason{DropNotAllowed, DropRateLimited, DropNoRecipient, DropNoOrg, DropMalformed} {
		sr := &stubRelayer{res: RelayResult{Drop: d}}
		h := NewWebhookServer(sr, 0, nil).Handler()
		rec := doPost(t, h, `{}`, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("drop %s status = %d, want 200 (no provider retry)", d, rec.Code)
		}
	}
}

func TestWebhookServerRejectsNonPost(t *testing.T) {
	sr := &stubRelayer{}
	h := NewWebhookServer(sr, 0, nil).Handler()
	req := httptest.NewRequest(http.MethodGet, "/inbound", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed || sr.calls != 0 {
		t.Fatalf("GET must be 405 with no relay, got %d calls=%d", rec.Code, sr.calls)
	}
}

func TestWebhookServerCapsBody(t *testing.T) {
	sr := &stubRelayer{res: RelayResult{Delivered: true}}
	h := NewWebhookServer(sr, 16, nil).Handler() // 16-byte cap
	rec := doPost(t, h, strings.Repeat("a", 100), nil)
	if rec.Code != http.StatusRequestEntityTooLarge || sr.calls != 0 {
		t.Fatalf("oversized body must be 413 with no relay, got %d calls=%d", rec.Code, sr.calls)
	}
}

func TestWebhookServerHealthz(t *testing.T) {
	h := NewWebhookServer(&stubRelayer{}, 0, nil).Handler()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz = %d", rec.Code)
	}
	b, _ := io.ReadAll(rec.Body)
	if string(b) != "ok" {
		t.Fatalf("healthz body = %q", b)
	}
}
