package bridge

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

const testSecret = "c2VjcmV0LWtleS0zMi1ieXRlcy1sb25nLXRlc3QhIQ==" // base64 of a 32B key

func signSvix(t *testing.T, secretB64, id, ts string, body []byte) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, raw)
	mac.Write([]byte(id + "." + ts + "."))
	mac.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func inboundBody() []byte {
	return []byte(`{"type":"email.received","data":{"from":"owner@gmail.com","to":["agent@mail.example.com"],"subject":"hi","text":"do the job"}}`)
}

func fixedNow() time.Time { return time.Unix(1783000000, 0) }

func newVerifier(t *testing.T) *ResendInboundVerifier {
	v, err := NewResendInboundVerifier("whsec_" + testSecret)
	if err != nil {
		t.Fatal(err)
	}
	v.now = fixedNow
	return v
}

func TestResendVerifyHappyPath(t *testing.T) {
	v := newVerifier(t)
	body := inboundBody()
	ts := strconv.FormatInt(fixedNow().Unix(), 10)
	sig := signSvix(t, testSecret, "msg_1", ts, body)
	email, err := v.Verify(map[string]string{
		"svix-id": "msg_1", "svix-timestamp": ts, "svix-signature": sig,
	}, body)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if email.From != "owner@gmail.com" || email.To != "agent@mail.example.com" || email.Body != "do the job" {
		t.Fatalf("parsed wrong: %+v", email)
	}
}

func TestResendVerifyRejectsBadSignature(t *testing.T) {
	v := newVerifier(t)
	body := inboundBody()
	ts := strconv.FormatInt(fixedNow().Unix(), 10)
	// Signature computed over a tampered body.
	sig := signSvix(t, testSecret, "msg_1", ts, []byte("tampered"))
	_, err := v.Verify(map[string]string{
		"svix-id": "msg_1", "svix-timestamp": ts, "svix-signature": sig,
	}, body)
	if err == nil {
		t.Fatal("expected signature rejection for tampered body")
	}
}

func TestResendVerifyRejectsStaleTimestamp(t *testing.T) {
	v := newVerifier(t)
	body := inboundBody()
	staleTs := strconv.FormatInt(fixedNow().Add(-10*time.Minute).Unix(), 10)
	sig := signSvix(t, testSecret, "msg_1", staleTs, body)
	_, err := v.Verify(map[string]string{
		"svix-id": "msg_1", "svix-timestamp": staleTs, "svix-signature": sig,
	}, body)
	if err == nil {
		t.Fatal("expected stale-timestamp rejection (replay defense)")
	}
}

func TestResendVerifyRejectsMissingHeaders(t *testing.T) {
	v := newVerifier(t)
	if _, err := v.Verify(map[string]string{}, inboundBody()); err == nil {
		t.Fatal("expected missing-headers rejection")
	}
}

func TestResendVerifyCaseInsensitiveHeaders(t *testing.T) {
	v := newVerifier(t)
	body := inboundBody()
	ts := strconv.FormatInt(fixedNow().Unix(), 10)
	sig := signSvix(t, testSecret, "msg_1", ts, body)
	if _, err := v.Verify(map[string]string{
		"Svix-Id": "msg_1", "Svix-Timestamp": ts, "Svix-Signature": sig,
	}, body); err != nil {
		t.Fatalf("case-insensitive headers must work: %v", err)
	}
}

func TestNewResendInboundVerifierValidation(t *testing.T) {
	if _, err := NewResendInboundVerifier(""); err == nil {
		t.Fatal("empty secret must be rejected")
	}
	if _, err := NewResendInboundVerifier("whsec_not-base64!!!"); err == nil {
		t.Fatal("non-base64 secret must be rejected")
	}
}

func TestResendSMTPSendHappyPath(t *testing.T) {
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"email_1"}`))
	}))
	defer srv.Close()

	c, err := NewResendSMTPClient("re_key", "agent@mail.example.com", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	c.baseURL = srv.URL
	if err := c.Send(context.Background(), "owner@gmail.com", "re: job", "the result"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotAuth != "Bearer re_key" {
		t.Fatalf("auth header = %q", gotAuth)
	}
	for _, want := range []string{`"agent@mail.example.com"`, `"owner@gmail.com"`, `"re: job"`, `"the result"`} {
		if !contains(gotBody, want) {
			t.Fatalf("request body missing %s: %s", want, gotBody)
		}
	}
}

func TestResendSMTPSendSurfacesHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"domain not verified"}`))
	}))
	defer srv.Close()
	c, _ := NewResendSMTPClient("re_key", "agent@mail.example.com", srv.Client())
	c.baseURL = srv.URL
	if err := c.Send(context.Background(), "owner@gmail.com", "s", "b"); err == nil {
		t.Fatal("expected error surfaced for non-2xx")
	}
}

func TestNewResendSMTPClientValidation(t *testing.T) {
	if _, err := NewResendSMTPClient("", "a@b.com", nil); err == nil {
		t.Fatal("empty api key must be rejected")
	}
	if _, err := NewResendSMTPClient("k", "not-an-email", nil); err == nil {
		t.Fatal("bad from must be rejected")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
