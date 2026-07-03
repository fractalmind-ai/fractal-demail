package listener

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fractalmind-ai/fractal-demail/client-go/envelope"
	"github.com/fractalmind-ai/fractal-demail/client-go/schema"
)

const (
	senderAddr    = "0xf4fafecc95c2e7c984f8d26db9b692cf58da977ee0119be38b84904b394e82e2"
	recipientAddr = "0xeedfe046af0c10613356dea725fbe22af969a58077f27622936a6c4d9ec2fce3"
	packageID     = "0x65c96400535e97f9a5c444c284dfb531590f2119f5de4a1253f15f1a99b72e82"
	messageID     = "0x038dc21988cb6c41d467ccdebab81b1a7a3597bd7d7336fce52d518eea9aae9e"
)

// mockRPC serves suix_queryEvents (one MessageSent event) and sui_getObject
// (the sealed envelope payload).
func mockRPC(t *testing.T, payloadB64 string) *httptest.Server {
	t.Helper()
	return mockRPCWithKind(t, payloadB64, fmt.Sprintf("%q", base64.StdEncoding.EncodeToString([]byte("inline"))))
}

func mockRPCWithKind(t *testing.T, payloadB64 string, payloadKindJSON string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			ID     int    `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("bad rpc request: %v", err)
		}
		var result string
		switch req.Method {
		case "suix_queryEvents":
			result = fmt.Sprintf(`{
				"data": [{
					"id": {"txDigest": "abc", "eventSeq": "0"},
					"parsedJson": {
						"message_id": %q,
						"sender": %q,
						"recipient": %q,
						"payload_kind": %s,
						"created_at_ms": "1783011086750"
					}
				}],
				"nextCursor": {"txDigest": "abc", "eventSeq": "0"},
				"hasNextPage": false
			}`, messageID, senderAddr, recipientAddr, payloadKindJSON)
		case "sui_getObject":
			result = fmt.Sprintf(`{"data": {"content": {"fields": {"payload": %q}}}}`, payloadB64)
		default:
			t.Errorf("unexpected rpc method %s", req.Method)
		}
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":%s}`, req.ID, result)
	}))
}

func sealedPayload(t *testing.T, recipientPub ed25519.PublicKey, body string) string {
	t.Helper()
	plaintext := fmt.Sprintf(
		`{"type":"task","from":%q,"to":%q,"body":%q,"ts":1783011086750}`,
		senderAddr, recipientAddr, body)
	sender, err := decodeAddress(senderAddr)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := decodeAddress(recipientAddr)
	if err != nil {
		t.Fatal(err)
	}
	env, err := envelope.Seal(recipientPub, sender, recipient, []byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(wire)
}

func TestPollOnceDecryptsAndDelivers(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := mockRPC(t, sealedPayload(t, pub, "run backup"))
	defer srv.Close()

	var got *schema.Plaintext
	l, err := New(Config{
		RPCURL:      srv.URL,
		PackageID:   packageID,
		Recipient:   recipientAddr,
		IdentityKey: priv,
	}, func(id string, msg *schema.Plaintext) {
		if id != messageID {
			t.Errorf("message id = %s", id)
		}
		got = msg
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if got == nil {
		t.Fatal("handler not called")
	}
	if got.Body != "run backup" || got.Type != schema.TypeTask {
		t.Fatalf("unexpected message: %+v", got)
	}
	if l.cursor == nil {
		t.Fatal("cursor not advanced")
	}
}

func TestPollOnceAcceptsVectorU8ArrayPayloadKind(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := mockRPCWithKind(t, sealedPayload(t, pub, "array-kind"), `[105,110,108,105,110,101]`)
	defer srv.Close()

	called := false
	l, err := New(Config{
		RPCURL:      srv.URL,
		PackageID:   packageID,
		Recipient:   recipientAddr,
		IdentityKey: priv,
	}, func(_ string, msg *schema.Plaintext) {
		called = msg.Body == "array-kind"
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if !called {
		t.Fatal("handler not called for array-encoded payload_kind")
	}
}

func TestPollOnceDropsWrongKeyMessage(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := mockRPC(t, sealedPayload(t, pub, "secret"))
	defer srv.Close()

	called := false
	l, err := New(Config{
		RPCURL:      srv.URL,
		PackageID:   packageID,
		Recipient:   recipientAddr,
		IdentityKey: otherPriv,
	}, func(string, *schema.Plaintext) { called = true })
	if err != nil {
		t.Fatal(err)
	}
	// Undecryptable message is dropped without failing the poll.
	if err := l.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if called {
		t.Fatal("handler must not receive undecryptable messages")
	}
}

func TestPollOnceIgnoresOtherRecipients(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := mockRPC(t, sealedPayload(t, pub, "x"))
	defer srv.Close()

	called := false
	l, err := New(Config{
		RPCURL:      srv.URL,
		PackageID:   packageID,
		Recipient:   senderAddr, // we are not the event's recipient
		IdentityKey: priv,
	}, func(string, *schema.Plaintext) { called = true })
	if err != nil {
		t.Fatal(err)
	}
	if err := l.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if called {
		t.Fatal("handler must not receive messages routed to other recipients")
	}
}

func TestPollOnceRetriesMessageAfterTransientFetchError(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := sealedPayload(t, pub, "must not be lost")

	failNext := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			ID     int    `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("bad rpc request: %v", err)
		}
		var result string
		switch req.Method {
		case "suix_queryEvents":
			result = fmt.Sprintf(`{
				"data": [{
					"id": {"txDigest": "abc", "eventSeq": "0"},
					"parsedJson": {
						"message_id": %q,
						"sender": %q,
						"recipient": %q,
						"payload_kind": %q,
						"created_at_ms": "1783011086750"
					}
				}],
				"nextCursor": {"txDigest": "abc", "eventSeq": "0"},
				"hasNextPage": false
			}`, messageID, senderAddr, recipientAddr,
				base64.StdEncoding.EncodeToString([]byte("inline")))
		case "sui_getObject":
			if failNext {
				failNext = false
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			result = fmt.Sprintf(`{"data": {"content": {"fields": {"payload": %q}}}}`, payload)
		default:
			t.Errorf("unexpected rpc method %s", req.Method)
		}
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":%s}`, req.ID, result)
	}))
	defer srv.Close()

	delivered := 0
	l, err := New(Config{
		RPCURL:      srv.URL,
		PackageID:   packageID,
		Recipient:   recipientAddr,
		IdentityKey: priv,
	}, func(_ string, msg *schema.Plaintext) {
		if msg.Body == "must not be lost" {
			delivered++
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	// First poll: transient 500 on sui_getObject — must surface an error and
	// must NOT advance the cursor past the valid message.
	if err := l.PollOnce(context.Background()); err == nil {
		t.Fatal("expected transient error from first poll")
	}
	if delivered != 0 {
		t.Fatal("message must not be delivered while fetch fails")
	}
	if l.cursor != nil {
		t.Fatalf("cursor must not advance past an unfetched message, got %s", l.cursor)
	}
	// Second poll: RPC healthy again — the same message must be delivered.
	if err := l.PollOnce(context.Background()); err != nil {
		t.Fatalf("second PollOnce: %v", err)
	}
	if delivered != 1 {
		t.Fatalf("message lost after transient error: delivered=%d", delivered)
	}
}

func TestPollOncePoisonMessageStillAdvancesCursor(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Sealed to a different key: genuine poison for us, must be skipped.
	srv := mockRPC(t, sealedPayload(t, pub, "poison"))
	defer srv.Close()

	l, err := New(Config{
		RPCURL:      srv.URL,
		PackageID:   packageID,
		Recipient:   recipientAddr,
		IdentityKey: otherPriv,
	}, func(string, *schema.Plaintext) {})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if l.cursor == nil {
		t.Fatal("cursor must advance past genuine poison messages")
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := mockRPC(t, sealedPayload(t, pub, "x"))
	defer srv.Close()

	l, err := New(Config{
		RPCURL:       srv.URL,
		PackageID:    packageID,
		Recipient:    recipientAddr,
		IdentityKey:  priv,
		PollInterval: 10 * time.Millisecond,
	}, func(string, *schema.Plaintext) {})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := l.Run(ctx); err != context.DeadlineExceeded {
		t.Fatalf("Run returned %v, want context.DeadlineExceeded", err)
	}
}

func TestCursorPersistedAndReloaded(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := mockRPC(t, sealedPayload(t, pub, "persist me"))
	defer srv.Close()

	cursorFile := t.TempDir() + "/cursor.json"
	if err := os.WriteFile(cursorFile, []byte(`{"txDigest":"seed","eventSeq":"0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := New(Config{
		RPCURL:      srv.URL,
		PackageID:   packageID,
		Recipient:   recipientAddr,
		IdentityKey: priv,
		CursorFile:  cursorFile,
	}, func(string, *schema.Plaintext) {})
	if err != nil {
		t.Fatal(err)
	}
	if l.needsInit {
		t.Fatal("valid cursor file must not trigger init-from-latest")
	}
	if string(l.cursor) != `{"txDigest":"seed","eventSeq":"0"}` {
		t.Fatalf("cursor not loaded from file: %s", l.cursor)
	}
	if err := l.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	data, err := os.ReadFile(cursorFile)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) || string(data) == `{"txDigest":"seed","eventSeq":"0"}` {
		t.Fatalf("cursor file not advanced after poll: %s", data)
	}
}

func TestFreshCursorFileSkipsHistory(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := sealedPayload(t, pub, "historical")

	var descendingCalls, ascendingCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string            `json:"method"`
			ID     int               `json:"id"`
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("bad rpc request: %v", err)
		}
		var result string
		switch req.Method {
		case "suix_queryEvents":
			descending := len(req.Params) == 4 && string(req.Params[3]) == "true"
			if descending {
				descendingCalls++
				// Newest historical event.
				result = fmt.Sprintf(`{
					"data": [{
						"id": {"txDigest": "latest", "eventSeq": "7"},
						"parsedJson": {
							"message_id": %q, "sender": %q, "recipient": %q,
							"payload_kind": %q, "created_at_ms": "1"
						}
					}],
					"nextCursor": null, "hasNextPage": false
				}`, messageID, senderAddr, recipientAddr,
					base64.StdEncoding.EncodeToString([]byte("inline")))
			} else {
				ascendingCalls++
				// Nothing new after the latest cursor.
				result = `{"data": [], "nextCursor": null, "hasNextPage": false}`
			}
		case "sui_getObject":
			result = fmt.Sprintf(`{"data": {"content": {"fields": {"payload": %q}}}}`, payload)
		default:
			t.Errorf("unexpected rpc method %s", req.Method)
		}
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":%s}`, req.ID, result)
	}))
	defer srv.Close()

	called := false
	cursorFile := t.TempDir() + "/cursor.json"
	l, err := New(Config{
		RPCURL:      srv.URL,
		PackageID:   packageID,
		Recipient:   recipientAddr,
		IdentityKey: priv,
		CursorFile:  cursorFile,
	}, func(string, *schema.Plaintext) { called = true })
	if err != nil {
		t.Fatal(err)
	}
	// First poll initializes from latest without delivering history.
	if err := l.PollOnce(context.Background()); err != nil {
		t.Fatalf("init poll: %v", err)
	}
	if called {
		t.Fatal("history must not be replayed on fresh deployment")
	}
	if descendingCalls != 1 {
		t.Fatalf("expected one descending init query, got %d", descendingCalls)
	}
	if string(l.cursor) != `{"txDigest": "latest", "eventSeq": "7"}` {
		t.Fatalf("cursor not initialized from latest: %s", l.cursor)
	}
	// Second poll is a normal ascending query from that cursor.
	if err := l.PollOnce(context.Background()); err != nil {
		t.Fatalf("second poll: %v", err)
	}
	if called {
		t.Fatal("no new events: handler must not fire")
	}
	if ascendingCalls != 1 {
		t.Fatalf("expected one ascending query, got %d", ascendingCalls)
	}
	if data, err := os.ReadFile(cursorFile); err != nil || !json.Valid(data) {
		t.Fatalf("cursor file not persisted: %v %s", err, data)
	}
}

func TestPollOnceAcceptsBase64TextInlinePayload(t *testing.T) {
	// Canonical on-chain inline encoding: the Message.payload bytes are the
	// base64 TEXT of the envelope JSON (what a CLI/PTB sender writes). The
	// object RPC then renders those bytes base64-encoded once more.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envB64Text := sealedPayload(t, pub, "cli-sender-payload") // base64 of envelope JSON
	doubleEncoded := base64.StdEncoding.EncodeToString([]byte(envB64Text))
	srv := mockRPC(t, doubleEncoded)
	defer srv.Close()

	got := ""
	l, err := New(Config{
		RPCURL:      srv.URL,
		PackageID:   packageID,
		Recipient:   recipientAddr,
		IdentityKey: priv,
	}, func(_ string, msg *schema.Plaintext) { got = msg.Body })
	if err != nil {
		t.Fatal(err)
	}
	if err := l.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if got != "cli-sender-payload" {
		t.Fatalf("base64-text inline payload not delivered, got %q", got)
	}
}

func TestDecodeVectorU8NumberArray(t *testing.T) {
	got, err := decodeVectorU8(json.RawMessage(`[104,105]`))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hi" {
		t.Fatalf("got %q", got)
	}
	if _, err := decodeVectorU8(json.RawMessage(`[300]`)); err == nil {
		t.Fatal("expected out-of-range rejection")
	}
}

func TestStuckCursorEscalatesOnceAndRecovers(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub
	// Always-500 server: every poll fails as a transport error.
	fail := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var req struct {
			ID int `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{"data":[],"nextCursor":null,"hasNextPage":false}}`, req.ID)
	}))
	defer srv.Close()

	var errs, recovered int
	lg := slog.New(slogHandlerFunc(func(level slog.Level, msg string) {
		if level == slog.LevelError && strings.Contains(msg, "stuck") {
			errs++
		}
		if level == slog.LevelInfo && strings.Contains(msg, "recovered") {
			recovered++
		}
	}))
	l, err := New(Config{
		RPCURL:               srv.URL,
		PackageID:            packageID,
		Recipient:            recipientAddr,
		IdentityKey:          priv,
		StuckCursorThreshold: 3,
		Logger:               lg,
	}, func(string, *schema.Plaintext) {})
	if err != nil {
		t.Fatal(err)
	}
	// 5 failing polls: escalate exactly once at the threshold.
	for i := 0; i < 5; i++ {
		l.recordPoll(l.PollOnce(context.Background()))
	}
	if got := l.Stats().ConsecutivePollFailures; got != 5 {
		t.Fatalf("ConsecutivePollFailures = %d, want 5", got)
	}
	if errs != 1 {
		t.Fatalf("stuck escalations = %d, want exactly 1", errs)
	}
	// Recover: a healthy poll resets counters and logs recovery once.
	fail = false
	l.recordPoll(l.PollOnce(context.Background()))
	if got := l.Stats().ConsecutivePollFailures; got != 0 {
		t.Fatalf("after recovery ConsecutivePollFailures = %d, want 0", got)
	}
	if recovered != 1 {
		t.Fatalf("recovery logs = %d, want 1", recovered)
	}
	if l.Stats().TotalPollFailures != 5 {
		t.Fatalf("TotalPollFailures = %d, want 5", l.Stats().TotalPollFailures)
	}
}

func TestDecodeInlineRejectsURLSafeBase64(t *testing.T) {
	// A URL-safe/unpadded base64 rendering of envelope JSON must NOT decode as
	// canonical inline (spec pins StdEncoding); it falls through to poison.
	env := []byte(`{"v":1,"alg":"x25519-xchacha20poly1305","epk":"","nonce":"","ct":""}`)
	urlSafe := base64.RawURLEncoding.EncodeToString(env)
	got := decodeInlinePayload([]byte(urlSafe))
	// Not valid StdEncoding → returned as-is (the raw url-safe text), which is
	// neither JSON nor a valid envelope → poison downstream.
	if string(got) == string(env) {
		t.Fatal("url-safe base64 must not be accepted as canonical inline")
	}
	// Standard padded base64 of the same bytes DOES decode.
	std := base64.StdEncoding.EncodeToString(env)
	if string(decodeInlinePayload([]byte(std))) != string(env) {
		t.Fatal("standard padded base64 must decode to envelope JSON")
	}
	// Raw JSON passes through untouched.
	if string(decodeInlinePayload(env)) != string(env) {
		t.Fatal("raw JSON must pass through")
	}
}

// slogHandlerFunc is a minimal slog.Handler capturing level+message.
type slogHandlerFunc func(slog.Level, string)

func (f slogHandlerFunc) Enabled(context.Context, slog.Level) bool { return true }
func (f slogHandlerFunc) Handle(_ context.Context, r slog.Record) error {
	f(r.Level, r.Message)
	return nil
}
func (f slogHandlerFunc) WithAttrs([]slog.Attr) slog.Handler { return f }
func (f slogHandlerFunc) WithGroup(string) slog.Handler      { return f }
