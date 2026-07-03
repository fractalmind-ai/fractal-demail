package listener

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

func TestPollOnceAcceptsInlinePayloadWithTrailingNewline(t *testing.T) {
	// CLI tools (base64(1), shell heredocs) append a trailing newline to the
	// payload text; the spec allows decoders to strip surrounding whitespace.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envB64Text := sealedPayload(t, pub, "cli-newline")
	doubleEncoded := base64.StdEncoding.EncodeToString([]byte(envB64Text + "\n"))
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
	if got != "cli-newline" {
		t.Fatalf("trailing-newline payload not delivered, got %q", got)
	}
}

func TestPollOnceRejectsNonPinnedBase64InlineAsPoison(t *testing.T) {
	// Inline payloads in a non-pinned base64 variant (docs/payload-envelope.md
	// §0) are poison: dropped without delivery, without stalling the stream,
	// and with the cursor advanced past them.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envB64Text := sealedPayload(t, pub, "variant-probe")

	variants := map[string]string{
		"url-safe alphabet": strings.NewReplacer("+", "-", "/", "_").Replace(envB64Text),
		"unpadded":          strings.TrimRight(envB64Text, "="),
		"interior crlf":     envB64Text[:8] + "\r\n" + envB64Text[8:],
		"interior lf":       envB64Text[:8] + "\n" + envB64Text[8:],
		"garbage":           "not base64 at all!",
	}
	for name, payloadText := range variants {
		if payloadText == envB64Text {
			continue // mutation happened to be a no-op this run
		}
		t.Run(name, func(t *testing.T) {
			srv := mockRPC(t, base64.StdEncoding.EncodeToString([]byte(payloadText)))
			defer srv.Close()

			called := false
			l, err := New(Config{
				RPCURL:      srv.URL,
				PackageID:   packageID,
				Recipient:   recipientAddr,
				IdentityKey: priv,
			}, func(string, *schema.Plaintext) { called = true })
			if err != nil {
				t.Fatal(err)
			}
			if err := l.PollOnce(context.Background()); err != nil {
				t.Fatalf("poison must not fail the poll: %v", err)
			}
			if called {
				t.Fatal("handler must not receive non-pinned-variant payloads")
			}
			if l.cursor == nil {
				t.Fatal("cursor must advance past poison messages")
			}
		})
	}
}

func TestDecodeInlinePayload(t *testing.T) {
	rawJSON := []byte(`{"v":1}`)
	if got, err := decodeInlinePayload(rawJSON); err != nil || string(got) != `{"v":1}` {
		t.Fatalf("raw JSON compat path: got %q, %v", got, err)
	}
	if got, err := decodeInlinePayload([]byte("aGVsbG8=\n")); err != nil || string(got) != "hello" {
		t.Fatalf("canonical base64 with trailing newline: got %q, %v", got, err)
	}
	for _, bad := range []string{"aGVsbG8", "aGVs\nbG8=", "aGVsbG8_", "ZE=="} {
		if _, err := decodeInlinePayload([]byte(bad)); err == nil {
			t.Errorf("non-pinned payload %q must be rejected", bad)
		}
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
