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
