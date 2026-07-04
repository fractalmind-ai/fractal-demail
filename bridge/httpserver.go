package bridge

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// inboundHandler is the subset of MultiOrgRelayer the HTTP server needs; an
// interface keeps the server testable and lets a single-org InboundRelayer be
// served too.
type inboundHandler interface {
	Handle(ctx context.Context, headers map[string]string, body []byte) (RelayResult, error)
}

// Compile-time proof the production relayers satisfy the server's dependency.
var (
	_ inboundHandler = (*MultiOrgRelayer)(nil)
	_ inboundHandler = (*InboundRelayer)(nil)
)

// WebhookServer exposes an inbound relayer as an HTTP endpoint for a provider
// (Resend) to POST verified webhooks to. It maps relay outcomes to status
// codes without leaking internals, caps the request body, and never logs
// secrets or payloads.
type WebhookServer struct {
	relayer inboundHandler
	maxBody int64
	logger  *slog.Logger
}

// NewWebhookServer wraps a relayer. maxBody defaults to 1 MiB.
func NewWebhookServer(relayer inboundHandler, maxBody int64, logger *slog.Logger) *WebhookServer {
	if maxBody <= 0 {
		maxBody = 1 << 20
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &WebhookServer{relayer: relayer, maxBody: maxBody, logger: logger}
}

// Handler returns the HTTP handler. Mount it at the path configured as the
// provider's webhook URL (e.g. POST /inbound).
func (s *WebhookServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})
	mux.HandleFunc("/inbound", s.handleInbound)
	return mux
}

// dropStatus maps a drop reason to an HTTP status so the provider retries
// exactly the failures that could later succeed.
func dropStatus(d DropReason) int {
	switch d {
	case DropUnverified:
		return http.StatusUnauthorized
	case DropSendFailed:
		return http.StatusBadGateway // transient chain/send: provider retries
	case DropRateLimited:
		// The limiter is a token bucket (a rate throttle, not a permanent
		// policy or a total quota), and only allowlisted+verified senders
		// reach it. "Too fast right now" — the same message retried after the
		// bucket refills WOULD succeed, so ask the provider to retry instead
		// of silently dropping a legitimate email.
		return http.StatusTooManyRequests
	default:
		// not_allowed / no_recipient / no_org / malformed: these will never
		// succeed on retry, so 200 stops the provider from retrying.
		return http.StatusOK
	}
}

func (s *WebhookServer) handleInbound(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, s.maxBody+1))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if int64(len(body)) > s.maxBody {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}

	// Forward only the provider signature headers the verifier needs; never
	// log header values (they authenticate the request).
	headers := map[string]string{
		"svix-id":        r.Header.Get("svix-id"),
		"svix-timestamp": r.Header.Get("svix-timestamp"),
		"svix-signature": r.Header.Get("svix-signature"),
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	res, err := s.relayer.Handle(ctx, headers, body)
	status := http.StatusOK
	if res.Delivered {
		s.logger.Info("demail inbound relayed", "tx", res.TxDigest)
	} else {
		status = dropStatus(res.Drop)
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "60")
		}
		// Log the reason only, never the payload/sender.
		s.logger.Warn("demail inbound dropped", "reason", string(res.Drop), "err_present", err != nil)
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, string(res.Drop))
}
