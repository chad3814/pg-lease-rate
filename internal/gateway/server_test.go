package gateway

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/chad3814/pg-lease-rate/internal/config"
	"github.com/chad3814/pg-lease-rate/internal/pgwire"
)

// Wire constants are repeated here rather than imported so that the tests
// assert the protocol's values independently of the values the gateway uses.
const (
	wireSSLRequest    = 80877103
	wireGSSEncRequest = 80877104
	wireCancelRequest = 80877102
	wireProtocol30    = 3 << 16
)

// newTestServer starts a Server on an ephemeral loopback port and registers
// cleanup that shuts it down and asserts a clean exit.
func newTestServer(t *testing.T) *Server {
	t.Helper()

	cfg := config.Default()
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.StartupTimeout = 5 * time.Second
	cfg.ShutdownTimeout = 5 * time.Second

	srv := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen() unexpected error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx) }()

	t.Cleanup(func() {
		cancel()
		if err := <-served; err != nil {
			t.Errorf("Serve() = %v, want nil after cancellation", err)
		}
	})

	return srv
}

// dial opens a client connection to srv with a deadline that keeps a protocol
// mistake from hanging the suite.
func dial(t *testing.T, srv *Server) net.Conn {
	t.Helper()

	conn, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatalf("Dial() unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() unexpected error: %v", err)
	}
	return conn
}

// writeUntyped frames body as a startup-phase message and sends it.
func writeUntyped(t *testing.T, conn net.Conn, body []byte) {
	t.Helper()

	buf := binary.BigEndian.AppendUint32(nil, uint32(4+len(body)))
	if _, err := conn.Write(append(buf, body...)); err != nil {
		t.Fatalf("writing untyped message: %v", err)
	}
}

// negotiationBody builds one of the fixed-size requests that carry a magic
// code where a version would be.
func negotiationBody(code uint32) []byte {
	return binary.BigEndian.AppendUint32(nil, code)
}

// startupBody builds a StartupMessage body from a version code and alternating
// parameter keys and values.
func startupBody(version uint32, kv ...string) []byte {
	b := binary.BigEndian.AppendUint32(nil, version)
	for _, s := range kv {
		b = append(b, s...)
		b = append(b, 0)
	}
	return append(b, 0)
}

// readDenial consumes the single unframed byte that declines encryption. It
// reads straight from the connection so that no buffering hides later bytes.
func readDenial(t *testing.T, conn net.Conn) byte {
	t.Helper()

	var b [1]byte
	if _, err := io.ReadFull(conn, b[:]); err != nil {
		t.Fatalf("reading negotiation reply: %v", err)
	}
	return b[0]
}

// readErrorResponse reads one framed message and decodes it as an
// ErrorResponse.
func readErrorResponse(t *testing.T, r *pgwire.Reader) pgwire.Error {
	t.Helper()

	msg, err := r.ReadTyped()
	if err != nil {
		t.Fatalf("reading server reply: %v", err)
	}
	if msg.Type != pgwire.BackendErrorResponse {
		t.Fatalf("reply type = %q, want %q (ErrorResponse)", msg.Type, pgwire.BackendErrorResponse)
	}
	e, err := pgwire.ParseError(msg.Body)
	if err != nil {
		t.Fatalf("ParseError() unexpected error: %v", err)
	}
	return e
}

// assertClosed checks that the server hung up after its final message.
func assertClosed(t *testing.T, conn net.Conn) {
	t.Helper()

	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("connection still readable, want it closed after a FATAL error")
	}
}

func TestServerRejectsStartupWithNoBackend(t *testing.T) {
	srv := newTestServer(t)
	conn := dial(t, srv)

	writeUntyped(t, conn, startupBody(wireProtocol30, "user", "chad", "database", "lease_abc123"))

	got := readErrorResponse(t, pgwire.NewReader(conn, 0))
	if got.Severity != pgwire.SeverityFatal {
		t.Errorf("Severity = %q, want %q", got.Severity, pgwire.SeverityFatal)
	}
	if got.Code != pgwire.SQLStateFeatureNotSupported {
		t.Errorf("Code = %q, want %q", got.Code, pgwire.SQLStateFeatureNotSupported)
	}
	if got.Message != "gateway has no backend attached" {
		t.Errorf("Message = %q, want %q", got.Message, "gateway has no backend attached")
	}
	if !strings.Contains(got.Detail, `user "chad"`) {
		t.Errorf("Detail = %q, want it to name the user", got.Detail)
	}
	if !strings.Contains(got.Detail, `database "lease_abc123"`) {
		t.Errorf("Detail = %q, want it to name the database", got.Detail)
	}
	assertClosed(t, conn)
}

func TestServerDeclinesEncryptionThenReadsStartup(t *testing.T) {
	tests := []struct {
		name string
		code uint32
	}{
		{name: "ssl request", code: wireSSLRequest},
		{name: "gssenc request", code: wireGSSEncRequest},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t)
			conn := dial(t, srv)

			writeUntyped(t, conn, negotiationBody(tc.code))
			if got := readDenial(t, conn); got != pgwire.SSLDenied {
				t.Fatalf("negotiation reply = %q, want %q", got, pgwire.SSLDenied)
			}

			writeUntyped(t, conn, startupBody(wireProtocol30, "user", "chad"))

			got := readErrorResponse(t, pgwire.NewReader(conn, 0))
			if got.Code != pgwire.SQLStateFeatureNotSupported {
				t.Errorf("Code = %q, want %q", got.Code, pgwire.SQLStateFeatureNotSupported)
			}
			if got.Message != "gateway has no backend attached" {
				t.Errorf("Message = %q, want the no-backend message", got.Message)
			}
			assertClosed(t, conn)
		})
	}
}

func TestServerDeclinesBothNegotiationsInSequence(t *testing.T) {
	srv := newTestServer(t)
	conn := dial(t, srv)

	for _, code := range []uint32{wireSSLRequest, wireGSSEncRequest} {
		writeUntyped(t, conn, negotiationBody(code))
		if got := readDenial(t, conn); got != pgwire.SSLDenied {
			t.Fatalf("negotiation reply = %q, want %q", got, pgwire.SSLDenied)
		}
	}

	writeUntyped(t, conn, startupBody(wireProtocol30, "user", "chad"))
	if got := readErrorResponse(t, pgwire.NewReader(conn, 0)); got.Message != "gateway has no backend attached" {
		t.Errorf("Message = %q, want the no-backend message", got.Message)
	}
}

func TestServerRejectsTooManyNegotiations(t *testing.T) {
	srv := newTestServer(t)
	conn := dial(t, srv)

	// One more than the gateway tolerates.
	for range maxNegotiations {
		writeUntyped(t, conn, negotiationBody(wireSSLRequest))
		if got := readDenial(t, conn); got != pgwire.SSLDenied {
			t.Fatalf("negotiation reply = %q, want %q", got, pgwire.SSLDenied)
		}
	}
	writeUntyped(t, conn, negotiationBody(wireSSLRequest))

	got := readErrorResponse(t, pgwire.NewReader(conn, 0))
	if got.Code != pgwire.SQLStateProtocolViolation {
		t.Errorf("Code = %q, want %q", got.Code, pgwire.SQLStateProtocolViolation)
	}
	if !strings.Contains(got.Detail, "negotiation") {
		t.Errorf("Detail = %q, want it to mention negotiation", got.Detail)
	}
	assertClosed(t, conn)
}

func TestServerRejectsUnsupportedProtocolVersion(t *testing.T) {
	srv := newTestServer(t)
	conn := dial(t, srv)

	writeUntyped(t, conn, startupBody(2<<16, "user", "chad"))

	got := readErrorResponse(t, pgwire.NewReader(conn, 0))
	if got.Code != pgwire.SQLStateFeatureNotSupported {
		t.Errorf("Code = %q, want %q", got.Code, pgwire.SQLStateFeatureNotSupported)
	}
	if !strings.Contains(got.Message, "2.0") {
		t.Errorf("Message = %q, want it to name the rejected version", got.Message)
	}
	assertClosed(t, conn)
}

func TestServerAcceptsMinorProtocolVersion(t *testing.T) {
	srv := newTestServer(t)
	conn := dial(t, srv)

	// Postgres 18 clients may ask for 3.2. A newer minor version within major
	// 3 must not be refused outright.
	writeUntyped(t, conn, startupBody(3<<16|2, "user", "chad"))

	got := readErrorResponse(t, pgwire.NewReader(conn, 0))
	if got.Message != "gateway has no backend attached" {
		t.Errorf("Message = %q, want the startup to have been accepted", got.Message)
	}
	if !strings.Contains(got.Detail, "3.2") {
		t.Errorf("Detail = %q, want it to report protocol 3.2", got.Detail)
	}
}

func TestServerRejectsMalformedStartup(t *testing.T) {
	srv := newTestServer(t)
	conn := dial(t, srv)

	// A version code with a parameter list that is never terminated.
	writeUntyped(t, conn, append(binary.BigEndian.AppendUint32(nil, wireProtocol30), []byte("user\x00chad\x00")...))

	got := readErrorResponse(t, pgwire.NewReader(conn, 0))
	if got.Code != pgwire.SQLStateProtocolViolation {
		t.Errorf("Code = %q, want %q", got.Code, pgwire.SQLStateProtocolViolation)
	}
	assertClosed(t, conn)
}

func TestServerIgnoresCancelRequest(t *testing.T) {
	srv := newTestServer(t)
	conn := dial(t, srv)

	body := binary.BigEndian.AppendUint32(nil, wireCancelRequest)
	body = binary.BigEndian.AppendUint32(body, 4242)
	body = binary.BigEndian.AppendUint32(body, 9001)
	writeUntyped(t, conn, body)

	// The protocol answers a cancel request with silence, so the only thing to
	// observe is the close.
	if n, err := conn.Read(make([]byte, 1)); err == nil {
		t.Errorf("read %d bytes, want the connection closed with no reply", n)
	}
}

func TestServerRejectsOversizeMessage(t *testing.T) {
	srv := newTestServer(t)
	conn := dial(t, srv)

	// Claim a body far past the configured cap without sending it. The gateway
	// must refuse on the length prefix alone rather than try to buffer it.
	if _, err := conn.Write(binary.BigEndian.AppendUint32(nil, 1<<30)); err != nil {
		t.Fatalf("writing length prefix: %v", err)
	}

	got := readErrorResponse(t, pgwire.NewReader(conn, 0))
	if got.Code != pgwire.SQLStateProtocolViolation {
		t.Errorf("Code = %q, want %q", got.Code, pgwire.SQLStateProtocolViolation)
	}
	if !strings.Contains(got.Detail, "too large") {
		t.Errorf("Detail = %q, want it to report the size refusal", got.Detail)
	}
}

func TestServerToleratesClientHangUp(t *testing.T) {
	srv := newTestServer(t)

	// A port probe: connect and leave without sending anything. This must not
	// disturb the listener.
	probe, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatalf("Dial() unexpected error: %v", err)
	}
	if err := probe.Close(); err != nil {
		t.Fatalf("Close() unexpected error: %v", err)
	}

	// A real client afterwards still completes the startup exchange.
	conn := dial(t, srv)
	writeUntyped(t, conn, startupBody(wireProtocol30, "user", "chad"))
	if got := readErrorResponse(t, pgwire.NewReader(conn, 0)); got.Message != "gateway has no backend attached" {
		t.Errorf("Message = %q, want the no-backend message", got.Message)
	}
}

func TestServerToleratesHangUpAfterNegotiation(t *testing.T) {
	srv := newTestServer(t)

	// Some clients probe for TLS and then give up rather than continuing in
	// cleartext.
	conn, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatalf("Dial() unexpected error: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() unexpected error: %v", err)
	}
	writeUntyped(t, conn, negotiationBody(wireSSLRequest))
	if got := readDenial(t, conn); got != pgwire.SSLDenied {
		t.Fatalf("negotiation reply = %q, want %q", got, pgwire.SSLDenied)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close() unexpected error: %v", err)
	}

	next := dial(t, srv)
	writeUntyped(t, next, startupBody(wireProtocol30, "user", "chad"))
	if got := readErrorResponse(t, pgwire.NewReader(next, 0)); got.Message != "gateway has no backend attached" {
		t.Errorf("Message = %q, want the no-backend message", got.Message)
	}
}

func TestServeBeforeListen(t *testing.T) {
	srv := New(config.Default(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := srv.Serve(context.Background()); !errors.Is(err, ErrNotListening) {
		t.Errorf("Serve() = %v, want %v", err, ErrNotListening)
	}
}

func TestAddrBeforeListen(t *testing.T) {
	srv := New(config.Default(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if got := srv.Addr(); got != nil {
		t.Errorf("Addr() = %v, want nil before Listen", got)
	}
}
