// Package gateway accepts PostgreSQL client connections and performs the
// protocol's startup exchange.
//
// What this package implements today is the startup exchange only: it declines
// encryption negotiation, parses the StartupMessage, and tells the client that
// no backend is attached. Lease resolution, authentication, rate limiting, and
// message relay are deliberately absent; the README records the order in which
// they are intended to land.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/chad3814/pg-lease-rate/internal/config"
	"github.com/chad3814/pg-lease-rate/internal/pgwire"
)

// ErrNotListening reports Serve called before a successful Listen.
var ErrNotListening = errors.New("gateway: Serve called before Listen")

// ErrShutdownTimeout reports in-flight connections that outlived the
// configured shutdown budget.
var ErrShutdownTimeout = errors.New("gateway: in-flight connections did not finish before the shutdown timeout")

// ErrTooManyNegotiations reports a client that kept sending encryption
// negotiation requests instead of a StartupMessage.
var ErrTooManyNegotiations = errors.New("gateway: too many encryption negotiation requests")

// ErrClientHungUp reports a client that closed the connection cleanly during
// the startup phase. Port probes, health checks and load balancers all do
// this, so it is ordinary traffic rather than a failure.
var ErrClientHungUp = errors.New("gateway: client closed the connection during startup")

// maxNegotiations is how many encryption requests the gateway will decline
// before it treats the client as misbehaving. A client sends at most one
// SSLRequest and one GSSENCRequest before its StartupMessage, so anything
// beyond that is a peer spinning us.
const maxNegotiations = 2

// Server is a Postgres-wire listener.
type Server struct {
	cfg    config.Config
	logger *slog.Logger

	ln net.Listener
	wg sync.WaitGroup
}

// New returns a Server that will bind the address in cfg.
func New(cfg config.Config, logger *slog.Logger) *Server {
	return &Server{cfg: cfg, logger: logger}
}

// Listen binds the configured address. Addr reports the result once it returns
// nil, which lets a caller discover the port when the configuration asks for
// an ephemeral one.
func (s *Server) Listen() error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("gateway: listen on %s: %w", s.cfg.ListenAddr, err)
	}
	s.ln = ln
	return nil
}

// Addr returns the bound address, or nil before Listen succeeds.
func (s *Server) Addr() net.Addr {
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Serve accepts connections until ctx is cancelled, then waits for in-flight
// connections to finish within the configured shutdown timeout.
func (s *Server) Serve(ctx context.Context) error {
	if s.ln == nil {
		return ErrNotListening
	}

	// Closing the listener is what unblocks Accept; there is no cancellable
	// form of it.
	go func() {
		<-ctx.Done()
		_ = s.ln.Close()
	}()

	s.logger.Info("gateway listening", "addr", s.ln.Addr().String())

	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return s.drain()
			}
			return fmt.Errorf("gateway: accept: %w", err)
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(conn)
		}()
	}
}

// ListenAndServe binds and then serves.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if err := s.Listen(); err != nil {
		return err
	}
	return s.Serve(ctx)
}

// drain waits for open connections, bounded by the shutdown timeout.
func (s *Server) drain() error {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("gateway shut down")
		return nil
	case <-time.After(s.cfg.ShutdownTimeout):
		return fmt.Errorf("%w: waited %s", ErrShutdownTimeout, s.cfg.ShutdownTimeout)
	}
}

// handle runs one client connection through the startup exchange.
func (s *Server) handle(conn net.Conn) {
	defer func() {
		_ = conn.Close()
	}()

	logger := s.logger.With("remote", conn.RemoteAddr().String())

	// One deadline covers the whole exchange. Nothing here is long-lived, so a
	// single budget is simpler than per-read deadlines and gives the same
	// protection.
	if err := conn.SetDeadline(time.Now().Add(s.cfg.StartupTimeout)); err != nil {
		logger.Error("set connection deadline", "error", err)
		return
	}

	r := pgwire.NewReader(conn, s.cfg.MaxMessageBytes)
	w := pgwire.NewWriter(conn)

	startup, err := s.negotiate(r, w, logger)
	if err != nil {
		// A peer that sent FIN cannot receive an ErrorResponse, and did
		// nothing wrong by leaving.
		if errors.Is(err, ErrClientHungUp) {
			logger.Debug("client closed during startup")
			return
		}
		logger.Warn("startup exchange failed", "error", err)
		s.reject(w, logger, pgwire.Error{
			Severity: pgwire.SeverityFatal,
			Code:     pgwire.SQLStateProtocolViolation,
			Message:  "could not complete the startup exchange",
			Detail:   err.Error(),
		})
		return
	}

	// A CancelRequest arrives on its own connection and is answered with
	// silence, whether or not the server acts on it.
	if startup.Kind == pgwire.StartupKindCancelRequest {
		logger.Info("cancel request ignored",
			"process_id", startup.ProcessID,
			"reason", "no backend sessions exist to cancel")
		return
	}

	if startup.Major != pgwire.ProtocolMajor3 {
		logger.Warn("unsupported protocol version", "major", startup.Major, "minor", startup.Minor)
		s.reject(w, logger, pgwire.Error{
			Severity: pgwire.SeverityFatal,
			Code:     pgwire.SQLStateFeatureNotSupported,
			Message:  fmt.Sprintf("unsupported frontend protocol %d.%d", startup.Major, startup.Minor),
			Hint:     fmt.Sprintf("this gateway speaks major version %d", pgwire.ProtocolMajor3),
		})
		return
	}

	logger.Info("startup message accepted",
		"user", startup.User(),
		"database", startup.Database(),
		"protocol", fmt.Sprintf("%d.%d", startup.Major, startup.Minor),
		"parameters", len(startup.Parameters))

	s.reject(w, logger, pgwire.Error{
		Severity: pgwire.SeverityFatal,
		Code:     pgwire.SQLStateFeatureNotSupported,
		Message:  "gateway has no backend attached",
		Detail: fmt.Sprintf("parsed a protocol %d.%d startup for user %q, database %q",
			startup.Major, startup.Minor, startup.User(), startup.Database()),
		Hint: "lease resolution and message relay are not implemented yet",
	})
}

// negotiate runs the untyped phase of the exchange and returns the first
// message that is not an encryption request.
//
// Declining encryption is a single unframed byte, after which the client
// continues in cleartext on the same connection and sends its StartupMessage.
func (s *Server) negotiate(r *pgwire.Reader, w *pgwire.Writer, logger *slog.Logger) (pgwire.Startup, error) {
	declined := 0
	for {
		msg, err := r.ReadUntyped()
		if err != nil {
			// A clean EOF means the peer closed gracefully. A truncated
			// message is io.ErrUnexpectedEOF instead, and is a real fault.
			if errors.Is(err, io.EOF) {
				return pgwire.Startup{}, ErrClientHungUp
			}
			return pgwire.Startup{}, fmt.Errorf("read startup message: %w", err)
		}

		startup, err := pgwire.ParseStartup(msg.Body)
		if err != nil {
			return pgwire.Startup{}, err
		}

		switch startup.Kind {
		case pgwire.StartupKindSSLRequest, pgwire.StartupKindGSSEncRequest:
			// Refuse without replying once the budget is spent, so a client
			// never receives more denial bytes than it has requests
			// outstanding.
			if declined >= maxNegotiations {
				return pgwire.Startup{}, fmt.Errorf("%w: declined %d already", ErrTooManyNegotiations, declined)
			}
			declined++

			logger.Debug("declining encryption negotiation", "kind", startup.Kind.String())
			if err := w.WriteRawByte(pgwire.SSLDenied); err != nil {
				return pgwire.Startup{}, fmt.Errorf("decline %s: %w", startup.Kind, err)
			}
			if err := w.Flush(); err != nil {
				return pgwire.Startup{}, fmt.Errorf("decline %s: %w", startup.Kind, err)
			}
		default:
			return startup, nil
		}
	}
}

// reject sends a final ErrorResponse. The caller closes the connection, which
// is the correct end to a FATAL error.
func (s *Server) reject(w *pgwire.Writer, logger *slog.Logger, e pgwire.Error) {
	if err := w.WriteError(e); err != nil {
		logger.Error("write error response", "error", err)
		return
	}
	if err := w.Flush(); err != nil {
		logger.Error("flush error response", "error", err)
	}
}
