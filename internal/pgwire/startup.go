package pgwire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// Magic values that appear where a protocol version would, distinguishing the
// three fixed-size requests from a real StartupMessage. They are deliberately
// outside the range of any plausible version number.
const (
	sslRequestCode    int32 = 80877103
	gssEncRequestCode int32 = 80877104
	cancelRequestCode int32 = 80877102
)

// ProtocolMajor3 is the only major protocol version this gateway speaks. Minor
// versions within it are backward compatible: a server that does not
// understand a requested minor version replies with NegotiateProtocolVersion
// and proceeds at the version it does support.
const ProtocolMajor3 = 3

// ErrMalformed reports a message that does not parse.
var ErrMalformed = errors.New("pgwire: malformed message")

// StartupKind identifies which of the four untyped first messages a client
// sent.
type StartupKind int

const (
	// StartupKindStartup is a StartupMessage carrying a protocol version and
	// connection parameters.
	StartupKindStartup StartupKind = iota
	// StartupKindSSLRequest asks whether the server will negotiate TLS.
	StartupKindSSLRequest
	// StartupKindGSSEncRequest asks whether the server will negotiate GSSAPI
	// encryption.
	StartupKindGSSEncRequest
	// StartupKindCancelRequest asks the server to cancel a query running on
	// another connection. It is sent on its own connection and receives no
	// reply.
	StartupKindCancelRequest
)

// String implements fmt.Stringer.
func (k StartupKind) String() string {
	switch k {
	case StartupKindStartup:
		return "startup"
	case StartupKindSSLRequest:
		return "ssl_request"
	case StartupKindGSSEncRequest:
		return "gssenc_request"
	case StartupKindCancelRequest:
		return "cancel_request"
	default:
		return fmt.Sprintf("unknown(%d)", int(k))
	}
}

// Startup is a parsed untyped first message. Which fields carry meaning
// depends on Kind.
type Startup struct {
	// Kind discriminates the four forms.
	Kind StartupKind

	// Major and Minor are the requested protocol version. Set only when Kind
	// is StartupKindStartup.
	Major int
	Minor int

	// Parameters are the startup key/value pairs. Set only when Kind is
	// StartupKindStartup. The protocol requires "user"; "database" is
	// conventional and defaults to the user name when absent.
	Parameters map[string]string

	// ProcessID and SecretKey identify the connection to cancel. Set only
	// when Kind is StartupKindCancelRequest.
	ProcessID int32
	SecretKey int32
}

// User returns the "user" startup parameter.
func (s Startup) User() string {
	return s.Parameters["user"]
}

// Database returns the "database" startup parameter, defaulting to the user
// name as the server does when the parameter is absent.
func (s Startup) Database() string {
	if db, ok := s.Parameters["database"]; ok && db != "" {
		return db
	}
	return s.Parameters["user"]
}

// ParseStartup interprets the body of an untyped first message.
//
// Bytes after the parameter list's terminator are ignored, matching the
// server's own tolerance.
func ParseStartup(body []byte) (Startup, error) {
	if len(body) < 4 {
		return Startup{}, fmt.Errorf("%w: body is %d bytes, need at least 4", ErrMalformed, len(body))
	}
	code := int32(binary.BigEndian.Uint32(body[:4]))

	switch code {
	case sslRequestCode, gssEncRequestCode:
		if len(body) != 4 {
			return Startup{}, fmt.Errorf("%w: negotiation request carries %d trailing bytes", ErrMalformed, len(body)-4)
		}
		kind := StartupKindSSLRequest
		if code == gssEncRequestCode {
			kind = StartupKindGSSEncRequest
		}
		return Startup{Kind: kind}, nil

	case cancelRequestCode:
		if len(body) != 12 {
			return Startup{}, fmt.Errorf("%w: cancel request body is %d bytes, want 12", ErrMalformed, len(body))
		}
		return Startup{
			Kind:      StartupKindCancelRequest,
			ProcessID: int32(binary.BigEndian.Uint32(body[4:8])),
			SecretKey: int32(binary.BigEndian.Uint32(body[8:12])),
		}, nil
	}

	params, err := parseParameters(body[4:])
	if err != nil {
		return Startup{}, err
	}
	return Startup{
		Kind:       StartupKindStartup,
		Major:      int(code >> 16),
		Minor:      int(code & 0xFFFF),
		Parameters: params,
	}, nil
}

// parseParameters reads null-terminated key/value string pairs terminated by an
// empty key.
func parseParameters(b []byte) (map[string]string, error) {
	params := make(map[string]string)
	for {
		if len(b) == 0 {
			return nil, fmt.Errorf("%w: parameter list is not terminated", ErrMalformed)
		}
		if b[0] == 0 {
			return params, nil
		}
		key, n, err := readCString(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		value, n, err := readCString(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		params[key] = value
	}
}

// readCString reads a null-terminated string, returning it and the number of
// bytes consumed including the terminator.
func readCString(b []byte) (string, int, error) {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return "", 0, fmt.Errorf("%w: unterminated string", ErrMalformed)
	}
	return string(b[:i]), i + 1, nil
}
