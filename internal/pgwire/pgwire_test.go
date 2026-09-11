package pgwire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"maps"
	"testing"
)

// typed builds the wire encoding of a typed message.
func typed(typ byte, body []byte) []byte {
	b := []byte{typ}
	b = binary.BigEndian.AppendUint32(b, uint32(headerSize+len(body)))
	return append(b, body...)
}

// untyped builds the wire encoding of a startup-phase message.
func untyped(body []byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(headerSize+len(body)))
	return append(b, body...)
}

// startupBody builds a StartupMessage body from a version code and an
// alternating sequence of parameter keys and values.
func startupBody(version int32, kv ...string) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(version))
	for _, s := range kv {
		b = append(b, s...)
		b = append(b, 0)
	}
	return append(b, 0)
}

func TestReaderReadTyped(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		max      int
		wantType byte
		wantBody []byte
		wantErr  error
	}{
		{
			name:     "query with body",
			input:    typed(FrontendQuery, []byte("SELECT 1\x00")),
			wantType: FrontendQuery,
			wantBody: []byte("SELECT 1\x00"),
		},
		{
			name:     "empty body",
			input:    typed(FrontendSync, nil),
			wantType: FrontendSync,
			wantBody: nil,
		},
		{
			name:    "length below minimum",
			input:   []byte{FrontendQuery, 0x00, 0x00, 0x00, 0x03},
			wantErr: ErrInvalidLength,
		},
		{
			name:    "negative length",
			input:   []byte{FrontendQuery, 0xFF, 0xFF, 0xFF, 0xFF},
			wantErr: ErrInvalidLength,
		},
		{
			name:    "body exceeds limit",
			input:   typed(FrontendQuery, bytes.Repeat([]byte("x"), 32)),
			max:     8,
			wantErr: ErrMessageTooLarge,
		},
		{
			name:    "truncated body",
			input:   append(typed(FrontendQuery, []byte("SELECT 1"))[:5], 'S'),
			wantErr: io.ErrUnexpectedEOF,
		},
		{
			name:    "empty stream",
			input:   nil,
			wantErr: io.EOF,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewReader(bytes.NewReader(tc.input), tc.max)
			msg, err := r.ReadTyped()
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ReadTyped() error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadTyped() unexpected error: %v", err)
			}
			if msg.Type != tc.wantType {
				t.Errorf("Type = %q, want %q", msg.Type, tc.wantType)
			}
			if !bytes.Equal(msg.Body, tc.wantBody) {
				t.Errorf("Body = %q, want %q", msg.Body, tc.wantBody)
			}
		})
	}
}

func TestReaderReadUntyped(t *testing.T) {
	body := startupBody(ProtocolMajor3<<16, "user", "chad")
	r := NewReader(bytes.NewReader(untyped(body)), 0)

	msg, err := r.ReadUntyped()
	if err != nil {
		t.Fatalf("ReadUntyped() unexpected error: %v", err)
	}
	if msg.Type != 0 {
		t.Errorf("Type = %q, want 0 for an untyped message", msg.Type)
	}
	if !bytes.Equal(msg.Body, body) {
		t.Errorf("Body = %q, want %q", msg.Body, body)
	}
}

func TestReaderSequentialMessages(t *testing.T) {
	var stream bytes.Buffer
	stream.Write(typed(FrontendQuery, []byte("SELECT 1\x00")))
	stream.Write(typed(FrontendSync, nil))
	stream.Write(typed(FrontendTerminate, nil))

	r := NewReader(&stream, 0)
	want := []byte{FrontendQuery, FrontendSync, FrontendTerminate}
	for i, wantType := range want {
		msg, err := r.ReadTyped()
		if err != nil {
			t.Fatalf("message %d: unexpected error: %v", i, err)
		}
		if msg.Type != wantType {
			t.Errorf("message %d: Type = %q, want %q", i, msg.Type, wantType)
		}
	}
	if _, err := r.ReadTyped(); !errors.Is(err, io.EOF) {
		t.Errorf("after last message: error = %v, want io.EOF", err)
	}
}

func TestWriterRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	if err := w.WriteRawByte(SSLDenied); err != nil {
		t.Fatalf("WriteRawByte() unexpected error: %v", err)
	}
	if err := w.WriteTyped(BackendReadyForQuery, []byte{'I'}); err != nil {
		t.Fatalf("WriteTyped() unexpected error: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatal("writes reached the stream before Flush")
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush() unexpected error: %v", err)
	}

	if got := buf.Next(1); !bytes.Equal(got, []byte{SSLDenied}) {
		t.Fatalf("first byte = %q, want %q", got, SSLDenied)
	}
	msg, err := NewReader(&buf, 0).ReadTyped()
	if err != nil {
		t.Fatalf("reading back: unexpected error: %v", err)
	}
	if msg.Type != BackendReadyForQuery {
		t.Errorf("Type = %q, want %q", msg.Type, BackendReadyForQuery)
	}
	if !bytes.Equal(msg.Body, []byte{'I'}) {
		t.Errorf("Body = %q, want %q", msg.Body, []byte{'I'})
	}
}

func TestParseStartup(t *testing.T) {
	tests := []struct {
		name    string
		body    []byte
		want    Startup
		wantErr error
	}{
		{
			name: "protocol 3.0 with parameters",
			body: startupBody(ProtocolMajor3<<16, "user", "chad", "database", "lease_abc123"),
			want: Startup{
				Kind:       StartupKindStartup,
				Major:      3,
				Minor:      0,
				Parameters: map[string]string{"user": "chad", "database": "lease_abc123"},
			},
		},
		{
			name: "protocol 3.2 is accepted and reported",
			body: startupBody(ProtocolMajor3<<16|2, "user", "chad"),
			want: Startup{
				Kind:       StartupKindStartup,
				Major:      3,
				Minor:      2,
				Parameters: map[string]string{"user": "chad"},
			},
		},
		{
			name: "no parameters",
			body: startupBody(ProtocolMajor3 << 16),
			want: Startup{
				Kind:       StartupKindStartup,
				Major:      3,
				Parameters: map[string]string{},
			},
		},
		{
			name: "ssl request",
			body: binary.BigEndian.AppendUint32(nil, uint32(sslRequestCode)),
			want: Startup{Kind: StartupKindSSLRequest},
		},
		{
			name: "gssenc request",
			body: binary.BigEndian.AppendUint32(nil, uint32(gssEncRequestCode)),
			want: Startup{Kind: StartupKindGSSEncRequest},
		},
		{
			name: "cancel request",
			body: func() []byte {
				b := binary.BigEndian.AppendUint32(nil, uint32(cancelRequestCode))
				b = binary.BigEndian.AppendUint32(b, 4242)
				return binary.BigEndian.AppendUint32(b, 9001)
			}(),
			want: Startup{Kind: StartupKindCancelRequest, ProcessID: 4242, SecretKey: 9001},
		},
		{
			name:    "body too short for a version code",
			body:    []byte{0x00, 0x03, 0x00},
			wantErr: ErrMalformed,
		},
		{
			name:    "ssl request with trailing bytes",
			body:    append(binary.BigEndian.AppendUint32(nil, uint32(sslRequestCode)), 'x'),
			wantErr: ErrMalformed,
		},
		{
			name:    "cancel request with wrong length",
			body:    binary.BigEndian.AppendUint32(nil, uint32(cancelRequestCode)),
			wantErr: ErrMalformed,
		},
		{
			name:    "unterminated parameter list",
			body:    append(binary.BigEndian.AppendUint32(nil, ProtocolMajor3<<16), []byte("user\x00chad\x00")...),
			wantErr: ErrMalformed,
		},
		{
			name:    "unterminated string",
			body:    append(binary.BigEndian.AppendUint32(nil, ProtocolMajor3<<16), []byte("user")...),
			wantErr: ErrMalformed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseStartup(tc.body)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ParseStartup() error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseStartup() unexpected error: %v", err)
			}
			if got.Kind != tc.want.Kind {
				t.Errorf("Kind = %v, want %v", got.Kind, tc.want.Kind)
			}
			if got.Major != tc.want.Major || got.Minor != tc.want.Minor {
				t.Errorf("version = %d.%d, want %d.%d", got.Major, got.Minor, tc.want.Major, tc.want.Minor)
			}
			if !maps.Equal(got.Parameters, tc.want.Parameters) {
				t.Errorf("Parameters = %v, want %v", got.Parameters, tc.want.Parameters)
			}
			if got.ProcessID != tc.want.ProcessID || got.SecretKey != tc.want.SecretKey {
				t.Errorf("cancel key = (%d, %d), want (%d, %d)",
					got.ProcessID, got.SecretKey, tc.want.ProcessID, tc.want.SecretKey)
			}
		})
	}
}

func TestStartupAccessors(t *testing.T) {
	tests := []struct {
		name         string
		params       map[string]string
		wantUser     string
		wantDatabase string
	}{
		{
			name:         "explicit database",
			params:       map[string]string{"user": "chad", "database": "lease_abc123"},
			wantUser:     "chad",
			wantDatabase: "lease_abc123",
		},
		{
			name:         "database defaults to user",
			params:       map[string]string{"user": "chad"},
			wantUser:     "chad",
			wantDatabase: "chad",
		},
		{
			name:         "empty database defaults to user",
			params:       map[string]string{"user": "chad", "database": ""},
			wantUser:     "chad",
			wantDatabase: "chad",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := Startup{Kind: StartupKindStartup, Parameters: tc.params}
			if got := s.User(); got != tc.wantUser {
				t.Errorf("User() = %q, want %q", got, tc.wantUser)
			}
			if got := s.Database(); got != tc.wantDatabase {
				t.Errorf("Database() = %q, want %q", got, tc.wantDatabase)
			}
		})
	}
}

func TestStartupKindString(t *testing.T) {
	tests := []struct {
		kind StartupKind
		want string
	}{
		{StartupKindStartup, "startup"},
		{StartupKindSSLRequest, "ssl_request"},
		{StartupKindGSSEncRequest, "gssenc_request"},
		{StartupKindCancelRequest, "cancel_request"},
		{StartupKind(99), "unknown(99)"},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := tc.kind.String(); got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestErrorRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   Error
		want Error
	}{
		{
			name: "all fields",
			in: Error{
				Severity: SeverityFatal,
				Code:     SQLStateConfigurationLimitExceeded,
				Message:  "rate limit exceeded",
				Detail:   "lease lease_abc123 exhausted its query budget",
				Hint:     "retry after the current window closes",
			},
			want: Error{
				Severity: SeverityFatal,
				Code:     SQLStateConfigurationLimitExceeded,
				Message:  "rate limit exceeded",
				Detail:   "lease lease_abc123 exhausted its query budget",
				Hint:     "retry after the current window closes",
			},
		},
		{
			name: "defaults applied for severity and code",
			in:   Error{Message: "something went wrong"},
			want: Error{
				Severity: SeverityError,
				Code:     SQLStateInternalError,
				Message:  "something went wrong",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseError(tc.in.Encode())
			if err != nil {
				t.Fatalf("ParseError() unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("round trip = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestParseErrorUnterminated(t *testing.T) {
	if _, err := ParseError([]byte{'M', 'o', 'o', 'p', 0}); !errors.Is(err, ErrMalformed) {
		t.Errorf("ParseError() error = %v, want %v", err, ErrMalformed)
	}
}

func TestWriteError(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	want := Error{Severity: SeverityFatal, Code: SQLStateFeatureNotSupported, Message: "nope"}

	if err := w.WriteError(want); err != nil {
		t.Fatalf("WriteError() unexpected error: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush() unexpected error: %v", err)
	}

	msg, err := NewReader(&buf, 0).ReadTyped()
	if err != nil {
		t.Fatalf("ReadTyped() unexpected error: %v", err)
	}
	if msg.Type != BackendErrorResponse {
		t.Fatalf("Type = %q, want %q", msg.Type, BackendErrorResponse)
	}
	got, err := ParseError(msg.Body)
	if err != nil {
		t.Fatalf("ParseError() unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("decoded = %+v, want %+v", got, want)
	}
}
