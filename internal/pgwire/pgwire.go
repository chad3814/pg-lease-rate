// Package pgwire implements framing for version 3 of the PostgreSQL
// frontend/backend protocol.
//
// Every message after the startup exchange is framed identically: a single
// type byte, a big-endian int32 length, then a body. The length counts its own
// four bytes but not the type byte, so a body is length-4 bytes long.
//
// The first message a client sends is untyped: it carries a length and body but
// no type byte. That message is either a StartupMessage or one of three
// fixed-size requests distinguished by a magic version code (TLS negotiation,
// GSSAPI encryption negotiation, or query cancellation). See ParseStartup.
//
// Several type bytes are reused across directions and mean different things
// depending on who sent them: 'E' is Execute from a client and ErrorResponse
// from a server, 'S' is Sync or ParameterStatus, 'D' is Describe or DataRow,
// and 'C' is Close or CommandComplete. Callers must interpret a message's type
// in the context of its direction. This package frames bytes; it does not
// decide what they mean.
package pgwire

// DefaultMaxMessageBytes caps the body of a single message. The protocol
// permits bodies up to 1GB, but a gateway that relays rather than materializes
// result sets has no reason to buffer that much.
const DefaultMaxMessageBytes = 16 << 20

// headerSize is the width of the big-endian int32 length prefix.
const headerSize = 4

// Frontend message types, sent by a client to a server.
const (
	FrontendBind         byte = 'B'
	FrontendClose        byte = 'C'
	FrontendCopyData     byte = 'd'
	FrontendCopyDone     byte = 'c'
	FrontendCopyFail     byte = 'f'
	FrontendDescribe     byte = 'D'
	FrontendExecute      byte = 'E'
	FrontendFlush        byte = 'H'
	FrontendFunctionCall byte = 'F'
	FrontendParse        byte = 'P'
	FrontendPassword     byte = 'p'
	FrontendQuery        byte = 'Q'
	FrontendSync         byte = 'S'
	FrontendTerminate    byte = 'X'
)

// Backend message types, sent by a server to a client.
const (
	BackendAuthentication  byte = 'R'
	BackendBackendKeyData  byte = 'K'
	BackendCommandComplete byte = 'C'
	BackendDataRow         byte = 'D'
	BackendErrorResponse   byte = 'E'
	BackendNoticeResponse  byte = 'N'
	BackendParameterStatus byte = 'S'
	BackendReadyForQuery   byte = 'Z'
	BackendRowDescription  byte = 'T'
)

// Message is a single framed protocol message. Type is zero for the untyped
// messages of the startup phase.
type Message struct {
	Type byte
	Body []byte
}
