package pgwire

import (
	"bytes"
	"fmt"
)

// SQLSTATE codes this gateway emits. The full set is defined by the SQL
// standard and extended by PostgreSQL; these are the conditions a connection
// broker can actually report.
const (
	// SQLStateFeatureNotSupported reports a protocol feature the gateway
	// declines to implement.
	SQLStateFeatureNotSupported = "0A000"
	// SQLStateProtocolViolation reports a message the gateway could not parse.
	SQLStateProtocolViolation = "08P01"
	// SQLStateConfigurationLimitExceeded reports an exhausted quota, which is
	// the condition a rate limiter raises.
	SQLStateConfigurationLimitExceeded = "53400"
	// SQLStateInternalError reports a fault inside the gateway.
	SQLStateInternalError = "XX000"
)

// Severity values for the 'S' and 'V' fields of an ErrorResponse. FATAL tells
// the client the connection is over, which is what a rejected startup means.
const (
	SeverityError = "ERROR"
	SeverityFatal = "FATAL"
)

// Field type tags within an ErrorResponse body.
const (
	fieldSeverityLocalized byte = 'S'
	fieldSeverity          byte = 'V'
	fieldCode              byte = 'C'
	fieldMessage           byte = 'M'
	fieldDetail            byte = 'D'
	fieldHint              byte = 'H'
)

// Error is a backend ErrorResponse. A client such as psql renders it as a
// normal server error, so a gateway that speaks this correctly is transparent
// to existing tooling.
type Error struct {
	// Severity defaults to SeverityError when empty.
	Severity string
	// Code is a five-character SQLSTATE, defaulting to
	// SQLStateInternalError when empty.
	Code string
	// Message is the primary human-readable text, required by the protocol.
	Message string
	// Detail is optional secondary text.
	Detail string
	// Hint is optional remediation advice.
	Hint string
}

// Error implements the error interface.
func (e Error) Error() string {
	return fmt.Sprintf("%s %s: %s", e.severityOrDefault(), e.codeOrDefault(), e.Message)
}

func (e Error) severityOrDefault() string {
	if e.Severity == "" {
		return SeverityError
	}
	return e.Severity
}

func (e Error) codeOrDefault() string {
	if e.Code == "" {
		return SQLStateInternalError
	}
	return e.Code
}

// Encode returns the ErrorResponse body: tagged null-terminated strings
// followed by a zero byte that ends the field list.
func (e Error) Encode() []byte {
	var buf bytes.Buffer
	writeField(&buf, fieldSeverityLocalized, e.severityOrDefault())
	writeField(&buf, fieldSeverity, e.severityOrDefault())
	writeField(&buf, fieldCode, e.codeOrDefault())
	writeField(&buf, fieldMessage, e.Message)
	if e.Detail != "" {
		writeField(&buf, fieldDetail, e.Detail)
	}
	if e.Hint != "" {
		writeField(&buf, fieldHint, e.Hint)
	}
	buf.WriteByte(0)
	return buf.Bytes()
}

func writeField(buf *bytes.Buffer, tag byte, value string) {
	buf.WriteByte(tag)
	buf.WriteString(value)
	buf.WriteByte(0)
}

// ParseError decodes an ErrorResponse body. Unrecognized field tags are
// skipped, since the protocol reserves the right to add them.
func ParseError(body []byte) (Error, error) {
	var e Error
	for {
		if len(body) == 0 {
			return Error{}, fmt.Errorf("%w: error fields are not terminated", ErrMalformed)
		}
		if body[0] == 0 {
			return e, nil
		}
		tag := body[0]
		value, n, err := readCString(body[1:])
		if err != nil {
			return Error{}, err
		}
		body = body[1+n:]
		switch tag {
		case fieldSeverity:
			e.Severity = value
		case fieldCode:
			e.Code = value
		case fieldMessage:
			e.Message = value
		case fieldDetail:
			e.Detail = value
		case fieldHint:
			e.Hint = value
		}
	}
}

// WriteError frames e as an ErrorResponse and writes it.
func (w *Writer) WriteError(e Error) error {
	return w.WriteTyped(BackendErrorResponse, e.Encode())
}
