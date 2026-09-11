package pgwire

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ErrInvalidLength reports a length prefix smaller than the four bytes it
// occupies, which includes any prefix whose high bit is set.
var ErrInvalidLength = errors.New("pgwire: invalid message length")

// ErrMessageTooLarge reports a body larger than the Reader's configured limit.
var ErrMessageTooLarge = errors.New("pgwire: message too large")

// Reader frames incoming protocol messages from a stream.
//
// A Reader is not safe for concurrent use. The protocol is a single ordered
// stream per connection, so one Reader per direction per connection is the
// intended pattern.
type Reader struct {
	br  *bufio.Reader
	max int
}

// NewReader returns a Reader that rejects bodies larger than max bytes. A max
// of zero or less selects DefaultMaxMessageBytes.
func NewReader(r io.Reader, max int) *Reader {
	if max <= 0 {
		max = DefaultMaxMessageBytes
	}
	return &Reader{br: bufio.NewReader(r), max: max}
}

// ReadUntyped reads a startup-phase message, which carries no type byte. The
// returned Message has a zero Type.
func (r *Reader) ReadUntyped() (Message, error) {
	body, err := r.readBody()
	if err != nil {
		return Message{}, err
	}
	return Message{Body: body}, nil
}

// ReadTyped reads a post-startup message, which is prefixed by a type byte.
func (r *Reader) ReadTyped() (Message, error) {
	typ, err := r.br.ReadByte()
	if err != nil {
		return Message{}, err
	}
	body, err := r.readBody()
	if err != nil {
		return Message{}, err
	}
	return Message{Type: typ, Body: body}, nil
}

// readBody consumes a length prefix and the body it describes. The prefix
// counts itself, so the body is length-headerSize bytes long.
func (r *Reader) readBody() ([]byte, error) {
	var hdr [headerSize]byte
	if _, err := io.ReadFull(r.br, hdr[:]); err != nil {
		return nil, err
	}
	length := int32(binary.BigEndian.Uint32(hdr[:]))
	if length < headerSize {
		return nil, fmt.Errorf("%w: %d", ErrInvalidLength, length)
	}
	size := int(length) - headerSize
	if size > r.max {
		return nil, fmt.Errorf("%w: %d bytes exceeds limit of %d", ErrMessageTooLarge, size, r.max)
	}
	if size == 0 {
		return nil, nil
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r.br, body); err != nil {
		return nil, err
	}
	return body, nil
}
