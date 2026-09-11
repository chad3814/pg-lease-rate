package pgwire

import (
	"bufio"
	"encoding/binary"
	"io"
)

// SSLDenied is the reply that declines an SSLRequest, after which the client
// continues in cleartext on the same connection. The accepting reply is 'S',
// which commits both ends to a TLS handshake; this gateway does not offer it.
const SSLDenied byte = 'N'

// Writer frames outgoing protocol messages onto a stream. Writes are buffered,
// so callers must Flush before a peer can observe them.
//
// A Writer is not safe for concurrent use.
type Writer struct {
	bw *bufio.Writer
}

// NewWriter returns a Writer that buffers onto w.
func NewWriter(w io.Writer) *Writer {
	return &Writer{bw: bufio.NewWriter(w)}
}

// WriteTyped frames body as a message of the given type.
func (w *Writer) WriteTyped(typ byte, body []byte) error {
	if err := w.bw.WriteByte(typ); err != nil {
		return err
	}
	var hdr [headerSize]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(headerSize+len(body)))
	if _, err := w.bw.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.bw.Write(body)
	return err
}

// WriteRawByte writes a single unframed byte. The only bytes the protocol
// exchanges outside the framing are the replies to SSLRequest and
// GSSENCRequest; see SSLDenied.
func (w *Writer) WriteRawByte(b byte) error {
	return w.bw.WriteByte(b)
}

// Flush writes any buffered bytes to the underlying stream.
func (w *Writer) Flush() error {
	return w.bw.Flush()
}
