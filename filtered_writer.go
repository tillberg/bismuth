package bismuth

import (
	"errors"
	"io"
	// log "github.com/tillberg/ansi-log"
)

type FilteredWriter struct {
	nextWriter  io.Writer
	readPrefix  bool
	buf         []byte
	msgBuf      []byte
	pidChan     chan string
	retCodeChan chan string
}

func NewFilteredWriter(nextWriter io.Writer, pidChan chan string, retCodeChan chan string) io.Writer {
	w := &FilteredWriter{}
	w.nextWriter = nextWriter
	w.pidChan = pidChan
	w.retCodeChan = retCodeChan
	return w
}

var newlineByte byte = 0x0a

func (w *FilteredWriter) Write(p []byte) (nn int, err error) {
	for _, b := range p {
		if !w.readPrefix {
			if b == newlineByte {
				// log.Printf("The prefix is [%s]\n", string(w.msgBuf))
				w.pidChan <- string(w.msgBuf)
				w.msgBuf = w.msgBuf[:0]
				w.readPrefix = true
			} else {
				w.msgBuf = append(w.msgBuf, b)
			}
		} else if len(w.msgBuf) < len(resultCodeEscapeBytes) {
			if b == resultCodeEscapeBytes[len(w.msgBuf)] {
				w.msgBuf = append(w.msgBuf, b)
			} else {
				if len(w.msgBuf) > 0 {
					w.buf = append(w.buf, w.msgBuf...)
					w.buf = w.buf[:0]
				}
				w.buf = append(w.buf, b)
			}
		} else {
			if b == newlineByte {
				retCodeStr := string(w.msgBuf[len(resultCodeEscapeBytes):])
				// log.Printf("The suffix is [%s]\n", retCodeStr)
				w.retCodeChan <- retCodeStr
			} else {
				w.msgBuf = append(w.msgBuf, b)
			}
		}
	}
	for w.nextWriter != nil && len(w.buf) > 0 {
		numBytesWritten, err := w.nextWriter.Write(w.buf)
		// log.Printf("Wrote %d bytes to the underlying stream (out of %d in buf or %d received): %q\n", numBytesWritten, len(w.buf), len(p), string(w.buf))
		if numBytesWritten == 0 {
			return len(p), errors.New("nextWriter wrote only zero bytes")
		}
		w.buf = w.buf[numBytesWritten:]
		if err != nil {
			return len(p), err
		}
	}
	return len(p), nil
}
