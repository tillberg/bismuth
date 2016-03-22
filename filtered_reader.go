package bismuth

import "io"

type FilteredReader struct {
	underReader io.Reader
	readPrefix  bool
	buf         []byte
	msgBuf      []byte
	pidChan     chan string
	retCodeChan chan string
}

func NewFilteredReader(underReader io.Reader, pidChan chan string, retCodeChan chan string) io.Reader {
	return &FilteredReader{
		underReader: underReader,
		pidChan:     pidChan,
		retCodeChan: retCodeChan,
	}
}

var newlineByte byte = 0x0a

func (r *FilteredReader) Read(p []byte) (int, error) {
	var err error
	var nn int
	for err == nil {
		nn, err = r.underReader.Read(p)
		// alog.Printf("Read %d bytes from stream underlying FilteredReader: %q\n", nn, p[:nn])
		for _, b := range p[:nn] {
			if !r.readPrefix {
				if b == newlineByte {
					// alog.Printf("The prefix is [%s]\n", string(r.msgBuf))
					r.pidChan <- string(r.msgBuf)
					r.msgBuf = r.msgBuf[:0]
					r.readPrefix = true
				} else {
					r.msgBuf = append(r.msgBuf, b)
				}
			} else if len(r.msgBuf) < len(resultCodeEscapeBytes) {
				if b == resultCodeEscapeBytes[len(r.msgBuf)] {
					r.msgBuf = append(r.msgBuf, b)
				} else {
					if len(r.msgBuf) > 0 {
						r.buf = append(r.buf, r.msgBuf...)
						r.msgBuf = r.msgBuf[:0]
					}
					r.buf = append(r.buf, b)
				}
			} else {
				if b == newlineByte {
					retCodeStr := string(r.msgBuf[len(resultCodeEscapeBytes):])
					// alog.Printf("The suffix is [%s]\n", retCodeStr)
					r.retCodeChan <- retCodeStr
				} else {
					r.msgBuf = append(r.msgBuf, b)
				}
			}
		}
		if len(r.buf) > 0 {
			bytesRead := len(r.buf)
			if len(r.buf) > len(p) {
				bytesRead = len(p)
			}
			copy(p[:bytesRead], r.buf[:bytesRead])
			r.buf = r.buf[bytesRead:]
			// alog.Printf("Returning %d bytes from FilteredReader\n", bytesRead)
			return bytesRead, err
		}
	}
	return 0, err
}
