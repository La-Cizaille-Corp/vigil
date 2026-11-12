// Package limit reads data within a bound: neither an answer from the network
// nor a file sent by a user is ever read whole whatever its size, and a
// reading cut at its bound fails instead of passing for the whole data.
package limit

import (
	"bytes"
	"fmt"
	"io"
)

// TooLargeError is the failure of a reading of the network that goes past its
// bound (Reader, Read); File says it of a file.
type TooLargeError struct{ Max int64 }

func (e *TooLargeError) Error() string {
	return fmt.Sprintf("réponse supérieure à %d octets", e.Max)
}

// Reader returns a reader of the first max bytes of r, which fails with a
// *TooLargeError if r holds more. io.LimitReader would end there as if the
// data were whole: a document cut at the bound must not pass for a complete
// one, nor fail as a malformed one.
func Reader(r io.Reader, max int64) io.Reader {
	return &reader{r: r, max: max, left: max}
}

type reader struct {
	r         io.Reader
	max, left int64 // left < 0 once r went past max
}

func (l *reader) Read(p []byte) (int, error) {
	if l.left < 0 {
		return 0, &TooLargeError{Max: l.max}
	}
	if int64(len(p)) > l.left+1 {
		p = p[:l.left+1] // one byte more tells whether r goes past max
	}
	n, err := l.r.Read(p)
	if int64(n) > l.left {
		n, l.left = int(l.left), -1
		return n, &TooLargeError{Max: l.max}
	}
	l.left -= int64(n)
	return n, err
}

// Read reads r whole, at most max bytes: past them it fails with a
// *TooLargeError.
func Read(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(Reader(r, max))
	if err != nil {
		return nil, err
	}
	return b, nil
}

// bom is the UTF-8 byte order mark, which tools on Windows (Excel, PowerShell,
// some SBOM generators) put in front of a text file.
var bom = []byte{0xEF, 0xBB, 0xBF}

// File reads a file sent by a user, an upload or a file named on the command
// line: at most max bytes, without the UTF-8 byte order mark in front. A file
// past max fails with an error that says the bound, for the screen.
func File(r io.Reader, max int64) ([]byte, error) {
	data, err := Read(r, max)
	// io.ReadAll returns the error of the reader as it is: no unwrapping
	// (errors.As, which the capability check cannot follow) is needed.
	if _, tooLarge := err.(*TooLargeError); tooLarge {
		return nil, fmt.Errorf("fichier supérieur à %s", size(max))
	}
	if err != nil {
		return nil, err
	}
	return bytes.TrimPrefix(data, bom), nil
}

// size writes a bound in megabytes when it is a whole number of them, as the
// pages state it ("2 Mo max"), in bytes otherwise.
func size(n int64) string {
	if n > 0 && n%(1<<20) == 0 {
		return fmt.Sprintf("%d Mo", n>>20)
	}
	return fmt.Sprintf("%d octets", n)
}
