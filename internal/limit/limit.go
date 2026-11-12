// Package limit reads data within a bound: neither an answer from the network
// nor a file sent by a user is ever read whole whatever its size, and a
// reading cut at its bound fails instead of passing for the whole data. A JSON
// document sent by a user is also bounded in values before it is decoded, one
// at a time (AdmitJSON).
package limit

import (
	"bytes"
	"fmt"
	"io"
	"strings"
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
func Reader(r io.Reader, max int64) *Limited {
	return &Limited{r: r, max: max, left: max}
}

// Limited is the reader of Reader.
type Limited struct {
	r         io.Reader
	max, left int64 // left < 0 once r went past max
}

// Renew gives the reader its whole bound again, for the next part of a stream
// read part by part, such as the advisories of a page of OSV: each part is
// then bounded, rather than the stream. A reader past its bound stays failed.
func (l *Limited) Renew() {
	if l.left >= 0 {
		l.left = l.max
	}
}

func (l *Limited) Read(p []byte) (int, error) {
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

// maxJSONValues bounds the values of a JSON document sent by a user (SBOM,
// VEX), counted before it is decoded. Every element of a list becomes a
// structure of the decoder, up to 128 bytes for an empty {}, 0 or "": 20 MB
// of them made it hold 2 to 3 GB. Real documents hold far fewer per byte: the
// SBOM of a release of Vigil made by Syft 1.54.0 (SPDX, 13 packages) has 40
// values per package, one byte in 39, so 540 000 values in 20 MB; a CycloneDX
// SBOM in the form of Trivy, 30 per component, 850 000. Two million leaves
// more than twice that, and the decoder under 800 MB (790 MB measured for two
// million 0 in a list of components), one document at a time.
const maxJSONValues = 2_000_000

// jsonValues reports whether a JSON document holds at most max values a
// decoder could build: the elements of its lists and the members of its
// objects, which commas separate, and the lists and objects themselves. It
// reads bytes only, skipping the strings, so that a document is refused before
// anything is allocated for it; whether it is valid JSON is the decoder's
// business.
func jsonValues(data []byte, max int) bool {
	n := 0
	inString, escaped := false, false
	for _, c := range data {
		switch {
		case escaped:
			escaped = false
		case inString:
			escaped = c == '\\'
			inString = c != '"'
		case c == '"':
			inString = true
		case c == ',' || c == '[' || c == '{':
			if n++; n > max {
				return false
			}
		}
	}
	return true
}

// decoding lets one document sent by a user be decoded at a time.
// SECURITY: the largest one admitted holds the decoder hundreds of megabytes;
// concurrent imports (pages, API) wait instead of adding up.
var decoding = make(chan struct{}, 1)

// AdmitJSON admits a JSON document sent by a user, read by File, to be
// decoded: it fails, with an error for the screen, past maxJSONValues values
// (see jsonValues); otherwise it waits until no other document is being
// decoded. The caller decodes, then calls done.
func AdmitJSON(data []byte) (done func(), err error) {
	if !jsonValues(data, maxJSONValues) {
		return nil, fmt.Errorf("document trop complexe : plus de %d valeurs JSON", maxJSONValues)
	}
	decoding <- struct{}{}
	return func() { <-decoding }, nil
}

// JSONKind names a kind of JSON value in French, for an error shown about a
// document that is not the one expected: given as encoding/json names it (the
// value found: "string", "number"…) or as a Go kind (the value expected:
// "slice", "struct"…). A value received is named by its kind, never quoted.
func JSONKind(kind string) string {
	switch kind {
	case "array", "slice":
		return "une liste"
	case "object", "struct", "map":
		return "un objet"
	case "string":
		return "un texte"
	case "bool":
		return "vrai ou faux"
	}
	if strings.HasPrefix(kind, "number") || strings.HasPrefix(kind, "int") || strings.HasPrefix(kind, "float") {
		return "un nombre"
	}
	return "une autre valeur"
}

// size writes a bound in megabytes when it is a whole number of them, as the
// pages state it ("2 Mo max"), in bytes otherwise.
func size(n int64) string {
	if n > 0 && n%(1<<20) == 0 {
		return fmt.Sprintf("%d Mo", n>>20)
	}
	return fmt.Sprintf("%d octets", n)
}
