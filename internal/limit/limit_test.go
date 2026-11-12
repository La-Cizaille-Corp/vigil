package limit

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

// A reading stops at its bound with an error, never as if the data were whole,
// whatever the size of the reads.
func TestReader(t *testing.T) {
	for _, c := range []struct {
		data string
		ok   bool
	}{{"", true}, {"12345", true}, {"123456", false}, {strings.Repeat("x", 10_000), false}} {
		for name, r := range map[string]io.Reader{
			"whole":    strings.NewReader(c.data),
			"one byte": iotest.OneByteReader(strings.NewReader(c.data)),
		} {
			got, err := io.ReadAll(Reader(r, 5))
			var tooLarge *TooLargeError
			if c.ok && (err != nil || string(got) != c.data) ||
				!c.ok && (!errors.As(err, &tooLarge) || tooLarge.Max != 5 || len(got) != 5) {
				t.Errorf("%d bytes, %s: %q, %v", len(c.data), name, got, err)
			}
		}
		got, err := Read(strings.NewReader(c.data), 5)
		if c.ok != (err == nil) || !c.ok && (got != nil || err.Error() != "réponse supérieure à 5 octets") {
			t.Errorf("Read, %d bytes: %q, %v", len(c.data), got, err)
		}
	}
}

// A file is read within its bound, with or without the byte order mark that
// tools on Windows put in front; past the bound, the error says it for the
// screen.
func TestFile(t *testing.T) {
	for _, c := range []struct {
		in, want string
		max      int64
		err      string
	}{
		{"name;version\n", "name;version\n", 100, ""},
		{"\xef\xbb\xbfname;version\n", "name;version\n", 100, ""},
		{"\xef\xbb\xbf", "", 100, ""},
		{"\xef\xbb\xbf\xef\xbb\xbfx", "\xef\xbb\xbfx", 100, ""}, // one mark only: a second one is data
		{"12345", "12345", 5, ""},
		{"123456", "", 5, "fichier supérieur à 5 octets"},
		{strings.Repeat("x", 2<<20+1), "", 2 << 20, "fichier supérieur à 2 Mo"},
	} {
		got, err := File(strings.NewReader(c.in), c.max)
		if string(got) != c.want || c.err == "" && err != nil || c.err != "" && (err == nil || err.Error() != c.err) {
			t.Errorf("File(%.20q, %d) = %q, %v; want %q, %q", c.in, c.max, got, err, c.want, c.err)
		}
	}
	failing := errors.New("connection reset")
	if _, err := File(iotest.ErrReader(failing), 10); !errors.Is(err, failing) {
		t.Errorf("failed reading: %v", err)
	}
}
