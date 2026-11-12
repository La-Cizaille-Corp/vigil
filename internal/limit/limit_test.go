package limit

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"time"
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

// The values of a JSON document are counted from its bytes: commas, lists and
// objects, but nothing inside a string, escaped quotes included.
func TestJSONValues(t *testing.T) {
	for _, c := range []struct {
		doc  string
		want int // values counted
	}{
		{`{}`, 1},
		{`[0,0,0]`, 3},
		{`{"a":[{},{}],"b":""}`, 6},
		{`{"a":"x,y[{","b":"\",{["}`, 2},
		{`"\\",[`, 2}, // an escaped backslash ends before the quote
	} {
		if !jsonValues([]byte(c.doc), c.want) || jsonValues([]byte(c.doc), c.want-1) {
			t.Errorf("%s: not %d values", c.doc, c.want)
		}
	}
}

// A document with too many values is refused before it is decoded; the others
// are decoded one at a time.
func TestAdmitJSON(t *testing.T) {
	many := []byte("[" + strings.Repeat("0,", maxJSONValues) + "0]")
	if _, err := AdmitJSON(many); err == nil || err.Error() != "document trop complexe : plus de 2000000 valeurs JSON" {
		t.Fatalf("too many values: %v", err)
	}
	done, err := AdmitJSON([]byte(`{"components":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	second := make(chan func())
	go func() {
		d, _ := AdmitJSON([]byte(`{}`))
		second <- d
	}()
	select {
	case <-second:
		t.Fatal("two documents decoded at once")
	case <-time.After(50 * time.Millisecond):
	}
	done()
	select {
	case d := <-second:
		d()
	case <-time.After(5 * time.Second):
		t.Fatal("the second document still waits")
	}
}

// Renewed, a reader bounds the next part of a stream, not the stream; past
// its bound, it stays failed.
func TestRenew(t *testing.T) {
	r := Reader(strings.NewReader("12345678"), 4)
	buf := make([]byte, 3)
	for range 2 {
		if n, err := io.ReadFull(r, buf); n != 3 || err != nil {
			t.Fatalf("part of 3 bytes: %d, %v", n, err)
		}
		r.Renew()
	}
	r = Reader(strings.NewReader("123456"), 4)
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("no error past the bound")
	}
	r.Renew()
	var tooLarge *TooLargeError
	if _, err := r.Read(buf); !errors.As(err, &tooLarge) {
		t.Errorf("renewed after failing: %v", err)
	}
}
