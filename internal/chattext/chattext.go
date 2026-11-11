// Package chattext neutralises untrusted text (feed titles, advisory
// summaries, asset names from SBOMs) before it goes into a Markdown message
// read by Slack, Mattermost, Teams or a Markdown viewer.
package chattext

import (
	"strings"
)

// zwsp is a zero-width space: invisible, but it breaks a mention or a link.
const zwsp = string(rune(0x200B))

// SECURITY: without this, a third party writing "<!channel>", "@all" or
// "[Correctif](https://evil)" in a feed title or an SBOM component name would
// ping a whole channel or show a disguised link under Vigil's name.
var replacer = strings.NewReplacer(
	"<", "‹", // Slack <!channel>, <url|text>, and HTML in Markdown viewers
	">", "›",
	"@", "@"+zwsp, // @channel, @here, @all, @user
	"](", "]"+zwsp+"(", // [text](url) and ![image](url)
	"\r", " ", "\n", " ", "\t", " ",
)

// Text returns s as plain, inert text on one line.
func Text(s string) string {
	return replacer.Replace(strings.Join(strings.Fields(s), " "))
}

// Cell is Text safe inside a Markdown table cell.
func Cell(s string) string {
	return strings.ReplaceAll(Text(s), "|", `\|`)
}

// URL makes a validated http(s) link safe as the target of a Markdown link:
// characters that would end the target or the link are percent-encoded.
// SECURITY: so are spaces and control characters: a line break would cut
// the link and start a line that the chat reads as text ("@channel"), even
// for a link stored before links were checked on collection.
func URL(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c == 0x7f || strings.IndexByte("()<>[]", c) >= 0 {
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}
