package cti

import (
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// Tag is a sector or a country with the keywords that reveal it.
// Matching is deliberately simple (whole words, case-insensitive): the
// source's own country and sectors come first, keywords only complete them,
// and tags can be filtered rather than trusted blindly.
type Tag struct {
	Value    string
	Label    string
	Keywords []string
}

// Sectors follows the NIS2 sector list, simplified.
var Sectors = []Tag{
	{"energy", "Énergie", []string{"energy", "énergie", "power grid", "electricity", "électricité", "oil", "pétrole", "gas pipeline", "nuclear", "nucléaire", "utility", "utilities"}},
	{"health", "Santé", []string{"health", "santé", "hospital", "hôpital", "hôpitaux", "healthcare", "medical", "médical", "pharma", "pharmaceutical", "clinic", "clinique"}},
	{"finance", "Finance", []string{"bank", "banque", "banking", "bancaire", "financial", "financier", "fintech", "insurance", "assurance", "crypto exchange", "payment", "paiement"}},
	{"government", "Administration publique", []string{"government", "gouvernement", "ministry", "ministère", "municipal", "collectivité", "public sector", "secteur public", "administration", "embassy", "ambassade"}},
	{"defense", "Défense", []string{"defense", "defence", "défense", "military", "militaire", "armed forces", "armée"}},
	{"transport", "Transports", []string{"airline", "airport", "aéroport", "aviation", "maritime", "shipping", "railway", "ferroviaire", "logistics", "logistique", "transport"}},
	{"telecom", "Télécommunications", []string{"telecom", "télécom", "telecommunications", "télécommunications", "isp", "mobile operator", "opérateur télécom"}},
	{"education", "Éducation et recherche", []string{"university", "université", "school", "école", "education", "éducation", "research institute", "laboratoire"}},
	{"manufacturing", "Industrie", []string{"manufacturing", "industrie", "industrial", "industriel", "ics", "scada", "factory", "usine", "automotive", "automobile"}},
	{"retail", "Commerce", []string{"retail", "e-commerce", "retailer", "commerce", "point of sale"}},
	{"water", "Eau", []string{"water utility", "wastewater", "eau potable", "water treatment"}},
	{"digital", "Services numériques / IT", []string{"cloud", "saas", "msp", "managed service provider", "hosting", "hébergeur", "data center", "datacenter", "software supply chain"}},
}

// Regulations are the regulations and reference standards followed by the
// regulatory watch. Keywords avoid bare acronyms that are common words
// (e.g. "CRA" alone) to limit false positives.
var Regulations = []Tag{
	{"nis2", "NIS2", []string{"nis2", "nis 2", "nis-2", "directive (eu) 2022/2555", "directive 2022/2555"}},
	{"cra", "Cyber Resilience Act", []string{"cyber resilience act", "cyber-resilience act", "cyberrésilience", "cyber-résilience", "règlement cra", "the cra", "le cra", "regulation (eu) 2024/2847"}},
	{"dora", "DORA", []string{"dora", "digital operational resilience", "résilience opérationnelle numérique", "regulation (eu) 2022/2554"}},
	{"gdpr", "RGPD", []string{"gdpr", "rgpd", "general data protection regulation", "règlement général sur la protection des données", "data protection authority", "protection des données personnelles"}},
	{"ai_act", "AI Act", []string{"ai act", "artificial intelligence act", "règlement sur l'intelligence artificielle", "règlement sur l'ia", "règlement ia", "regulation (eu) 2024/1689"}},
	{"cybersecurity_act", "Cybersecurity Act / certification UE", []string{"cybersecurity act", "eucc", "eucs", "eu5g", "certification de cybersécurité", "cybersecurity certification"}},
	{"eidas", "eIDAS", []string{"eidas", "eudi wallet", "european digital identity", "identité numérique européenne"}},
	{"data_act", "Data Act", []string{"data act", "règlement sur les données"}},
	{"iso27001", "ISO/IEC 27001", []string{"iso 27001", "iso/iec 27001", "iso27001", "iso 27002", "iso/iec 27002", "iso 27005"}},
	{"secnumcloud", "SecNumCloud", []string{"secnumcloud"}},
	{"hds", "HDS (données de santé)", []string{"hébergement de données de santé", "hébergeur de données de santé", "certification hds"}},
	{"pci_dss", "PCI DSS", []string{"pci dss", "pci-dss"}},
	{"lpm", "LPM / OIV", []string{"loi de programmation militaire", "opérateur d'importance vitale", "opérateurs d'importance vitale"}},
	{"nist_csf", "NIST CSF / SP 800", []string{"nist csf", "cybersecurity framework", "nist sp 800", "sp 800-53"}},
}

// Countries most commonly cited in CTI news; extend as needed.
var Countries = []Tag{
	{"FR", "France", []string{"france", "french", "français", "française", "anssi", "cert-fr"}},
	{"BE", "Belgique", []string{"belgium", "belgique", "belgian", "belge"}},
	{"CH", "Suisse", []string{"switzerland", "suisse", "swiss"}},
	{"CA", "Canada", []string{"canada", "canadian", "canadien"}},
	{"DE", "Allemagne", []string{"germany", "german", "allemagne", "allemand", "bsi"}},
	{"GB", "Royaume-Uni", []string{"united kingdom", "uk", "britain", "british", "royaume-uni", "ncsc"}},
	{"US", "États-Unis", []string{"united states", "u.s.", "usa", "american", "états-unis", "cisa", "fbi"}},
	{"IT", "Italie", []string{"italy", "italian", "italie", "italien"}},
	{"ES", "Espagne", []string{"spain", "spanish", "espagne", "espagnol"}},
	{"NL", "Pays-Bas", []string{"netherlands", "dutch", "pays-bas", "néerlandais"}},
	{"PL", "Pologne", []string{"poland", "polish", "pologne", "polonais"}},
	{"UA", "Ukraine", []string{"ukraine", "ukrainian", "ukrainien"}},
	{"RU", "Russie", []string{"russia", "russian", "russie", "russe"}},
	{"CN", "Chine", []string{"china", "chinese", "chine", "chinois"}},
	{"KP", "Corée du Nord", []string{"north korea", "north korean", "corée du nord", "nord-coréen", "lazarus"}},
	{"IR", "Iran", []string{"iran", "iranian", "iranien"}},
	{"IL", "Israël", []string{"israel", "israeli", "israël", "israélien"}},
	{"IN", "Inde", []string{"india", "indian", "inde", "indien"}},
	{"JP", "Japon", []string{"japan", "japanese", "japon", "japonais"}},
	{"AU", "Australie", []string{"australia", "australian", "australie", "australien"}},
	{"EU", "Union européenne", []string{"european union", "union européenne", "enisa", "europol"}},
}

var tagPatterns = map[string]*regexp.Regexp{}

func init() {
	for _, list := range [][]Tag{Sectors, Countries, Regulations} {
		for _, t := range list {
			quoted := make([]string, len(t.Keywords))
			for i, k := range t.Keywords {
				quoted[i] = regexp.QuoteMeta(k)
			}
			// Word boundaries that also work around accented letters.
			tagPatterns[t.Value] = regexp.MustCompile(`(?i)(^|[^\pL\pN])(` + strings.Join(quoted, "|") + `)($|[^\pL\pN])`)
		}
	}
}

// Tags are the classification of an item.
type Tags struct {
	Countries, Sectors, Regulations []string
}

// Classify returns the tags of an item: those of its feed plus those
// detected in its title and summary.
func Classify(it Item, f store.Feed) Tags {
	text := it.Title + " " + it.Summary
	return Tags{
		Countries:   match(Countries, text, splitNonEmpty(f.Country)),
		Sectors:     match(Sectors, text, splitNonEmpty(f.Sectors)),
		Regulations: match(Regulations, text, splitNonEmpty(f.Regulations)),
	}
}

func match(tags []Tag, text string, initial []string) []string {
	set := map[string]bool{}
	for _, v := range initial {
		set[v] = true
	}
	for _, t := range tags {
		if tagPatterns[t.Value].MatchString(text) {
			set[t.Value] = true
		}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Label returns the display label of a sector or country value.
func Label(tags []Tag, value string) string {
	for _, t := range tags {
		if t.Value == value {
			return t.Label
		}
	}
	return value
}

// Known reports whether value is one of tags.
func Known(tags []Tag, value string) bool {
	for _, t := range tags {
		if t.Value == value {
			return true
		}
	}
	return false
}

// charsetReader supports the single-byte encodings still found in old feeds.
func charsetReader(charset string, input io.Reader) (io.Reader, error) {
	switch strings.ToLower(charset) {
	case "utf-8", "utf8", "us-ascii", "ascii":
		return input, nil
	case "iso-8859-1", "iso-8859-15", "latin1", "windows-1252", "cp1252":
		return latin1Reader{input}, nil
	}
	return nil, fmt.Errorf("encodage non supporté : %s", charset)
}

// latin1Reader converts ISO-8859-1 bytes to UTF-8.
type latin1Reader struct{ r io.Reader }

func (l latin1Reader) Read(p []byte) (int, error) {
	// Each input byte becomes at most 2 UTF-8 bytes.
	buf := make([]byte, len(p)/2)
	if len(buf) == 0 {
		buf = make([]byte, 1)
		if len(p) < 2 {
			return 0, io.ErrShortBuffer
		}
	}
	n, err := l.r.Read(buf)
	out := p[:0]
	for _, b := range buf[:n] {
		out = utf8.AppendRune(out, rune(b))
	}
	return len(out), err
}
