package jwt

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/reyjayswa/asfasf/internal/crawler"
)

// makeJWT builds an unsigned test JWT string from header and payload maps.
func makeJWT(t *testing.T, header, payload map[string]interface{}) string {
	t.Helper()
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	enc := base64.RawURLEncoding.EncodeToString
	return enc(hb) + "." + enc(pb) + ".sig-omitted"
}

func TestAnalyze_Positive(t *testing.T) {
	noneTok := makeJWT(t,
		map[string]interface{}{"alg": "none", "typ": "JWT"},
		map[string]interface{}{"sub": "1", "exp": 9999999999},
	)
	noExpTok := makeJWT(t,
		map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{"sub": "2"},
	)

	pages := []crawler.Page{
		{
			URL:    "http://127.0.0.1/a",
			Status: 200,
			Header: http.Header{},
			Body:   []byte(`{"access_token":"` + noneTok + `"}`),
		},
		{
			URL:    "http://127.0.0.1/b",
			Status: 200,
			Header: http.Header{},
			Body:   []byte("token=" + noExpTok),
		},
	}

	findings := Analyze(pages)
	if len(findings) == 0 {
		t.Fatalf("expected findings, got none")
	}

	var haveNone, haveExposed, haveNoExp bool
	for _, f := range findings {
		if f.Type != "jwt" {
			t.Errorf("unexpected finding type %q", f.Type)
		}
		switch f.Title {
		case "JWT using 'none' algorithm":
			haveNone = true
			if f.Severity != "high" || f.Confidence != "firm" || f.CWE != "CWE-347" {
				t.Errorf("none finding wrong metadata: %+v", f)
			}
		case "JWT exposed in response body or URL":
			haveExposed = true
			if f.Severity != "low" || f.Confidence != "tentative" {
				t.Errorf("exposed finding wrong metadata: %+v", f)
			}
		case "JWT without expiry claim":
			haveNoExp = true
			if f.Severity != "low" || f.Confidence != "tentative" {
				t.Errorf("no-exp finding wrong metadata: %+v", f)
			}
		}
	}
	if !haveNone {
		t.Error("expected a 'none' algorithm finding")
	}
	if !haveExposed {
		t.Error("expected an exposure finding")
	}
	if !haveNoExp {
		t.Error("expected a missing-expiry finding")
	}
}

func TestAnalyze_Clean(t *testing.T) {
	// A well-formed token: HS256, has exp, and delivered ONLY in a Set-Cookie
	// header (not body/URL). No findings should result.
	tok := makeJWT(t,
		map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{"sub": "42", "exp": 9999999999},
	)

	h := http.Header{}
	h.Add("Set-Cookie", "session="+tok+"; HttpOnly; Secure; SameSite=Strict")

	pages := []crawler.Page{
		{
			URL:    "http://127.0.0.1/login",
			Status: 200,
			Header: h,
			Body:   []byte("<html><body>welcome</body></html>"),
		},
		{
			// Status 0 pages are skipped entirely.
			URL:    "http://127.0.0.1/skipme",
			Status: 0,
			Header: http.Header{},
			Body:   []byte(tok),
		},
	}

	findings := Analyze(pages)
	if len(findings) != 0 {
		t.Fatalf("expected zero findings, got %d: %+v", len(findings), findings)
	}
}
