package dirlisting

import (
	"testing"

	"github.com/reyjayswa/asfasf/internal/crawler"
)

func TestAnalyze_Positive(t *testing.T) {
	pages := []crawler.Page{
		{URL: "http://127.0.0.1/files/", Status: 200, Body: []byte(`<html><head><title>Index of /files</title></head><body><h1>Index of /files</h1><a href="../">Parent Directory</a></body></html>`)},
		{URL: "http://127.0.0.1/tomcat/", Status: 200, Body: []byte(`<html><body><h1>Directory Listing For /tomcat/</h1></body></html>`)},
		{URL: "http://127.0.0.1/iis/", Status: 200, Body: []byte(`<pre><A HREF="/iis/../">[To Parent Directory]</A></pre>`)},
	}
	findings := Analyze(pages)
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f.Type != "directory-listing" {
			t.Errorf("unexpected Type %q", f.Type)
		}
		if f.CWE != "CWE-548" {
			t.Errorf("expected CWE-548, got %q", f.CWE)
		}
		if f.Confidence != "firm" {
			t.Errorf("expected firm confidence, got %q", f.Confidence)
		}
		if f.Evidence == "" {
			t.Errorf("expected evidence for %s", f.URL)
		}
	}
}

func TestAnalyze_Clean(t *testing.T) {
	pages := []crawler.Page{
		// Normal page that merely links to directories - not a listing.
		{URL: "http://127.0.0.1/", Status: 200, Body: []byte(`<html><body><h1>Welcome</h1><a href="/files/">Browse files</a><a href="/docs/">Docs</a></body></html>`)},
		// Status 0 must be skipped even if it contains a signature.
		{URL: "http://127.0.0.1/skip", Status: 0, Body: []byte(`<title>Index of /</title>`)},
	}
	findings := Analyze(pages)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestAnalyze_OncePerURL(t *testing.T) {
	pages := []crawler.Page{
		{URL: "http://127.0.0.1/dup/", Status: 200, Body: []byte(`<title>Index of /dup</title><h1>Index of /dup</h1>`)},
	}
	if got := len(Analyze(pages)); got != 1 {
		t.Fatalf("expected 1 finding for page with multiple signatures, got %d", got)
	}
}
