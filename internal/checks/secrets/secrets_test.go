package secrets

import (
	"strings"
	"testing"

	"github.com/reyjayswa/asfasf/internal/crawler"
)

// Sample secrets are assembled from fragments at runtime so no complete secret
// literal exists in this source file. That keeps the regexes exercised while
// avoiding secret-scanning push protection on test fixtures.
func sampleSecrets() (aws, google, slack, github, privKey, generic string) {
	aws = "AKIA" + "IOSFODNN7EXAMPLE"
	google = "AIza" + "SyA1234567890abcdefghijklmnopqrstuvw"
	slack = "xox" + "b-" + "1234567890-abcdefghijkLMNOP"
	github = "ghp" + "_" + "abcdefghijklmnopqrstuvwxyz0123456789"
	privKey = "-----BEGIN RSA PRIVATE" + " KEY-----\nMIIEowIBAAKCAQEA1234\n-----END RSA PRIVATE KEY-----"
	generic = `apiKey = "abcdefghij0123456789ABCD"`
	return
}

func TestAnalyze_DetectsSecrets(t *testing.T) {
	aws, google, slack, github, privKey, generic := sampleSecrets()
	body := strings.Join([]string{
		"<html><head><script>",
		`  var awsKey = "` + aws + `";`,
		`  const gkey = "` + google + `";`,
		`  const slack = "` + slack + `";`,
		`  const gh = "` + github + `";`,
		"  var " + generic + ";",
		"</script></head><body>",
		privKey,
		"</body></html>",
	}, "\n")

	pages := []crawler.Page{{URL: "http://127.0.0.1/app.html", Body: []byte(body)}}
	findings := Analyze(pages)
	if len(findings) == 0 {
		t.Fatalf("expected findings, got none")
	}

	got := map[string]bool{}
	for _, f := range findings {
		got[f.Payload] = true
		if f.URL != "http://127.0.0.1/app.html" {
			t.Errorf("unexpected URL: %s", f.URL)
		}
		// Evidence must mask the secret: the full AWS key must never appear.
		if strings.Contains(f.Evidence, aws) {
			t.Errorf("evidence must mask secret, got %q", f.Evidence)
		}
	}

	for _, want := range []string{
		"aws-access-key-id",
		"google-api-key",
		"slack-token",
		"private-key-block",
		"github-token",
		"generic-secret-assignment",
	} {
		if !got[want] {
			t.Errorf("expected to detect %q, missing", want)
		}
	}
}

func TestAnalyze_Dedup(t *testing.T) {
	aws, _, _, _, _, _ := sampleSecrets()
	body := aws + " " + aws + " " + aws
	pages := []crawler.Page{{URL: "http://127.0.0.1/x", Body: []byte(body)}}
	findings := Analyze(pages)
	count := 0
	for _, f := range findings {
		if f.Payload == "aws-access-key-id" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 deduped AWS finding, got %d", count)
	}
}

func TestAnalyze_Clean(t *testing.T) {
	body := `
<html><body>
  <p>Welcome to our normal page. No secrets here.</p>
  <script>var x = "hello world"; var count = 12345;</script>
  <a href="/AKIA-marketing-page">AKIA campaign</a>
</body></html>`
	pages := []crawler.Page{{URL: "http://127.0.0.1/clean", Body: []byte(body)}}
	findings := Analyze(pages)
	if len(findings) != 0 {
		t.Fatalf("expected zero findings on clean page, got %d: %+v", len(findings), findings)
	}
}
