package sqldumper

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/config"
	"github.com/reyjayswa/asfasf/internal/httpclient"
	"github.com/reyjayswa/asfasf/internal/scope"
)

var limitRe = regexp.MustCompile(`(?i)limit (\d+),1`)

// mysqlEmulator emulates a MySQL error-based (extractvalue) injectable
// endpoint. When the payload uses extractvalue/updatexml with our ~ sentinel,
// it evaluates the embedded subquery and returns the value inside an XPATH
// error, exactly as MySQL would leak it.
func mysqlEmulator() *httptest.Server {
	tables := []string{"users", "orders", "products"}
	columns := []string{"id", "email", "passwd"}
	rows := []string{"alice@example.com", "bob@example.com", "carol@example.com"}

	offset := func(s string) int {
		if m := limitRe.FindStringSubmatch(s); len(m) == 2 {
			n := 0
			fmt.Sscanf(m[1], "%d", &n)
			return n
		}
		return -1
	}
	pick := func(list []string, s string) string {
		i := offset(s)
		if i >= 0 && i < len(list) {
			return list[i]
		}
		return ""
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/item", func(w http.ResponseWriter, r *http.Request) {
		p := strings.ToLower(r.URL.Query().Get("id"))
		if !strings.Contains(p, "extractvalue") && !strings.Contains(p, "updatexml") {
			fmt.Fprint(w, "<html>ok</html>")
			return
		}
		var val string
		switch {
		case strings.Contains(p, "information_schema.tables"):
			val = pick(tables, p)
		case strings.Contains(p, "information_schema.columns"):
			val = pick(columns, p)
		case strings.Contains(p, "from users"):
			val = pick(rows, p)
		case strings.Contains(p, "version()"):
			val = "5.7.31-log"
		case strings.Contains(p, "current_user"):
			val = "root@localhost"
		case strings.Contains(p, "database()"):
			val = "shopdb"
		}
		if val == "" {
			fmt.Fprint(w, "XPATH syntax error: '~'") // empty -> caller stops
			return
		}
		fmt.Fprintf(w, "XPATH syntax error: '~%s'", val)
	})
	return httptest.NewServer(mux)
}

func newClient(t *testing.T) *httpclient.Client {
	t.Helper()
	sc, err := scope.New(config.Scope{InScope: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	return httpclient.New(config.HTTP{RatePerSecond: 500, Concurrency: 4, TimeoutSeconds: 10}, sc)
}

func findByTitlePart(fs []checks.Finding, part string) *checks.Finding {
	for i := range fs {
		if strings.Contains(fs[i].Title, part) {
			return &fs[i]
		}
	}
	return nil
}

func TestDumpMetadataAndSchema(t *testing.T) {
	srv := mysqlEmulator()
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	ep := checks.Endpoint{URL: srv.URL + "/item", Method: http.MethodGet, Params: []string{"id"}}
	_ = u

	c := New(newClient(t), Options{}) // defaults; SampleData=false
	fs := c.Dump(context.Background(), ep, "id")

	meta := findByTitlePart(fs, "metadata extracted")
	if meta == nil {
		t.Fatalf("expected metadata finding, got %+v", fs)
	}
	for _, want := range []string{"5.7.31-log", "root@localhost", "shopdb"} {
		if !strings.Contains(meta.Evidence, want) {
			t.Errorf("metadata evidence missing %q: %s", want, meta.Evidence)
		}
	}

	schema := findByTitlePart(fs, "schema enumerated")
	if schema == nil {
		t.Fatalf("expected schema finding, got %+v", fs)
	}
	for _, want := range []string{"users", "orders", "products", "passwd"} {
		if !strings.Contains(schema.Evidence, want) {
			t.Errorf("schema evidence missing %q: %s", want, schema.Evidence)
		}
	}

	// Default must NOT sample row data.
	if findByTitlePart(fs, "sample of row data") != nil {
		t.Error("SampleData=false must not produce a row-sample finding")
	}
}

func TestDumpBoundedSampleAndCaps(t *testing.T) {
	srv := mysqlEmulator()
	defer srv.Close()

	ep := checks.Endpoint{URL: srv.URL + "/item", Method: http.MethodGet, Params: []string{"id"}}

	// Cap tables at 2 and rows at 2, enable sampling.
	c := New(newClient(t), Options{MaxTables: 2, MaxColumns: 5, MaxRows: 2, SampleData: true})
	fs := c.Dump(context.Background(), ep, "id")

	schema := findByTitlePart(fs, "schema enumerated")
	if schema == nil {
		t.Fatal("expected schema finding")
	}
	// Only 2 tables should appear because MaxTables=2.
	if !strings.Contains(schema.Evidence, "users") || !strings.Contains(schema.Evidence, "orders") {
		t.Errorf("expected first two tables, got: %s", schema.Evidence)
	}
	if strings.Contains(schema.Evidence, "products") {
		t.Errorf("MaxTables=2 should have excluded 'products': %s", schema.Evidence)
	}

	sample := findByTitlePart(fs, "sample of row data")
	if sample == nil {
		t.Fatal("SampleData=true should produce a bounded sample finding")
	}
	// At most MaxRows=2 rows.
	if strings.Count(sample.Evidence, "@example.com") > 2 {
		t.Errorf("row sample exceeded MaxRows=2: %s", sample.Evidence)
	}
}

func TestDumpReturnsNilWhenNotExtractable(t *testing.T) {
	// A server that never leaks values -> no extraction possible.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>nothing to see</html>")
	}))
	defer srv.Close()

	ep := checks.Endpoint{URL: srv.URL + "/item", Method: http.MethodGet, Params: []string{"id"}}
	c := New(newClient(t), Options{})
	if fs := c.Dump(context.Background(), ep, "id"); fs != nil {
		t.Errorf("expected nil when nothing extractable, got %+v", fs)
	}
}
