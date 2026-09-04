// Command scanner is a scope-enforced web vulnerability scanner intended for
// authorized security testing (for example, in-scope bug bounty assets).
//
// Subcommands:
//
//	scan   run a scan and write JSON/HTML reports
//	serve  run a scan and browse results in a local web dashboard
//	init   write an example scope configuration file
//
// The scanner refuses to send any request to a host that is not listed in
// the configuration's scope.in_scope. There is no way to bypass this.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/reyjayswa/asfasf/internal/config"
	"github.com/reyjayswa/asfasf/internal/dashboard"
	"github.com/reyjayswa/asfasf/internal/engine"
	"github.com/reyjayswa/asfasf/internal/report"
)

const banner = `asfasf-scanner — authorized web vulnerability scanner
Only scan targets you own or are explicitly permitted to test.`

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan":
		runScan(os.Args[2:])
	case "serve":
		runServe(os.Args[2:])
	case "init":
		runInit(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `%s

Usage:
  scanner scan  -config <file> [-json out.json] [-html out.html] [-mode passive|safe|aggressive] [-quiet]
  scanner serve -config <file> [-addr 127.0.0.1:8080] [-mode ...] [-no-scan]
  scanner init  [-o scope.yaml] [-interactive] [-minimal]

Run "scanner <command> -h" for command flags.
`, banner)
}

// loadConfig loads and applies a mode override if provided.
func loadConfig(path, modeOverride string) (*config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	if modeOverride != "" {
		cfg.Mode = strings.ToLower(strings.TrimSpace(modeOverride))
		// Re-validate the override.
		switch cfg.Mode {
		case config.ModePassive, config.ModeSafe, config.ModeAggressive:
		default:
			return nil, fmt.Errorf("invalid -mode %q (want passive, safe, or aggressive)", modeOverride)
		}
	}
	return cfg, nil
}

func newLogger(quiet bool) engine.Logger {
	if quiet {
		return func(string, ...interface{}) {}
	}
	return func(format string, args ...interface{}) {
		fmt.Fprintf(os.Stderr, "[*] "+format+"\n", args...)
	}
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		fmt.Fprintln(os.Stderr, "\n[!] interrupted, shutting down…")
		cancel()
	}()
	return ctx, cancel
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to scope config YAML (required)")
	jsonOut := fs.String("json", "", "write JSON report to this path")
	htmlOut := fs.String("html", "", "write HTML report to this path")
	mode := fs.String("mode", "", "override scan mode: passive|safe|aggressive")
	quiet := fs.Bool("quiet", false, "suppress progress output")
	fs.Parse(args)

	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "error: -config is required")
		fs.Usage()
		os.Exit(2)
	}
	cfg, err := loadConfig(*cfgPath, *mode)
	if err != nil {
		fatal(err)
	}
	eng, err := engine.New(cfg, newLogger(*quiet))
	if err != nil {
		fatal(err)
	}
	ctx, cancel := signalContext()
	defer cancel()

	rep := eng.Run(ctx)
	printSummary(rep)

	if *jsonOut != "" {
		if err := report.WriteJSON(rep, *jsonOut); err != nil {
			fatal(err)
		}
		fmt.Fprintf(os.Stderr, "[*] JSON report written to %s\n", *jsonOut)
	}
	if *htmlOut != "" {
		if err := report.WriteHTML(rep, *htmlOut); err != nil {
			fatal(err)
		}
		fmt.Fprintf(os.Stderr, "[*] HTML report written to %s\n", *htmlOut)
	}
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to scope config YAML (required)")
	addr := fs.String("addr", "127.0.0.1:8080", "dashboard bind address")
	mode := fs.String("mode", "", "override scan mode: passive|safe|aggressive")
	noScan := fs.Bool("no-scan", false, "start the dashboard without an initial scan")
	quiet := fs.Bool("quiet", false, "suppress progress output")
	fs.Parse(args)

	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "error: -config is required")
		fs.Usage()
		os.Exit(2)
	}
	cfg, err := loadConfig(*cfgPath, *mode)
	if err != nil {
		fatal(err)
	}
	log := newLogger(*quiet)
	srv := dashboard.NewServer(cfg, *addr, log)

	ctx, cancel := signalContext()
	defer cancel()

	if !*noScan {
		if err := srv.Scan(ctx); err != nil {
			fatal(err)
		}
	}
	if err := srv.ListenAndServe(ctx); err != nil {
		fatal(err)
	}
}

func runInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	out := fs.String("o", "scope.yaml", "output path for the config")
	minimal := fs.Bool("minimal", false, "write a short starter config (just scope + seeds)")
	interactive := fs.Bool("interactive", false, "answer a few questions to build the config")
	fs.BoolVar(interactive, "i", false, "shorthand for -interactive")
	fs.Parse(args)

	if _, err := os.Stat(*out); err == nil {
		fatal(fmt.Errorf("%s already exists; refusing to overwrite", *out))
	}

	if *interactive {
		body, ok := interactiveConfig(os.Stdin, os.Stdout)
		if !ok {
			return // the guide already explained why it stopped
		}
		writeConfig(*out, body)
		return
	}

	body := exampleConfig
	if *minimal {
		body = minimalConfig
	}
	writeConfig(*out, body)
}

// writeConfig saves the config and prints the next step.
func writeConfig(out, body string) {
	if err := os.WriteFile(out, []byte(body), 0o644); err != nil {
		fatal(err)
	}
	fmt.Printf("\nWrote config to %s\n", out)
	fmt.Println("Next: scanner scan -config " + out + " -html report.html")
	fmt.Println("Only in_scope and seeds are required — everything else has safe defaults,")
	fmt.Println("and a useful set of checks turns on automatically.")
}

// interactiveConfig walks the user through a few questions and returns the
// generated config body. It returns ok=false (without writing anything) if the
// user cannot confirm they are authorized to test the target, or aborts.
func interactiveConfig(in io.Reader, outw io.Writer) (string, bool) {
	r := bufio.NewReader(in)
	fmt.Fprintln(outw, "Let's set up a scan. Answers in [brackets] are the defaults — press Enter to accept.")
	fmt.Fprintln(outw)

	// 1. The primary host.
	host := ""
	for host == "" {
		host = sanitizeHost(ask(r, outw, "What host are you allowed to test? (e.g. example.com)", ""))
		if host == "" {
			fmt.Fprintln(outw, "  Please enter a host, or press Ctrl-C to quit.")
		}
	}

	// 2. Authorization confirmation — this is the one gate.
	if !askYesNo(r, outw, "Do you have explicit permission to test "+host+"?", false) {
		fmt.Fprintln(outw, "\nStopping. Only scan hosts you own or are authorized to test (for example,")
		fmt.Fprintln(outw, "a bug bounty program's in-scope assets). Nothing was written.")
		return "", false
	}

	// 3. Subdomains.
	wildcard := askYesNo(r, outw, "Include all of its subdomains (api."+host+", etc.)?", true)

	// 4. Extra hosts.
	extra := ask(r, outw, "Any other hosts you may test? (comma-separated, or blank)", "")

	// 5. Seed URL.
	seed := ask(r, outw, "Which page should it start from?", "https://"+host+"/")

	// 6. Mode.
	mode := ""
	for {
		mode = strings.ToLower(ask(r, outw, "Scan intensity — passive (look only), safe, or aggressive?", "safe"))
		if mode == config.ModePassive || mode == config.ModeSafe || mode == config.ModeAggressive {
			break
		}
		fmt.Fprintln(outw, "  Please type passive, safe, or aggressive.")
	}

	// Build the scope list.
	var scope []string
	scope = append(scope, host)
	if wildcard {
		scope = append(scope, "*."+host)
	}
	for _, h := range strings.Split(extra, ",") {
		if s := sanitizeHost(h); s != "" {
			scope = append(scope, s)
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# asfasf-scanner config (created by: scanner init -interactive)\n")
	fmt.Fprintf(&b, "#\n# Authorized use only. Only scan hosts you own or are permitted to test.\n")
	fmt.Fprintf(&b, "# Only in_scope and seeds are required; a useful set of checks turns on\n")
	fmt.Fprintf(&b, "# automatically. Run 'scanner init' for a fully-documented config.\n\n")
	fmt.Fprintf(&b, "mode: %s\n\n", mode)
	fmt.Fprintf(&b, "scope:\n  in_scope:\n")
	for _, h := range scope {
		fmt.Fprintf(&b, "    - %q\n", h)
	}
	fmt.Fprintf(&b, "\nseeds:\n    - %q\n", seed)

	// Echo a short summary.
	fmt.Fprintln(outw, "\nHere's what I'll write:")
	fmt.Fprintf(outw, "  Mode:     %s\n", mode)
	fmt.Fprintf(outw, "  In scope: %s\n", strings.Join(scope, ", "))
	fmt.Fprintf(outw, "  Start at: %s\n", seed)
	return b.String(), true
}

// ask prints a prompt (with an optional default) and returns the trimmed line.
func ask(r *bufio.Reader, outw io.Writer, prompt, def string) string {
	if def != "" {
		fmt.Fprintf(outw, "%s [%s]: ", prompt, def)
	} else {
		fmt.Fprintf(outw, "%s: ", prompt)
	}
	line, err := r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	if err != nil && err != io.EOF {
		return def
	}
	return line
}

// askYesNo prompts for a yes/no answer, returning def on blank input or EOF.
func askYesNo(r *bufio.Reader, outw io.Writer, prompt string, def bool) bool {
	hint := "y/N"
	if def {
		hint = "Y/n"
	}
	for {
		fmt.Fprintf(outw, "%s (%s): ", prompt, hint)
		line, err := r.ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			return true
		case "n", "no":
			return false
		case "":
			return def // blank or EOF -> default
		}
		if err != nil {
			return def
		}
	}
}

// sanitizeHost strips a pasted scheme/path and lower-cases a host.
func sanitizeHost(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(s)
}

func printSummary(rep *engine.Report) {
	c := report.Summarize(rep)
	fmt.Println()
	fmt.Println("================ SCAN SUMMARY ================")
	fmt.Printf(" Mode:            %s\n", rep.Mode)
	fmt.Printf(" Duration:        %s\n", rep.FinishedAt.Sub(rep.StartedAt).Round(1e6))
	fmt.Printf(" Pages crawled:   %d\n", rep.PagesCrawled)
	fmt.Printf(" Origins scanned: %d\n", rep.OriginsScanned)
	fmt.Printf(" Endpoints:       %d\n", len(rep.Endpoints))
	fmt.Printf(" Requests sent:   %d\n", rep.RequestsSent)
	fmt.Printf(" Out-of-scope blocked: %d\n", rep.Blocked)
	fmt.Println("---------------------------------------------")
	fmt.Printf(" Critical: %d   High: %d   Medium: %d   Low: %d   Info: %d\n",
		c.Critical, c.High, c.Medium, c.Low, c.Info)
	fmt.Println("=============================================")
	for _, f := range rep.Findings {
		fmt.Printf(" [%-8s] %s\n            %s", strings.ToUpper(string(f.Severity)), f.Title, f.URL)
		if f.Parameter != "" {
			fmt.Printf("  (param: %s)", f.Parameter)
		}
		fmt.Println()
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
