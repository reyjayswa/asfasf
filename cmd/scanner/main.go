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
	"context"
	"flag"
	"fmt"
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
  scanner init  [-o scope.yaml]

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
	out := fs.String("o", "scope.yaml", "output path for the example config")
	fs.Parse(args)

	if _, err := os.Stat(*out); err == nil {
		fatal(fmt.Errorf("%s already exists; refusing to overwrite", *out))
	}
	if err := os.WriteFile(*out, []byte(exampleConfig), 0o644); err != nil {
		fatal(err)
	}
	fmt.Printf("Wrote example config to %s\n", *out)
	fmt.Println("Edit scope.in_scope and seeds before running a scan.")
}

func printSummary(rep *engine.Report) {
	c := report.Summarize(rep)
	fmt.Println()
	fmt.Println("================ SCAN SUMMARY ================")
	fmt.Printf(" Mode:            %s\n", rep.Mode)
	fmt.Printf(" Duration:        %s\n", rep.FinishedAt.Sub(rep.StartedAt).Round(1e6))
	fmt.Printf(" Pages crawled:   %d\n", rep.PagesCrawled)
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
