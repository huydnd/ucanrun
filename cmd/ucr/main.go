// Command ucr is the ucanrun credential broker: agents ask for an action, a
// human approves it, and the server runs it without showing the secret.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/huydnd/ucanrun/internal/audit"
	"github.com/huydnd/ucanrun/internal/client"
	"github.com/huydnd/ucanrun/internal/core"
	"github.com/huydnd/ucanrun/internal/mcp"
	"github.com/huydnd/ucanrun/internal/vault"
	"github.com/huydnd/ucanrun/internal/web"
)

var version = "0.1.0"

const usage = `ucr: credential broker with human approval

Server, on the machine that holds the data directory:
  ucr serve                 run the web UI and agent API
  ucr add NAME              add or replace a secret (stdin, or a hidden prompt)
  ucr list                  list secret names
  ucr rm NAME               delete a secret
  ucr audit-verify          check the audit log chain
  ucr gate                  print the web access code
  ucr health                exit 0 if the server answers

Agent:
  ucr profiles              list permitted actions
  ucr run PROFILE [k=v...]  request an action (--reason "text")
  ucr mcp                   stdio MCP server

Environment: UCANRUN_PUBLIC_URL, UCANRUN_GATE_TOKEN, UCANRUN_GATE=off,
UCANRUN_ENABLE_EXEC=1, UCANRUN_DATA, UCANRUN_WEB_ADDR, UCANRUN_AGENT_ADDR,
UCANRUN_APPROVAL_TTL, UCANRUN_URL, UCANRUN_TOKEN
`

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func dataDir() string {
	if d := os.Getenv("UCANRUN_DATA"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "ucanrun")
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "ucr:", err)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = serve()
	case "add":
		err = add(args)
	case "list":
		err = list()
	case "rm":
		if len(args) != 1 {
			err = errors.New("usage: ucr rm NAME")
		} else {
			err = vault.New(filepath.Join(dataDir(), "vault")).Delete(args[0])
		}
	case "health":
		err = health()
	case "gate":
		var tok string
		tok, _, err = web.LoadGateToken(dataDir(), os.Getenv("UCANRUN_GATE_TOKEN"))
		if err == nil {
			fmt.Println(tok)
		}
	case "audit-verify":
		var n int
		n, err = audit.Verify(filepath.Join(dataDir(), "audit.jsonl"))
		if err == nil {
			fmt.Printf("OK: %d entries\n", n)
		}
	case "profiles":
		err = profiles()
	case "run":
		err = run(args)
	case "mcp":
		var c *client.Client
		if c, err = client.FromEnv(); err == nil {
			err = mcp.Serve(context.Background(), os.Stdin, os.Stdout, c)
		}
	case "version", "--version":
		fmt.Println("ucr", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Print(usage)
		os.Exit(2)
	}
	if err != nil {
		die(err)
	}
}

func serve() error {
	ttl, err := time.ParseDuration(env("UCANRUN_APPROVAL_TTL", "2m"))
	if err != nil {
		return err
	}
	dir := dataDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	c, err := core.New(core.Options{DataDir: dir, ApprovalTTL: ttl, TelegramAPI: os.Getenv("UCANRUN_TELEGRAM_API"),
		AllowExec: os.Getenv("UCANRUN_ENABLE_EXEC") == "1"})
	if err != nil {
		return err
	}
	defer c.Close()
	setup := ""
	if !c.Vault.Initialized() {
		b := make([]byte, 16)
		rand.Read(b)
		setup = hex.EncodeToString(b)
		// Goes to stdout, not the audit log, and stops working after setup.
		fmt.Printf("ucanrun chưa khởi tạo. Setup token: %s\n", setup)
	}
	public, err := publicURL()
	if err != nil {
		return err
	}
	s := web.New(c, setup, filepath.Join(dir, "audit.jsonl"), strings.HasPrefix(public, "https://"))
	if os.Getenv("UCANRUN_GATE") == "off" {
		slog.Warn("UCANRUN_GATE=off: the web UI has no access gate")
	} else {
		tok, created, err := web.LoadGateToken(dir, os.Getenv("UCANRUN_GATE_TOKEN"))
		if err != nil {
			return err
		}
		s.GateToken = tok
		// Shown until setup finishes, so a restart mid-setup does not lose it.
		if created || setup != "" {
			fmt.Printf("Mã truy cập: %s\n", tok)
		}
	}
	if setup != "" {
		fmt.Printf("Mở %s để khởi tạo. Xem lại mã bằng: ucr gate\n", public)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	harden()
	mk := func(addr string, h http.Handler) *http.Server {
		return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 130 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10}
	}
	webSrv := mk(env("UCANRUN_WEB_ADDR", "127.0.0.1:8780"), s.Handler())
	agentSrv := mk(env("UCANRUN_AGENT_ADDR", "127.0.0.1:8781"), s.AgentHandler())
	errc := make(chan error, 2)
	for _, srv := range []*http.Server{webSrv, agentSrv} {
		l, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			return err
		}
		slog.Info("listening", "addr", srv.Addr)
		go func() { errc <- srv.Serve(l) }()
	}
	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	sc, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	webSrv.Shutdown(sc)
	agentSrv.Shutdown(sc)
	return nil
}

// harden keeps keys out of core files and away from same-uid processes.
func harden() {
	const prSetDumpable = 4
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0); e != 0 {
		slog.Warn("could not disable dumps", "err", e)
	}
	syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})
}

// publicURL returns the address people use, which also decides cookie security.
func publicURL() (string, error) {
	v := strings.TrimRight(os.Getenv("UCANRUN_PUBLIC_URL"), "/")
	if v == "" {
		_, port, err := net.SplitHostPort(env("UCANRUN_WEB_ADDR", "127.0.0.1:8780"))
		if err != nil {
			return "", err
		}
		return "http://127.0.0.1:" + port, nil
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", errors.New("UCANRUN_PUBLIC_URL must look like https://ucanrun.example.com")
	}
	return v, nil
}

// health is the container health check. The default image has no shell or wget.
func health() error {
	_, port, err := net.SplitHostPort(env("UCANRUN_WEB_ADDR", "127.0.0.1:8780"))
	if err != nil {
		return err
	}
	cl := &http.Client{Timeout: 3 * time.Second}
	resp, err := cl.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func add(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: ucr add NAME")
	}
	if strings.HasPrefix(args[0], "_") {
		return vault.ErrInvalidName
	}
	var val []byte
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Giá trị (ẩn): ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		val = b
	} else {
		line, err := bufio.NewReader(os.Stdin).ReadBytes('\n')
		if err != nil && len(line) == 0 {
			return err
		}
		val = []byte(strings.TrimRight(string(line), "\r\n"))
	}
	return vault.New(filepath.Join(dataDir(), "vault")).Put(args[0], val)
}

func list() error {
	l, err := vault.New(filepath.Join(dataDir(), "vault")).List()
	if err != nil {
		return err
	}
	for _, m := range l {
		fmt.Printf("%s\t%s\n", m.Name, m.Updated.Format(time.RFC3339))
	}
	return nil
}

func printJSON(v any) {
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	e.Encode(v)
}

func profiles() error {
	c, err := client.FromEnv()
	if err != nil {
		return err
	}
	v, err := c.Profiles(context.Background())
	if err != nil {
		return err
	}
	printJSON(v)
	return nil
}

func run(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: ucr run PROFILE [k=v...] [--reason text]")
	}
	profile, params, reason := args[0], map[string]string{}, ""
	for i := 1; i < len(args); i++ {
		if args[i] == "--reason" && i+1 < len(args) {
			i++
			reason = args[i]
			continue
		}
		k, v, ok := strings.Cut(args[i], "=")
		if !ok {
			return fmt.Errorf("param %q must be k=v", args[i])
		}
		params[k] = v
	}
	c, err := client.FromEnv()
	if err != nil {
		return err
	}
	r, err := c.Run(context.Background(), profile, params, reason, 110)
	if err != nil {
		return err
	}
	printJSON(r)
	if r["state"] != "done" {
		os.Exit(1)
	}
	return nil
}
