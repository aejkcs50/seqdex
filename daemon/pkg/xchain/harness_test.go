package xchain_test

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// harness brings up (and tears down) the two-chain regtest used by the
// integration test: a parent Elements node standing in for Bitcoin (the anchor
// source) plus an anchored Sequentia node. It shells out to start-regtest.sh,
// which mirrors test/functional/feature_anchor_swap_consistency.py's node args.
//
// Discovery order:
//   - If SEQDEX_XCHAIN_PARENT_RPC / SEQDEX_XCHAIN_SEQ_RPC are set, the test
//     assumes externally-managed nodes and does NOT start/stop them.
//   - Otherwise it runs the script under SEQDEX_XCHAIN_SCRIPT (or a sensible
//     default), and stops the nodes on cleanup.
//
// The test is skipped (not failed) when neither the script nor running nodes
// are available, so `go test ./...` stays green in environments without the
// elementsd binaries.
type harness struct {
	parentDir string
	seqDir    string
	parentRPC int
	seqRPC    int
	script    string
	managed   bool
}

func defaultScriptPath() string {
	if p := os.Getenv("SEQDEX_XCHAIN_SCRIPT"); p != "" {
		return p
	}
	// `go test` runs with the package dir as the working directory, so the
	// committed harness under testdata/ is found relative to here.
	return filepath.Join("testdata", "start-regtest.sh")
}

func defaultDataDir() string {
	if p := os.Getenv("SEQDEX_XCHAIN_DIR"); p != "" {
		return p
	}
	return "/tmp/seqdex-xchain-regtest"
}

func setupHarness(t *testing.T) *harness {
	t.Helper()

	// 1) Externally-managed nodes via env.
	if pr := os.Getenv("SEQDEX_XCHAIN_PARENT_RPC"); pr != "" {
		h := &harness{
			parentDir: filepath.Join(defaultDataDir(), "parent"),
			seqDir:    filepath.Join(defaultDataDir(), "seq"),
			parentRPC: atoiOr(pr, 18000),
			seqRPC:    atoiOr(os.Getenv("SEQDEX_XCHAIN_SEQ_RPC"), 18001),
			managed:   false,
		}
		return h
	}

	// 2) Boot via script.
	script := defaultScriptPath()
	if _, err := os.Stat(script); err != nil {
		t.Skipf("regtest harness script not found (%s); set SEQDEX_XCHAIN_PARENT_RPC to use running nodes", script)
	}
	out, err := exec.Command("bash", script, "up").CombinedOutput()
	if err != nil {
		t.Skipf("could not start regtest harness (%v): %s", err, out)
	}
	h := &harness{
		parentDir: filepath.Join(defaultDataDir(), "parent"),
		seqDir:    filepath.Join(defaultDataDir(), "seq"),
		parentRPC: 18000,
		seqRPC:    18001,
		script:    script,
		managed:   true,
	}
	// Parse PARENT_RPC/SEQ_RPC from script output if present.
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := sc.Text()
		if v, ok := strings.CutPrefix(line, "PARENT_RPC="); ok {
			h.parentRPC = atoiOr(v, h.parentRPC)
		}
		if v, ok := strings.CutPrefix(line, "SEQ_RPC="); ok {
			h.seqRPC = atoiOr(v, h.seqRPC)
		}
	}
	t.Cleanup(func() {
		_ = exec.Command("bash", script, "stop").Run()
	})
	return h
}

// cookie reads a node's RPC cookie (user, pass) from its datadir.
func (h *harness) cookie(t *testing.T, dir string) (string, string) {
	t.Helper()
	path := filepath.Join(dir, "elementsregtest", ".cookie")
	var data []byte
	var err error
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		data, err = os.ReadFile(path)
		if err == nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("read cookie %s: %v", path, err)
	}
	parts := strings.SplitN(strings.TrimSpace(string(data)), ":", 2)
	if len(parts) != 2 {
		t.Fatalf("malformed cookie %s", path)
	}
	return parts[0], parts[1]
}

func atoiOr(s string, def int) int {
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n); err != nil {
		return def
	}
	return n
}
