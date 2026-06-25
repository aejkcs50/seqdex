package xchain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// RPC is a minimal Elements/Bitcoin JSON-RPC client over HTTP, scoped to the
// calls the swap orchestrator needs. It is intentionally self-contained (rather
// than reusing pkg/explorer/elements) so the xchain mechanism has no dependency
// on the daemon's explorer types.
type RPC struct {
	url    string
	user   string
	pass   string
	wallet string // optional -rpcwallet; appended to the path when set
	http   *http.Client
}

// NewRPC builds a client for host:port with HTTP basic auth (cookie user/pass).
func NewRPC(host string, port int, user, pass string) *RPC {
	return &RPC{
		url:  fmt.Sprintf("http://%s:%d", host, port),
		user: user,
		pass: pass,
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

// WithWallet returns a shallow copy targeting the named wallet endpoint.
func (c *RPC) WithWallet(name string) *RPC {
	cp := *c
	cp.wallet = name
	return &cp
}

type rpcReq struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      string      `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

type rpcResp struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcErr         `json:"error"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcErr) Error() string { return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message) }

// Call invokes method with positional params and unmarshals the result into
// out (if non-nil).
func (c *RPC) Call(out interface{}, method string, params ...interface{}) error {
	if params == nil {
		params = []interface{}{}
	}
	return c.do(out, method, params)
}

// CallNamed invokes method with a named-parameter object (Bitcoin/Elements
// JSON-RPC supports {"params": {...}}); used where positional args are
// awkward, e.g. sendtoaddress with a non-default assetlabel.
func (c *RPC) CallNamed(out interface{}, method string, params map[string]interface{}) error {
	return c.do(out, method, params)
}

func (c *RPC) do(out interface{}, method string, params interface{}) error {
	body, err := json.Marshal(rpcReq{JSONRPC: "1.0", ID: "xchain", Method: method, Params: params})
	if err != nil {
		return err
	}
	url := c.url
	if c.wallet != "" {
		url = url + "/wallet/" + c.wallet
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.user, c.pass)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var r rpcResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return fmt.Errorf("%s: decode response (http %d): %w", method, resp.StatusCode, err)
	}
	if r.Error != nil {
		return fmt.Errorf("%s: %w", method, r.Error)
	}
	if out != nil {
		if err := json.Unmarshal(r.Result, out); err != nil {
			return fmt.Errorf("%s: unmarshal result: %w", method, err)
		}
	}
	return nil
}
