package passkit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func setupTestServer() *httptest.Server {
	cfg := DefaultConfig()
	cfg.NoLog = true
	srv := New(cfg)
	return httptest.NewServer(srv)
}

func TestHelp(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/help")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	body := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(body, "text/plain") {
		t.Errorf("expected text/plain, got %s", body)
	}
}

func TestHealth(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestHashBcryptEndpoint(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/hash/bcrypt", "application/x-www-form-urlencoded", strings.NewReader("password=testpass&cost=10"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestHashBcryptMissingPassword(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/hash/bcrypt", "application/x-www-form-urlencoded", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestVerifyBcryptEndpoint(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	// First hash (request JSON to parse easily)
	resp, err := http.Post(ts.URL+"/hash/bcrypt?format=json", "application/x-www-form-urlencoded", strings.NewReader("password=testpass&cost=10"))
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	hash, _ := result["hash"].(string)
	if hash == "" {
		t.Fatal("expected non-empty hash from bcrypt endpoint")
	}

	// Verify correct
	resp2, err := http.Post(ts.URL+"/verify/bcrypt", "application/x-www-form-urlencoded",
		strings.NewReader("password=testpass&hash="+hash))
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}

	// Verify wrong
	resp3, err := http.Post(ts.URL+"/verify/bcrypt", "application/x-www-form-urlencoded",
		strings.NewReader("password=wrongpass&hash="+hash))
	if err != nil {
		t.Fatal(err)
	}
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp3.StatusCode)
	}
}

func TestTokenEndpoint(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader("length=16&encoding=hex"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestTokenEndpointJSON(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/token?format=json", "application/x-www-form-urlencoded", strings.NewReader("length=16&encoding=base64"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		t.Errorf("expected application/json, got %s", resp.Header.Get("Content-Type"))
	}
}

func TestPasswordEndpoint(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/password", "application/x-www-form-urlencoded", strings.NewReader("length=20&upper=true&lower=true&digits=true&symbols=true"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestStrengthEndpoint(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/strength", "application/x-www-form-urlencoded", strings.NewReader("password=MyStr0ng!P@ss"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestStrengthEndpointMissingPassword(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/strength", "application/x-www-form-urlencoded", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestCrackTimeEndpoint(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/cracktime", "application/x-www-form-urlencoded", strings.NewReader("password=MyStr0ng!P@ss"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestIdentifyEndpoint(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/identify", "application/x-www-form-urlencoded", strings.NewReader("hash=$2a$10$somehashvalue"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestHashHMACEndpoint(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/hash/hmac", "application/x-www-form-urlencoded", strings.NewReader("password=testpass&key=secretkey"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestHashHMACMissingKey(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/hash/hmac", "application/x-www-form-urlencoded", strings.NewReader("password=testpass"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestHashSHA512Endpoint(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/hash/sha512", "application/x-www-form-urlencoded", strings.NewReader("password=testpass"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestHashScryptEndpoint(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/hash/scrypt", "application/x-www-form-urlencoded", strings.NewReader("password=testpass&N=16384&r=8&p=1&keylen=32"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestMCPInitialize(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize"}`
	resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	var result MCPResponse
	json.NewDecoder(resp.Body).Decode(&result)
	if result.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %s", result.JSONRPC)
	}
}

func TestMCPToolsList(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	body := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	var result MCPResponse
	json.NewDecoder(resp.Body).Decode(&result)
	if result.Error != nil {
		t.Errorf("unexpected error: %s", result.Error.Message)
	}
}

func TestMCPToolsCallHashBcrypt(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	body := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"hash_bcrypt","arguments":{"password":"testpass","cost":10}}}`
	resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	var result MCPResponse
	json.NewDecoder(resp.Body).Decode(&result)
	if result.Error != nil {
		t.Errorf("unexpected error: %s", result.Error.Message)
	}
}

func TestMCPToolsCallGenerateToken(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	body := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"generate_token","arguments":{"length":16,"encoding":"hex"}}}`
	resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	var result MCPResponse
	json.NewDecoder(resp.Body).Decode(&result)
	if result.Error != nil {
		t.Errorf("unexpected error: %s", result.Error.Message)
	}
}

func TestMCPToolsCallScorePassword(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	body := `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"score_password","arguments":{"password":"MyStr0ng!P@ss"}}}`
	resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	var result MCPResponse
	json.NewDecoder(resp.Body).Decode(&result)
	if result.Error != nil {
		t.Errorf("unexpected error: %s", result.Error.Message)
	}
}

func TestMCPToolsCallUnknown(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	body := `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"nonexistent","arguments":{}}}`
	resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var result MCPResponse
	json.NewDecoder(resp.Body).Decode(&result)
	if result.Error == nil {
		t.Error("expected error for unknown tool")
	}
}

func TestMCPMethodNotAllowed(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}
