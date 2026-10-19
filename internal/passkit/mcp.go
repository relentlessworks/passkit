package passkit

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// MCPRequest is a JSON-RPC 2.0 request.
type MCPRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// MCPResponse is a JSON-RPC 2.0 response.
type MCPResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *MCPError       `json:"error,omitempty"`
}

// MCPError is a JSON-RPC 2.0 error.
type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCPTool represents a tool exposed via MCP.
type MCPTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// mcpTools returns the list of available MCP tools.
func mcpTools() []MCPTool {
	return []MCPTool{
		{
			Name:        "hash_bcrypt",
			Description: "Hash a password using bcrypt. Returns the bcrypt hash string.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"password": map[string]interface{}{"type": "string", "description": "The password to hash"},
					"cost":     map[string]interface{}{"type": "integer", "description": "Bcrypt cost factor (4-31, default 12)"},
				},
				"required": []string{"password"},
			},
		},
		{
			Name:        "verify_bcrypt",
			Description: "Verify a password against a bcrypt hash. Returns match=true or match=false.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"password": map[string]interface{}{"type": "string", "description": "The password to check"},
					"hash":      map[string]interface{}{"type": "string", "description": "The bcrypt hash to verify against"},
				},
				"required": []string{"password", "hash"},
			},
		},
		{
			Name:        "hash_scrypt",
			Description: "Hash a password using scrypt. Returns the scrypt hash string.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"password": map[string]interface{}{"type": "string", "description": "The password to hash"},
					"N":        map[string]interface{}{"type": "integer", "description": "CPU/memory cost (power of 2, default 32768)"},
					"r":        map[string]interface{}{"type": "integer", "description": "Block size (default 8)"},
					"p":        map[string]interface{}{"type": "integer", "description": "Parallelization (default 1)"},
					"keylen":   map[string]interface{}{"type": "integer", "description": "Key length (default 32)"},
				},
				"required": []string{"password"},
			},
		},
		{
			Name:        "verify_scrypt",
			Description: "Verify a password against a scrypt hash. Returns match=true or match=false.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"password": map[string]interface{}{"type": "string", "description": "The password to check"},
					"hash":      map[string]interface{}{"type": "string", "description": "The scrypt hash to verify against"},
				},
				"required": []string{"password", "hash"},
			},
		},
		{
			Name:        "hash_hmac",
			Description: "Hash a password using HMAC-SHA256 with a secret key. Returns the HMAC hash string.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"password": map[string]interface{}{"type": "string", "description": "The password to hash"},
					"key":      map[string]interface{}{"type": "string", "description": "The HMAC secret key"},
				},
				"required": []string{"password", "key"},
			},
		},
		{
			Name:        "verify_hmac",
			Description: "Verify a password against an HMAC-SHA256 hash. Returns match=true or match=false.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"password": map[string]interface{}{"type": "string", "description": "The password to check"},
					"key":      map[string]interface{}{"type": "string", "description": "The HMAC secret key"},
					"hash":     map[string]interface{}{"type": "string", "description": "The HMAC hash to verify against"},
				},
				"required": []string{"password", "key", "hash"},
			},
		},
		{
			Name:        "hash_sha512",
			Description: "Hash a password using SHA-512. Fast hash, not recommended for password storage. Returns hex-encoded hash.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"password": map[string]interface{}{"type": "string", "description": "The password to hash"},
				},
				"required": []string{"password"},
			},
		},
		{
			Name:        "verify_sha512",
			Description: "Verify a password against a SHA-512 hash. Returns match=true or match=false.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"password": map[string]interface{}{"type": "string", "description": "The password to check"},
					"hash":      map[string]interface{}{"type": "string", "description": "The SHA-512 hash to verify against"},
				},
				"required": []string{"password", "hash"},
			},
		},
		{
			Name:        "generate_token",
			Description: "Generate a cryptographically secure random token.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"length":   map[string]interface{}{"type": "integer", "description": "Token length in bytes (default 32)"},
					"encoding": map[string]interface{}{"type": "string", "description": "Encoding: hex, base64, base64url, base64raw, raw (default hex)"},
				},
			},
		},
		{
			Name:        "generate_password",
			Description: "Generate a random password with configurable character classes.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"length":  map[string]interface{}{"type": "integer", "description": "Password length (default 16)"},
					"upper":   map[string]interface{}{"type": "boolean", "description": "Include uppercase letters (default true)"},
					"lower":   map[string]interface{}{"type": "boolean", "description": "Include lowercase letters (default true)"},
					"digits":  map[string]interface{}{"type": "boolean", "description": "Include digits (default true)"},
					"symbols": map[string]interface{}{"type": "boolean", "description": "Include symbols (default false)"},
				},
			},
		},
		{
			Name:        "score_password",
			Description: "Score password strength (0-100). Returns score, level, entropy, and feedback.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"password": map[string]interface{}{"type": "string", "description": "The password to score"},
				},
				"required": []string{"password"},
			},
		},
		{
			Name:        "estimate_cracktime",
			Description: "Estimate offline crack time for a password. Returns entropy, seconds, and human-readable duration.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"password":            map[string]interface{}{"type": "string", "description": "The password to analyze"},
					"guesses_per_second":   map[string]interface{}{"type": "integer", "description": "Attacker speed in guesses/sec (default 10000000000)"},
				},
				"required": []string{"password"},
			},
		},
		{
			Name:        "identify_hash",
			Description: "Identify the hash format of a given hash string. Returns the algorithm name.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"hash": map[string]interface{}{"type": "string", "description": "The hash to identify"},
				},
				"required": []string{"hash"},
			},
		},
	}
}

// handleMCP handles MCP JSON-RPC 2.0 requests.
func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteError(w, http.StatusMethodNotAllowed, "method not allowed", "use POST for MCP requests", false)
		return
	}

	var req MCPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeMCPError(w, nil, -32700, "parse error")
		return
	}

	switch req.Method {
	case "initialize":
		writeMCPResult(w, req.ID, map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
			"serverInfo": map[string]interface{}{
				"name":    "passkit",
				"version": s.cfg.Version,
			},
		})

	case "tools/list":
		writeMCPResult(w, req.ID, map[string]interface{}{
			"tools": mcpTools(),
		})

	case "tools/call":
		var params struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			writeMCPError(w, req.ID, -32602, "invalid params")
			return
		}
		result, err := s.callMCPTool(params.Name, params.Arguments)
		if err != nil {
			writeMCPError(w, req.ID, -32603, err.Error())
			return
		}
		writeMCPResult(w, req.ID, map[string]interface{}{
			"content": []map[string]interface{}{
				{"type": "text", "text": result},
			},
		})

	default:
		writeMCPError(w, req.ID, -32601, fmt.Sprintf("method %q not found", req.Method))
	}
}

func (s *Server) callMCPTool(name string, args map[string]interface{}) (string, error) {
	getStr := func(k string) string {
		if v, ok := args[k]; ok {
			return fmt.Sprintf("%v", v)
		}
		return ""
	}
	getInt := func(k string, def int) int {
		if v, ok := args[k]; ok {
			switch n := v.(type) {
			case float64:
				return int(n)
			case int:
				return n
			}
		}
		return def
	}
	getBool := func(k string, def bool) bool {
		if v, ok := args[k]; ok {
			switch b := v.(type) {
			case bool:
				return b
			}
		}
		return def
	}

	switch name {
	case "hash_bcrypt":
		pw := getStr("password")
		if pw == "" {
			return "", fmt.Errorf("password is required")
		}
		cost := getInt("cost", 12)
		h, err := HashBcrypt(pw, cost)
		if err != nil {
			return "", err
		}
		return h, nil

	case "verify_bcrypt":
		pw := getStr("password")
		h := getStr("hash")
		if pw == "" || h == "" {
			return "", fmt.Errorf("password and hash are required")
		}
		return fmt.Sprintf("match=%v", VerifyBcrypt(pw, h)), nil

	case "hash_scrypt":
		pw := getStr("password")
		if pw == "" {
			return "", fmt.Errorf("password is required")
		}
		N := getInt("N", 32768)
		r := getInt("r", 8)
		p := getInt("p", 1)
		kl := getInt("keylen", 32)
		h, err := HashScrypt(pw, N, r, p, kl)
		if err != nil {
			return "", err
		}
		return h, nil

	case "verify_scrypt":
		pw := getStr("password")
		h := getStr("hash")
		if pw == "" || h == "" {
			return "", fmt.Errorf("password and hash are required")
		}
		return fmt.Sprintf("match=%v", VerifyScrypt(pw, h)), nil

	case "hash_hmac":
		pw := getStr("password")
		key := getStr("key")
		if pw == "" || key == "" {
			return "", fmt.Errorf("password and key are required")
		}
		h, err := HashHMAC(pw, key)
		if err != nil {
			return "", err
		}
		return h, nil

	case "verify_hmac":
		pw := getStr("password")
		key := getStr("key")
		h := getStr("hash")
		if pw == "" || key == "" || h == "" {
			return "", fmt.Errorf("password, key, and hash are required")
		}
		return fmt.Sprintf("match=%v", VerifyHMAC(pw, key, h)), nil

	case "hash_sha512":
		pw := getStr("password")
		if pw == "" {
			return "", fmt.Errorf("password is required")
		}
		return HashSHA512(pw), nil

	case "verify_sha512":
		pw := getStr("password")
		h := getStr("hash")
		if pw == "" || h == "" {
			return "", fmt.Errorf("password and hash are required")
		}
		return fmt.Sprintf("match=%v", VerifySHA512(pw, h)), nil

	case "generate_token":
		length := getInt("length", 32)
		enc := getStr("encoding")
		if enc == "" {
			enc = "hex"
		}
		t, err := GenerateToken(length, enc)
		if err != nil {
			return "", err
		}
		return t, nil

	case "generate_password":
		length := getInt("length", 16)
		upper := getBool("upper", true)
		lower := getBool("lower", true)
		digits := getBool("digits", true)
		symbols := getBool("symbols", false)
		pw, err := GeneratePassword(length, upper, lower, digits, symbols)
		if err != nil {
			return "", err
		}
		return pw, nil

	case "score_password":
		pw := getStr("password")
		if pw == "" {
			return "", fmt.Errorf("password is required")
		}
		r := ScorePassword(pw)
		return fmt.Sprintf("score=%d level=%s entropy=%.1f length=%d upper=%v lower=%v digit=%v symbol=%v feedback=%s",
			r.Score, r.Level, r.Entropy, r.Length, r.HasUpper, r.HasLower, r.HasDigit, r.HasSymbol,
			joinStrings(r.Feedback, "; ")), nil

	case "estimate_cracktime":
		pw := getStr("password")
		if pw == "" {
			return "", fmt.Errorf("password is required")
		}
		gps := float64(getInt("guesses_per_second", 10000000000))
		r := EstimateCrackTime(pw, gps)
		return fmt.Sprintf("entropy=%.1f guesses_per_second=%.0f seconds=%.1f human_readable=%s",
			r.Entropy, r.GuessesPerSecond, r.Seconds, r.HumanReadable), nil

	case "identify_hash":
		h := getStr("hash")
		if h == "" {
			return "", fmt.Errorf("hash is required")
		}
		return IdentifyHash(h), nil

	default:
		return "", fmt.Errorf("unknown tool %q", name)
	}
}

func joinStrings(ss []string, sep string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}

func writeMCPResult(w http.ResponseWriter, id json.RawMessage, result interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(MCPResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	})
}

func writeMCPError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(MCPResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &MCPError{Code: code, Message: msg},
	})
}
