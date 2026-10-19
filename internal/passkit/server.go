package passkit

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
)

// Server is the HTTP server for passkit.
type Server struct {
	cfg Config
	mux *http.ServeMux
}

// New creates a new server.
func New(cfg Config) *Server {
	s := &Server{cfg: cfg, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("/help", s.handleHelp)
	s.mux.HandleFunc("/.well-known/agent.md", s.handleHelp)
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/hash/bcrypt", s.handleHashBcrypt)
	s.mux.HandleFunc("/verify/bcrypt", s.handleVerifyBcrypt)
	s.mux.HandleFunc("/hash/scrypt", s.handleHashScrypt)
	s.mux.HandleFunc("/verify/scrypt", s.handleVerifyScrypt)
	s.mux.HandleFunc("/hash/hmac", s.handleHashHMAC)
	s.mux.HandleFunc("/verify/hmac", s.handleVerifyHMAC)
	s.mux.HandleFunc("/hash/sha512", s.handleHashSHA512)
	s.mux.HandleFunc("/verify/sha512", s.handleVerifySHA512)
	s.mux.HandleFunc("/token", s.handleToken)
	s.mux.HandleFunc("/password", s.handlePassword)
	s.mux.HandleFunc("/strength", s.handleStrength)
	s.mux.HandleFunc("/cracktime", s.handleCrackTime)
	s.mux.HandleFunc("/identify", s.handleIdentify)
	s.mux.HandleFunc("/mcp", s.handleMCP)
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.NoLog {
		log.Printf("%s %s %s", r.Method, r.URL.Path, r.RemoteAddr)
	}
	w.Header().Set("X-Server", "passkit")
	s.mux.ServeHTTP(w, r)
}

// ListenAndServe starts the server.
func (s *Server) ListenAndServe() error {
	log.Printf("passkit listening on %s", s.cfg.Addr)
	return http.ListenAndServe(s.cfg.Addr, s)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func isJSON(r *http.Request) bool {
	if r.Header.Get("Accept") == "application/json" {
		return true
	}
	if r.URL.Query().Get("format") == "json" {
		return true
	}
	return false
}

func getParam(r *http.Request, key string) string {
	// Try query params first
	v := r.URL.Query().Get(key)
	if v != "" {
		return v
	}
	// Try form body
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err == nil {
			if v := r.Form.Get(key); v != "" {
				return v
			}
		}
		// Try JSON body
		if r.Header.Get("Content-Type") == "application/json" {
			body, err := io.ReadAll(r.Body)
			if err == nil && len(body) > 0 {
				var m map[string]interface{}
				if json.Unmarshal(body, &m) == nil {
					if v, ok := m[key]; ok {
						return fmt.Sprintf("%v", v)
					}
				}
			}
		}
	}
	return ""
}

func getParamInt(r *http.Request, key string, def int) int {
	v := getParam(r, key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func getParamBool(r *http.Request, key string, def bool) bool {
	v := getParam(r, key)
	if v == "" {
		return def
	}
	switch strings.ToLower(v) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	}
	return def
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func (s *Server) handleHelp(w http.ResponseWriter, r *http.Request) {
	WriteText(w, http.StatusOK, HelpText)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	WriteText(w, http.StatusOK, "ok")
}

func (s *Server) handleHashBcrypt(w http.ResponseWriter, r *http.Request) {
	password := getParam(r, "password")
	if password == "" {
		WriteError(w, http.StatusBadRequest, "password is required", "provide a password parameter", isJSON(r))
		return
	}
	cost := getParamInt(r, "cost", 12)
	hash, err := HashBcrypt(password, cost)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error(), "use cost between 4 and 31", isJSON(r))
		return
	}
	if isJSON(r) {
		WriteJSON(w, http.StatusOK, fmt.Sprintf(`{"hash":%q,"algorithm":"bcrypt","cost":%d}`, hash, cost))
	} else {
		WriteText(w, http.StatusOK, hash)
	}
}

func (s *Server) handleVerifyBcrypt(w http.ResponseWriter, r *http.Request) {
	password := getParam(r, "password")
	hash := getParam(r, "hash")
	if password == "" {
		WriteError(w, http.StatusBadRequest, "password is required", "provide a password parameter", isJSON(r))
		return
	}
	if hash == "" {
		WriteError(w, http.StatusBadRequest, "hash is required", "provide a hash parameter", isJSON(r))
		return
	}
	match := VerifyBcrypt(password, hash)
	if isJSON(r) {
		WriteJSON(w, http.StatusOK, fmt.Sprintf(`{"match":%v,"algorithm":"bcrypt"}`, match))
	} else {
		WriteText(w, http.StatusOK, fmt.Sprintf("match=%v", match))
	}
}

func (s *Server) handleHashScrypt(w http.ResponseWriter, r *http.Request) {
	password := getParam(r, "password")
	if password == "" {
		WriteError(w, http.StatusBadRequest, "password is required", "provide a password parameter", isJSON(r))
		return
	}
	N := getParamInt(r, "N", 32768)
	rp := getParamInt(r, "r", 8)
	p := getParamInt(r, "p", 1)
	keyLen := getParamInt(r, "keylen", 32)
	hash, err := HashScrypt(password, N, rp, p, keyLen)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error(), "ensure N is a power of 2, r>0, p>0, keylen>0", isJSON(r))
		return
	}
	if isJSON(r) {
		WriteJSON(w, http.StatusOK, fmt.Sprintf(`{"hash":%q,"algorithm":"scrypt","N":%d,"r":%d,"p":%d,"keylen":%d}`, hash, N, rp, p, keyLen))
	} else {
		WriteText(w, http.StatusOK, hash)
	}
}

func (s *Server) handleVerifyScrypt(w http.ResponseWriter, r *http.Request) {
	password := getParam(r, "password")
	hash := getParam(r, "hash")
	if password == "" {
		WriteError(w, http.StatusBadRequest, "password is required", "provide a password parameter", isJSON(r))
		return
	}
	if hash == "" {
		WriteError(w, http.StatusBadRequest, "hash is required", "provide a hash parameter", isJSON(r))
		return
	}
	match := VerifyScrypt(password, hash)
	if isJSON(r) {
		WriteJSON(w, http.StatusOK, fmt.Sprintf(`{"match":%v,"algorithm":"scrypt"}`, match))
	} else {
		WriteText(w, http.StatusOK, fmt.Sprintf("match=%v", match))
	}
}

func (s *Server) handleHashHMAC(w http.ResponseWriter, r *http.Request) {
	password := getParam(r, "password")
	key := getParam(r, "key")
	if password == "" {
		WriteError(w, http.StatusBadRequest, "password is required", "provide a password parameter", isJSON(r))
		return
	}
	if key == "" {
		WriteError(w, http.StatusBadRequest, "key is required", "provide a key parameter (the HMAC secret key)", isJSON(r))
		return
	}
	hash, err := HashHMAC(password, key)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error(), "ensure key is not empty", isJSON(r))
		return
	}
	if isJSON(r) {
		WriteJSON(w, http.StatusOK, fmt.Sprintf(`{"hash":%q,"algorithm":"hmac-sha256"}`, hash))
	} else {
		WriteText(w, http.StatusOK, hash)
	}
}

func (s *Server) handleVerifyHMAC(w http.ResponseWriter, r *http.Request) {
	password := getParam(r, "password")
	key := getParam(r, "key")
	hash := getParam(r, "hash")
	if password == "" {
		WriteError(w, http.StatusBadRequest, "password is required", "provide a password parameter", isJSON(r))
		return
	}
	if key == "" {
		WriteError(w, http.StatusBadRequest, "key is required", "provide a key parameter", isJSON(r))
		return
	}
	if hash == "" {
		WriteError(w, http.StatusBadRequest, "hash is required", "provide a hash parameter", isJSON(r))
		return
	}
	match := VerifyHMAC(password, key, hash)
	if isJSON(r) {
		WriteJSON(w, http.StatusOK, fmt.Sprintf(`{"match":%v,"algorithm":"hmac-sha256"}`, match))
	} else {
		WriteText(w, http.StatusOK, fmt.Sprintf("match=%v", match))
	}
}

func (s *Server) handleHashSHA512(w http.ResponseWriter, r *http.Request) {
	password := getParam(r, "password")
	if password == "" {
		WriteError(w, http.StatusBadRequest, "password is required", "provide a password parameter", isJSON(r))
		return
	}
	hash := HashSHA512(password)
	if isJSON(r) {
		WriteJSON(w, http.StatusOK, fmt.Sprintf(`{"hash":%q,"algorithm":"sha512"}`, hash))
	} else {
		WriteText(w, http.StatusOK, hash)
	}
}

func (s *Server) handleVerifySHA512(w http.ResponseWriter, r *http.Request) {
	password := getParam(r, "password")
	hash := getParam(r, "hash")
	if password == "" {
		WriteError(w, http.StatusBadRequest, "password is required", "provide a password parameter", isJSON(r))
		return
	}
	if hash == "" {
		WriteError(w, http.StatusBadRequest, "hash is required", "provide a hash parameter", isJSON(r))
		return
	}
	match := VerifySHA512(password, hash)
	if isJSON(r) {
		WriteJSON(w, http.StatusOK, fmt.Sprintf(`{"match":%v,"algorithm":"sha512"}`, match))
	} else {
		WriteText(w, http.StatusOK, fmt.Sprintf("match=%v", match))
	}
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	length := getParamInt(r, "length", 32)
	encoding := getParam(r, "encoding")
	if encoding == "" {
		encoding = "hex"
	}
	token, err := GenerateToken(length, encoding)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error(), "use encoding: hex, base64, base64url, base64raw, or raw", isJSON(r))
		return
	}
	if isJSON(r) {
		WriteJSON(w, http.StatusOK, fmt.Sprintf(`{"token":%q,"length":%d,"encoding":%q}`, token, length, encoding))
	} else {
		WriteText(w, http.StatusOK, token)
	}
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	length := getParamInt(r, "length", 16)
	upper := getParamBool(r, "upper", true)
	lower := getParamBool(r, "lower", true)
	digits := getParamBool(r, "digits", true)
	symbols := getParamBool(r, "symbols", false)
	pw, err := GeneratePassword(length, upper, lower, digits, symbols)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error(), "try a different length or character set", isJSON(r))
		return
	}
	if isJSON(r) {
		WriteJSON(w, http.StatusOK, fmt.Sprintf(`{"password":%q,"length":%d,"upper":%v,"lower":%v,"digits":%v,"symbols":%v}`, pw, length, upper, lower, digits, symbols))
	} else {
		WriteText(w, http.StatusOK, pw)
	}
}

func (s *Server) handleStrength(w http.ResponseWriter, r *http.Request) {
	password := getParam(r, "password")
	if password == "" {
		WriteError(w, http.StatusBadRequest, "password is required", "provide a password parameter", isJSON(r))
		return
	}
	result := ScorePassword(password)
	if isJSON(r) {
		fb, _ := json.Marshal(result.Feedback)
		WriteJSON(w, http.StatusOK, fmt.Sprintf(`{"score":%d,"level":%q,"entropy":%.1f,"length":%d,"has_upper":%v,"has_lower":%v,"has_digit":%v,"has_symbol":%v,"feedback":%s}`,
			result.Score, result.Level, result.Entropy, result.Length, result.HasUpper, result.HasLower, result.HasDigit, result.HasSymbol, string(fb)))
	} else {
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("score=%d level=%s entropy=%.1f length=%d", result.Score, result.Level, result.Entropy, result.Length))
		sb.WriteString(fmt.Sprintf(" upper=%v lower=%v digit=%v symbol=%v", result.HasUpper, result.HasLower, result.HasDigit, result.HasSymbol))
		sb.WriteString("\nfeedback: " + strings.Join(result.Feedback, "; "))
		WriteText(w, http.StatusOK, sb.String())
	}
}

func (s *Server) handleCrackTime(w http.ResponseWriter, r *http.Request) {
	password := getParam(r, "password")
	if password == "" {
		WriteError(w, http.StatusBadRequest, "password is required", "provide a password parameter", isJSON(r))
		return
	}
	gps := getParamInt(r, "guesses_per_second", 10000000000)
	result := EstimateCrackTime(password, float64(gps))
	if isJSON(r) {
		WriteJSON(w, http.StatusOK, fmt.Sprintf(`{"entropy":%.1f,"guesses_per_second":%.0f,"seconds":%.1f,"human_readable":%q}`,
			result.Entropy, result.GuessesPerSecond, result.Seconds, result.HumanReadable))
	} else {
		WriteText(w, http.StatusOK, fmt.Sprintf("entropy=%.1f guesses_per_second=%.0f seconds=%.1f human_readable=%s",
			result.Entropy, result.GuessesPerSecond, result.Seconds, result.HumanReadable))
	}
}

func (s *Server) handleIdentify(w http.ResponseWriter, r *http.Request) {
	hash := getParam(r, "hash")
	if hash == "" {
		WriteError(w, http.StatusBadRequest, "hash is required", "provide a hash parameter", isJSON(r))
		return
	}
	algo := IdentifyHash(hash)
	if isJSON(r) {
		WriteJSON(w, http.StatusOK, fmt.Sprintf(`{"hash":%q,"algorithm":%q}`, hash, algo))
	} else {
		WriteText(w, http.StatusOK, algo)
	}
}
