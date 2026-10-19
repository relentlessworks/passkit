package passkit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

// ---------------------------------------------------------------------------
// Password hashing
// ---------------------------------------------------------------------------

// HashBcrypt hashes a password using bcrypt with the given cost (4–31).
func HashBcrypt(password string, cost int) (string, error) {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return "", fmt.Errorf("cost must be %d–%d, got %d", bcrypt.MinCost, bcrypt.MaxCost, cost)
	}
	b, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// VerifyBcrypt checks a password against a bcrypt hash.
func VerifyBcrypt(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// HashScrypt hashes a password using scrypt with the given parameters.
func HashScrypt(password string, N, r, p, keyLen int) (string, error) {
	if N <= 0 || N&(N-1) != 0 {
		return "", fmt.Errorf("N must be a power of 2, got %d", N)
	}
	if r <= 0 {
		return "", fmt.Errorf("r must be > 0, got %d", r)
	}
	if p <= 0 {
		return "", fmt.Errorf("p must be > 0, got %d", p)
	}
	if keyLen <= 0 {
		return "", fmt.Errorf("keyLen must be > 0, got %d", keyLen)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk, err := scrypt.Key([]byte(password), salt, N, r, p, keyLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("$scrypt$N=%d,r=%d,p=%d$%s$%s",
		N, r, p,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(dk)), nil
}

// VerifyScrypt checks a password against a scrypt hash.
func VerifyScrypt(password, hash string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 5 || parts[1] != "scrypt" {
		return false
	}
	params := strings.Split(parts[2], ",")
	if len(params) != 3 {
		return false
	}
	var N, r, p int
	for _, param := range params {
		kv := strings.SplitN(param, "=", 2)
		if len(kv) != 2 {
			return false
		}
		switch kv[0] {
		case "N":
			N, _ = strconv.Atoi(kv[1])
		case "r":
			r, _ = strconv.Atoi(kv[1])
		case "p":
			p, _ = strconv.Atoi(kv[1])
		}
	}
	salt, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	expected, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	dk, err := scrypt.Key([]byte(password), salt, N, r, p, len(expected))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(dk, expected) == 1
}

// ---------------------------------------------------------------------------
// HMAC-based hashing (PBKDF2-style using HMAC-SHA256)
// ---------------------------------------------------------------------------

// HashHMAC hashes a password using HMAC-SHA256 with a random salt.
func HashHMAC(password, key string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("key must not be empty")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(salt)
	mac.Write([]byte(password))
	dk := mac.Sum(nil)
	return fmt.Sprintf("$hmac-sha256$%s$%s",
		hex.EncodeToString(salt),
		hex.EncodeToString(dk)), nil
}

// VerifyHMAC checks a password against an HMAC-SHA256 hash.
func VerifyHMAC(password, key, hash string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[1] != "hmac-sha256" {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	expected, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(salt)
	mac.Write([]byte(password))
	dk := mac.Sum(nil)
	return hmac.Equal(dk, expected)
}

// ---------------------------------------------------------------------------
// Token generation
// ---------------------------------------------------------------------------

// GenerateToken generates a cryptographically secure random token.
func GenerateToken(length int, encoding string) (string, error) {
	if length <= 0 {
		length = 32
	}
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	switch encoding {
	case "", "hex":
		return hex.EncodeToString(b), nil
	case "base64":
		return base64.StdEncoding.EncodeToString(b), nil
	case "base64url":
		return base64.URLEncoding.EncodeToString(b), nil
	case "base64raw":
		return base64.RawURLEncoding.EncodeToString(b), nil
	case "raw":
		return string(b), nil
	default:
		return "", fmt.Errorf("unknown encoding %q — use hex, base64, base64url, base64raw, or raw", encoding)
	}
}

// GeneratePassword generates a random password with configurable character classes.
func GeneratePassword(length int, upper, lower, digits, symbols bool) (string, error) {
	if length < 4 {
		length = 4
	}
	var pool string
	if upper {
		pool += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	if lower {
		pool += "abcdefghijklmnopqrstuvwxyz"
	}
	if digits {
		pool += "0123456789"
	}
	if symbols {
		pool += "!@#$%^&*()-_=+[]{}<>?"
	}
	if pool == "" {
		pool = "abcdefghijklmnopqrstuvwxyz"
	}
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(pool))))
		if err != nil {
			return "", err
		}
		result[i] = pool[idx.Int64()]
	}
	return string(result), nil
}

// ---------------------------------------------------------------------------
// Password strength scoring
// ---------------------------------------------------------------------------

// StrengthResult holds the result of a password strength analysis.
type StrengthResult struct {
	Score     int    // 0–100
	Level     string // very-weak, weak, fair, good, strong, very-strong
	Entropy   float64
	Length    int
	HasUpper  bool
	HasLower  bool
	HasDigit  bool
	HasSymbol bool
	Feedback  []string
}

// ScorePassword analyzes password strength and returns a score 0–100.
func ScorePassword(password string) StrengthResult {
	r := StrengthResult{Length: len(password)}

	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			r.HasUpper = true
		case unicode.IsLower(c):
			r.HasLower = true
		case unicode.IsDigit(c):
			r.HasDigit = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			r.HasSymbol = true
		}
	}

	// Calculate entropy
	poolSize := 0
	if r.HasLower {
		poolSize += 26
	}
	if r.HasUpper {
		poolSize += 26
	}
	if r.HasDigit {
		poolSize += 10
	}
	if r.HasSymbol {
		poolSize += 32
	}
	if poolSize == 0 {
		poolSize = 1
	}
	r.Entropy = float64(r.Length) * (log2(poolSize))

	// Score
	r.Score = 0
	if r.Length >= 8 {
		r.Score += 10
	}
	if r.Length >= 12 {
		r.Score += 10
	}
	if r.Length >= 16 {
		r.Score += 10
	}
	if r.Length >= 20 {
		r.Score += 10
	}
	if r.HasLower {
		r.Score += 5
	}
	if r.HasUpper {
		r.Score += 10
	}
	if r.HasDigit {
		r.Score += 10
	}
	if r.HasSymbol {
		r.Score += 15
	}
	// Entropy bonus
	if r.Entropy >= 60 {
		r.Score += 10
	}
	if r.Entropy >= 100 {
		r.Score += 10
	}
	// Penalties
	if r.Length < 8 {
		r.Score -= 20
		r.Feedback = append(r.Feedback, "Use at least 8 characters")
	}
	if !r.HasUpper {
		r.Score -= 5
		r.Feedback = append(r.Feedback, "Add uppercase letters")
	}
	if !r.HasDigit {
		r.Score -= 5
		r.Feedback = append(r.Feedback, "Add digits")
	}
	if !r.HasSymbol {
		r.Score -= 5
		r.Feedback = append(r.Feedback, "Add symbols for stronger passwords")
	}
	// Common password penalty
	if isCommonPassword(password) {
		r.Score = 0
		r.Feedback = append(r.Feedback, "This is a commonly used password — choose something unique")
	}

	if r.Score < 0 {
		r.Score = 0
	}
	if r.Score > 100 {
		r.Score = 100
	}

	switch {
	case r.Score < 20:
		r.Level = "very-weak"
	case r.Score < 40:
		r.Level = "weak"
	case r.Score < 60:
		r.Level = "fair"
	case r.Score < 75:
		r.Level = "good"
	case r.Score < 90:
		r.Level = "strong"
	default:
		r.Level = "very-strong"
	}

	if len(r.Feedback) == 0 {
		r.Feedback = append(r.Feedback, "Password looks good")
	}

	return r
}

func log2(n int) float64 {
	if n <= 0 {
		return 0
	}
	bits := 0
	for n > 1 {
		n >>= 1
		bits++
	}
	return float64(bits)
}

// ---------------------------------------------------------------------------
// Crack time estimation
// ---------------------------------------------------------------------------

// CrackTime estimates how long it would take to crack a password.
type CrackTime struct {
	Entropy          float64
	GuessesPerSecond float64
	Seconds          float64
	HumanReadable    string
}

// EstimateCrackTime estimates offline crack time at a given guesses/sec rate.
func EstimateCrackTime(password string, guessesPerSecond float64) CrackTime {
	if guessesPerSecond <= 0 {
		guessesPerSecond = 1e10 // 10 billion/sec — typical offline GPU attack
	}
	r := ScorePassword(password)
	guesses := pow2(r.Entropy)
	seconds := guesses / guessesPerSecond
	return CrackTime{
		Entropy:          r.Entropy,
		GuessesPerSecond: guessesPerSecond,
		Seconds:          seconds,
		HumanReadable:    humanDuration(seconds),
	}
}

func pow2(exp float64) float64 {
	result := 1.0
	for i := 0; i < int(exp); i++ {
		result *= 2
	}
	return result
}

func humanDuration(seconds float64) string {
	if seconds < 1 {
		return "instant"
	}
	units := []struct {
		name   string
		secs   float64
	}{
		{"year", 365.25 * 24 * 3600},
		{"day", 24 * 3600},
		{"hour", 3600},
		{"minute", 60},
		{"second", 1},
	}
	for _, u := range units {
		v := seconds / u.secs
		if v >= 1 {
			if v >= 1e9 {
				return "billions of years"
			}
			if v >= 1e6 {
				return "millions of years"
			}
			if v >= 1e3 {
				return fmt.Sprintf("%.0f %ss", v, u.name)
			}
			if v >= 100 {
				return fmt.Sprintf("%.0f %ss", v, u.name)
			}
			if v >= 10 {
				return fmt.Sprintf("%.0f %ss", v, u.name)
			}
			return fmt.Sprintf("%.1f %ss", v, u.name)
		}
	}
	return fmt.Sprintf("%.1f seconds", seconds)
}

// ---------------------------------------------------------------------------
// Common password detection
// ---------------------------------------------------------------------------

var commonPasswords = map[string]bool{
	"password": true, "123456": true, "12345678": true, "qwerty": true,
	"abc123": true, "monkey": true, "1234567": true, "letmein": true,
	"trustno1": true, "dragon": true, "baseball": true, "iloveyou": true,
	"master": true, "sunshine": true, "ashley": true, "bailey": true,
	"shadow": true, "123123": true, "654321": true, "superman": true,
	"qazwsx": true, "michael": true, "football": true, "password1": true,
	"password123": true, "admin": true, "welcome": true, "hello": true,
	"login": true, "passw0rd": true, "root": true, "toor": true,
	"111111": true, "000000": true, "123456789": true, "1234567890": true,
}

func isCommonPassword(password string) bool {
	return commonPasswords[strings.ToLower(password)]
}

// ---------------------------------------------------------------------------
// Hash identification
// ---------------------------------------------------------------------------

// IdentifyHash tries to identify the hash format.
func IdentifyHash(hash string) string {
	hash = strings.TrimSpace(hash)
	switch {
	case strings.HasPrefix(hash, "$2a$"), strings.HasPrefix(hash, "$2b$"), strings.HasPrefix(hash, "$2y$"):
		return "bcrypt"
	case strings.HasPrefix(hash, "$scrypt$"):
		return "scrypt"
	case strings.HasPrefix(hash, "$hmac-sha256$"):
		return "hmac-sha256"
	case strings.HasPrefix(hash, "$argon2"):
		return "argon2"
	case len(hash) == 32 && isHex(hash):
		return "md5"
	case len(hash) == 40 && isHex(hash):
		return "sha1"
	case len(hash) == 64 && isHex(hash):
		return "sha256"
	case len(hash) == 128 && isHex(hash):
		return "sha512"
	case len(hash) == 24 && isBase64(hash):
		return "base64-16"
	default:
		return "unknown"
	}
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func isBase64(s string) bool {
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// SHA-512 hashing (for comparison / legacy)
// ---------------------------------------------------------------------------

// HashSHA512 returns the hex-encoded SHA-512 hash of a password.
func HashSHA512(password string) string {
	h := sha512.Sum512([]byte(password))
	return hex.EncodeToString(h[:])
}

// VerifySHA512 checks a password against a SHA-512 hash.
func VerifySHA512(password, hash string) bool {
	return HashSHA512(password) == hash
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// IsValidBcryptCost returns true if cost is a valid bcrypt cost.
func IsValidBcryptCost(cost int) bool {
	return cost >= bcrypt.MinCost && cost <= bcrypt.MaxCost
}

// ExtractBcryptCost extracts the cost from a bcrypt hash.
func ExtractBcryptCost(hash string) (int, error) {
	re := regexp.MustCompile(`^\$2[aby]\$(\d{2})\$`)
	m := re.FindStringSubmatch(hash)
	if m == nil {
		return 0, fmt.Errorf("not a valid bcrypt hash")
	}
	return strconv.Atoi(m[1])
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

// WriteText writes a plain text response.
func WriteText(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	fmt.Fprintln(w, body)
}

// WriteJSON writes a JSON response.
func WriteJSON(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprint(w, body)
}

// WriteError writes an instructive error response.
func WriteError(w http.ResponseWriter, code int, msg, hint string, jsonMode bool) {
	if jsonMode {
		WriteJSON(w, code, fmt.Sprintf(`{"error":%q,"hint":%q}`, msg, hint))
	} else {
		WriteText(w, code, fmt.Sprintf("error: %s\nhint: %s", msg, hint))
	}
}
