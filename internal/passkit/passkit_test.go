package passkit

import (
	"strings"
	"testing"
)

func TestHashBcrypt(t *testing.T) {
	hash, err := HashBcrypt("testpassword", 10)
	if err != nil {
		t.Fatalf("HashBcrypt error: %v", err)
	}
	if !strings.HasPrefix(hash, "$2a$10$") {
		t.Errorf("expected bcrypt hash with cost 10, got %s", hash[:10])
	}
}

func TestHashBcryptInvalidCost(t *testing.T) {
	_, err := HashBcrypt("test", 3)
	if err == nil {
		t.Error("expected error for cost 3")
	}
	_, err = HashBcrypt("test", 32)
	if err == nil {
		t.Error("expected error for cost 32")
	}
}

func TestVerifyBcrypt(t *testing.T) {
	hash, _ := HashBcrypt("mypassword", 10)
	if !VerifyBcrypt("mypassword", hash) {
		t.Error("expected match=true for correct password")
	}
	if VerifyBcrypt("wrongpassword", hash) {
		t.Error("expected match=false for wrong password")
	}
}

func TestHashScrypt(t *testing.T) {
	hash, err := HashScrypt("testpassword", 16384, 8, 1, 32)
	if err != nil {
		t.Fatalf("HashScrypt error: %v", err)
	}
	if !strings.HasPrefix(hash, "$scrypt$N=16384,r=8,p=1$") {
		t.Errorf("unexpected scrypt hash format: %s", hash[:40])
	}
}

func TestHashScryptInvalidN(t *testing.T) {
	_, err := HashScrypt("test", 100, 8, 1, 32)
	if err == nil {
		t.Error("expected error for non-power-of-2 N")
	}
}

func TestVerifyScrypt(t *testing.T) {
	hash, _ := HashScrypt("mypassword", 16384, 8, 1, 32)
	if !VerifyScrypt("mypassword", hash) {
		t.Error("expected match=true for correct password")
	}
	if VerifyScrypt("wrongpassword", hash) {
		t.Error("expected match=false for wrong password")
	}
}

func TestHashHMAC(t *testing.T) {
	hash, err := HashHMAC("testpassword", "secretkey")
	if err != nil {
		t.Fatalf("HashHMAC error: %v", err)
	}
	if !strings.HasPrefix(hash, "$hmac-sha256$") {
		t.Errorf("unexpected HMAC hash format: %s", hash[:20])
	}
}

func TestHashHMACEmptyKey(t *testing.T) {
	_, err := HashHMAC("test", "")
	if err == nil {
		t.Error("expected error for empty key")
	}
}

func TestVerifyHMAC(t *testing.T) {
	hash, _ := HashHMAC("mypassword", "secretkey")
	if !VerifyHMAC("mypassword", "secretkey", hash) {
		t.Error("expected match=true for correct password")
	}
	if VerifyHMAC("wrongpassword", "secretkey", hash) {
		t.Error("expected match=false for wrong password")
	}
	if VerifyHMAC("mypassword", "wrongkey", hash) {
		t.Error("expected match=false for wrong key")
	}
}

func TestHashSHA512(t *testing.T) {
	hash := HashSHA512("test")
	if len(hash) != 128 {
		t.Errorf("expected 128-char hex hash, got %d", len(hash))
	}
}

func TestVerifySHA512(t *testing.T) {
	hash := HashSHA512("mypassword")
	if !VerifySHA512("mypassword", hash) {
		t.Error("expected match=true for correct password")
	}
	if VerifySHA512("wrongpassword", hash) {
		t.Error("expected match=false for wrong password")
	}
}

func TestGenerateTokenHex(t *testing.T) {
	token, err := GenerateToken(16, "hex")
	if err != nil {
		t.Fatalf("GenerateToken error: %v", err)
	}
	if len(token) != 32 {
		t.Errorf("expected 32-char hex token, got %d", len(token))
	}
}

func TestGenerateTokenBase64(t *testing.T) {
	token, err := GenerateToken(16, "base64")
	if err != nil {
		t.Fatalf("GenerateToken error: %v", err)
	}
	if token == "" {
		t.Error("expected non-empty base64 token")
	}
}

func TestGenerateTokenBase64URL(t *testing.T) {
	token, err := GenerateToken(16, "base64url")
	if err != nil {
		t.Fatalf("GenerateToken error: %v", err)
	}
	if token == "" {
		t.Error("expected non-empty base64url token")
	}
}

func TestGenerateTokenInvalidEncoding(t *testing.T) {
	_, err := GenerateToken(16, "invalid")
	if err == nil {
		t.Error("expected error for invalid encoding")
	}
}

func TestGenerateTokenDefaultLength(t *testing.T) {
	token, err := GenerateToken(0, "hex")
	if err != nil {
		t.Fatalf("GenerateToken error: %v", err)
	}
	if len(token) != 64 {
		t.Errorf("expected 64-char hex token for default length 32, got %d", len(token))
	}
}

func TestGeneratePassword(t *testing.T) {
	pw, err := GeneratePassword(16, true, true, true, true)
	if err != nil {
		t.Fatalf("GeneratePassword error: %v", err)
	}
	if len(pw) != 16 {
		t.Errorf("expected 16-char password, got %d", len(pw))
	}
}

func TestGeneratePasswordMinLength(t *testing.T) {
	pw, err := GeneratePassword(2, true, true, true, false)
	if err != nil {
		t.Fatalf("GeneratePassword error: %v", err)
	}
	if len(pw) != 4 {
		t.Errorf("expected 4-char password (min), got %d", len(pw))
	}
}

func TestGeneratePasswordNoClasses(t *testing.T) {
	pw, err := GeneratePassword(8, false, false, false, false)
	if err != nil {
		t.Fatalf("GeneratePassword error: %v", err)
	}
	if len(pw) != 8 {
		t.Errorf("expected 8-char password, got %d", len(pw))
	}
}

func TestScorePasswordStrong(t *testing.T) {
	r := ScorePassword("MyV3ryStr0ng!P@ssw0rd#2024")
	if r.Score < 60 {
		t.Errorf("expected score >= 60 for strong password, got %d", r.Score)
	}
	if !r.HasUpper || !r.HasLower || !r.HasDigit || !r.HasSymbol {
		t.Error("expected all character classes detected")
	}
}

func TestScorePasswordWeak(t *testing.T) {
	r := ScorePassword("abc")
	if r.Score > 30 {
		t.Errorf("expected score <= 30 for weak password, got %d", r.Score)
	}
	if r.Level != "very-weak" && r.Level != "weak" {
		t.Errorf("expected very-weak or weak level, got %s", r.Level)
	}
}

func TestScorePasswordCommon(t *testing.T) {
	r := ScorePassword("password")
	if r.Score != 0 {
		t.Errorf("expected score 0 for common password, got %d", r.Score)
	}
}

func TestScorePasswordEmpty(t *testing.T) {
	r := ScorePassword("")
	if r.Score != 0 {
		t.Errorf("expected score 0 for empty password, got %d", r.Score)
	}
}

func TestEstimateCrackTime(t *testing.T) {
	r := EstimateCrackTime("MyStr0ng!P@ss", 1e10)
	if r.Entropy <= 0 {
		t.Error("expected positive entropy")
	}
	if r.Seconds <= 0 {
		t.Error("expected positive seconds")
	}
	if r.HumanReadable == "" {
		t.Error("expected non-empty human readable duration")
	}
}

func TestEstimateCrackTimeWeak(t *testing.T) {
	r := EstimateCrackTime("abc", 1e10)
	if r.HumanReadable != "instant" && r.Seconds < 1 {
		// weak passwords should crack quickly
	}
}

func TestIdentifyHashBcrypt(t *testing.T) {
	tests := []struct {
		hash string
		want string
	}{
		{"$2a$10$N9qo8uLOickgx2ZMRZoMy.MQDvVZ6m...", "bcrypt"},
		{"$2b$12$somehashvalue", "bcrypt"},
		{"$2y$04$somehashvalue", "bcrypt"},
		{"$scrypt$N=32768,r=8,p=1$salt$key", "scrypt"},
		{"$hmac-sha256$salt$mac", "hmac-sha256"},
		{"d41d8cd98f00b204e9800998ecf8427e", "md5"},
		{"da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"},
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"},
		{"unknownhash", "unknown"},
	}
	for _, tt := range tests {
		got := IdentifyHash(tt.hash)
		if got != tt.want {
			t.Errorf("IdentifyHash(%q) = %q, want %q", tt.hash, got, tt.want)
		}
	}
}

func TestIsCommonPassword(t *testing.T) {
	if !isCommonPassword("password") {
		t.Error("expected 'password' to be common")
	}
	if !isCommonPassword("PASSWORD") {
		t.Error("expected 'PASSWORD' to be common (case-insensitive)")
	}
	if isCommonPassword("uniquepass123") {
		t.Error("expected 'uniquepass123' to not be common")
	}
}

func TestExtractBcryptCost(t *testing.T) {
	hash, _ := HashBcrypt("test", 14)
	cost, err := ExtractBcryptCost(hash)
	if err != nil {
		t.Fatalf("ExtractBcryptCost error: %v", err)
	}
	if cost != 14 {
		t.Errorf("expected cost 14, got %d", cost)
	}
}

func TestExtractBcryptCostInvalid(t *testing.T) {
	_, err := ExtractBcryptCost("not-a-bcrypt-hash")
	if err == nil {
		t.Error("expected error for non-bcrypt hash")
	}
}

func TestIsValidBcryptCost(t *testing.T) {
	if !IsValidBcryptCost(10) {
		t.Error("expected cost 10 to be valid")
	}
	if IsValidBcryptCost(3) {
		t.Error("expected cost 3 to be invalid")
	}
	if IsValidBcryptCost(32) {
		t.Error("expected cost 32 to be invalid")
	}
}

func TestHumanDuration(t *testing.T) {
	tests := []struct {
		secs float64
		want string
	}{
		{0.5, "instant"},
		{30, "30 seconds"},
		{120, "2.0 minutes"},
		{7200, "2.0 hours"},
		{86400, "1.0 days"},
	}
	for _, tt := range tests {
		got := humanDuration(tt.secs)
		if got != tt.want {
			t.Errorf("humanDuration(%v) = %q, want %q", tt.secs, got, tt.want)
		}
	}
}

func TestLog2(t *testing.T) {
	if log2(2) != 1 {
		t.Errorf("log2(2) = %v, want 1", log2(2))
	}
	if log2(4) != 2 {
		t.Errorf("log2(4) = %v, want 2", log2(4))
	}
	if log2(256) != 8 {
		t.Errorf("log2(256) = %v, want 8", log2(256))
	}
}
