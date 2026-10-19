package passkit

import (
	"flag"
	"fmt"
	"os"
)

// Config holds all application configuration.
type Config struct {
	Addr     string
	NoAuth   bool
	NoLog    bool
	Version  string
}

// Default returns config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Addr:    ":7100",
		NoAuth:  false,
		NoLog:   false,
		Version: "0.1.0",
	}
}

// ParseFlags parses command-line flags and env vars.
func ParseFlags() Config {
	c := DefaultConfig()
	flag.StringVar(&c.Addr, "addr", envOr("PASSKIT_ADDR", c.Addr), "listen address")
	flag.BoolVar(&c.NoAuth, "no-auth", envOrBool("PASSKIT_NO_AUTH", c.NoAuth), "disable auth (dev mode)")
	flag.BoolVar(&c.NoLog, "no-log", envOrBool("PASSKIT_NO_LOG", c.NoLog), "disable request logging")
	flag.Parse()
	return c
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envOrBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		switch v {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
	}
	return def
}

func (c Config) String() string {
	return fmt.Sprintf("addr=%s no-auth=%v version=%s", c.Addr, c.NoAuth, c.Version)
}
