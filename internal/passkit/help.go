package passkit

// HelpText is the self-documenting operating manual returned by GET /help.
const HelpText = `passkit — agentic-first password hashing and verification service

USAGE
  All endpoints accept GET (query params) or POST (body params).
  Plain text by default. Add Accept: application/json or ?format=json for JSON.

ENDPOINTS

  GET  /help                  This help text.
  GET  /.well-known/agent.md  Same as /help (agent-discoverable).

  POST /hash/bcrypt           Hash a password with bcrypt.
       params: password (required), cost (default 12, range 4–31)
       returns: the bcrypt hash string

  POST /verify/bcrypt         Verify a password against a bcrypt hash.
       params: password (required), hash (required)
       returns: match=true or match=false

  POST /hash/scrypt           Hash a password with scrypt.
       params: password (required), N (default 32768), r (default 8), p (default 1), keylen (default 32)
       returns: the scrypt hash string ($scrypt$N=..,r=..,p=..$<salt>$<key>)

  POST /verify/scrypt         Verify a password against a scrypt hash.
       params: password (required), hash (required)
       returns: match=true or match=false

  POST /hash/hmac             Hash a password with HMAC-SHA256.
       params: password (required), key (required)
       returns: the HMAC hash string ($hmac-sha256$<salt>$<mac>)

  POST /verify/hmac           Verify a password against an HMAC-SHA256 hash.
       params: password (required), key (required), hash (required)
       returns: match=true or match=false

  POST /hash/sha512           Hash a password with SHA-512 (fast, not for password storage).
       params: password (required)
       returns: hex-encoded SHA-512 hash

  POST /verify/sha512         Verify a password against a SHA-512 hash.
       params: password (required), hash (required)
       returns: match=true or match=false

  POST /token                 Generate a cryptographically secure random token.
       params: length (default 32), encoding (hex|base64|base64url|base64raw|raw, default hex)
       returns: the token string

  POST /password              Generate a random password.
       params: length (default 16), upper (default true), lower (default true),
              digits (default true), symbols (default false)
       returns: the generated password

  POST /strength              Score password strength (0–100).
       params: password (required)
       returns: score, level, entropy, character class flags, feedback

  POST /cracktime             Estimate offline crack time.
       params: password (required), guesses_per_second (default 10000000000)
       returns: entropy, seconds, human-readable duration

  POST /identify              Identify the hash format of a given hash.
       params: hash (required)
       returns: the identified algorithm name (bcrypt, scrypt, hmac-sha256, md5, sha1, sha256, sha512, unknown)

  GET  /health                Health check.
       returns: ok

EXAMPLES

  Hash with bcrypt:
    curl -X POST 'http://localhost:7100/hash/bcrypt' -d 'password=secret&cost=12'
    → $2a$12$N9qo8uLOickgx2ZMRZoMy.MQDvVZ6m...

  Verify bcrypt:
    curl -X POST 'http://localhost:7100/verify/bcrypt' -d 'password=secret&hash=$2a$12$...'

  Generate token:
    curl -X POST 'http://localhost:7100/token' -d 'length=32&encoding=hex'

  Score password:
    curl -X POST 'http://localhost:7100/strength' -d 'password=MyP@ssw0rd!'

  Estimate crack time:
    curl -X POST 'http://localhost:7100/cracktime' -d 'password=MyP@ssw0rd!'

ERRORS
  All 4xx errors include a hint telling you what to do next.
  Example: error: password is required
           hint: provide a password parameter

AUTH
  No auth required in default mode. Use -no-auth flag to explicitly disable.

VERSION
  passkit v0.1.0 — single Go binary, zero external deps, no database.
`
