# passkit

Agentic-first password hashing and verification service. Hash passwords with bcrypt, scrypt, HMAC-SHA256, and SHA-512. Verify passwords against hashes. Generate secure tokens and passwords. Score password strength. Estimate crack time. Identify hash formats. Plain text API, agent-driven, single Go binary.

## Philosophy

- **The agent IS the interface** — No UI, no SDK. The AI agent is the user. The API is the product.
- **Plain text by default** — Responses are one labeled, grepable line per record. JSON available on demand via `Accept: application/json` or `?format=json`.
- **Instructive errors** — Every 4xx response includes a hint telling the agent what to do next.
- **Self-documenting** — `GET /help` returns a one-page operating manual.
- **Single static binary** — Go + zero external dependencies (except `golang.org/x/crypto` for bcrypt/scrypt). CGO_ENABLED=0.
- **Zero config defaults** — Runs out of the box.
- **MCP connector** — Speaks Model Context Protocol at `/mcp` for chat client integrations.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/help` | Self-documenting help text |
| GET | `/.well-known/agent.md` | Same as /help |
| GET | `/health` | Health check |
| POST | `/hash/bcrypt` | Hash password with bcrypt |
| POST | `/verify/bcrypt` | Verify password against bcrypt hash |
| POST | `/hash/scrypt` | Hash password with scrypt |
| POST | `/verify/scrypt` | Verify password against scrypt hash |
| POST | `/hash/hmac` | Hash password with HMAC-SHA256 |
| POST | `/verify/hmac` | Verify password against HMAC-SHA256 hash |
| POST | `/hash/sha512` | Hash password with SHA-512 |
| POST | `/verify/sha512` | Verify password against SHA-512 hash |
| POST | `/token` | Generate secure random token |
| POST | `/password` | Generate random password |
| POST | `/strength` | Score password strength (0–100) |
| POST | `/cracktime` | Estimate offline crack time |
| POST | `/identify` | Identify hash format |
| POST | `/mcp` | MCP JSON-RPC 2.0 endpoint |

## Usage

```bash
# Build
make build

# Run
./passkit

# Hash a password with bcrypt
curl -X POST 'http://localhost:7100/hash/bcrypt' -d 'password=secret&cost=12'

# Verify
curl -X POST 'http://localhost:7100/verify/bcrypt' -d 'password=secret&hash=$2a$12$...'

# Generate a token
curl -X POST 'http://localhost:7100/token' -d 'length=32&encoding=hex'

# Generate a password
curl -X POST 'http://localhost:7100/password' -d 'length=20&symbols=true'

# Score password strength
curl -X POST 'http://localhost:7100/strength' -d 'password=MyP@ssw0rd!'

# Estimate crack time
curl -X POST 'http://localhost:7100/cracktime' -d 'password=MyP@ssw0rd!'

# Identify a hash
curl -X POST 'http://localhost:7100/identify' -d 'hash=$2a$10$...'

# Get JSON response
curl -X POST 'http://localhost:7100/hash/bcrypt?format=json' -d 'password=secret&cost=12'
```

## MCP

The service speaks Model Context Protocol at `POST /mcp`:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"hash_bcrypt","arguments":{"password":"secret","cost":12}}}
```

13 MCP tools: `hash_bcrypt`, `verify_bcrypt`, `hash_scrypt`, `verify_scrypt`, `hash_hmac`, `verify_hmac`, `hash_sha512`, `verify_sha512`, `generate_token`, `generate_password`, `score_password`, `estimate_cracktime`, `identify_hash`.

## Configuration

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `-addr` | `PASSKIT_ADDR` | `:7100` | Listen address |
| `-no-auth` | `PASSKIT_NO_AUTH` | `false` | Disable auth (dev mode) |
| `-no-log` | `PASSKIT_NO_LOG` | `false` | Disable request logging |

## License

MIT
