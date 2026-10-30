# Architecture

Everything is simulated: fake chain, fake tokens, fake addresses. Local only, no network calls.

```
 Browser: static/{index,history,policy,login}.html + app.js + style.css
     |  fetch (httpOnly cookie + X-CSRF-Token header)
     v
 app.py (FastAPI) ---- sqlite3: txshield.db
     |                 users, sessions, policies, analyses
     v
 engine.analyze(payload, ctx, policy)
     |
     |  decoder/decode.py      JSON tx / typed data / raw blob + abi.json
     |        |                -> plain-English lines + normalized actions[]
     |        v
     |  simulator.py           actions[] applied to a copy of the in-memory ledger
     |        |                -> before/after balances, approvals, net USD outflow
     |        v
     |  detectors/rules.py     8 detectors -> findings[] (rule, message, addresses)
     |        v
     |  policy.py              per-rule allow/warn/block, overrides, spending limit,
     |                         warn-escalation -> verdict green/amber/red + reasons
     v
 fixtures/registry.json (tokens, prices, contracts, origins, denylist)
 fixtures/wallet_history.json (balances, contacts, past activity, simulated clock)
 fixtures/txs.json (25 labeled txs)  <--  evaluate.py (precision/recall, misses)
```

## API

| Method | Path | Auth | CSRF | Purpose |
|---|---|---|---|---|
| POST | /api/register | no (rate limited) | no | create account, start session |
| POST | /api/login | no (rate limited) | no | start session |
| POST | /api/logout | yes | yes | end session |
| GET | /api/me | yes | no | username + CSRF token |
| GET | /api/fixtures | yes | no | the 25 labeled sample payloads |
| POST | /api/analyze | yes | yes | `{text}` -> verdict, summary, diff, reasons (also logged) |
| GET | /api/history | yes | no | last 100 checks |
| GET | /api/history/{id} | yes | no | one stored result |
| DELETE | /api/history | yes | yes | clear history |
| GET | /api/policy | yes | no | policy + rule metadata |
| PUT | /api/policy | yes | yes | validate and save policy |
| POST | /api/policy/reset | yes | yes | back to `policy.json` defaults |

## Input shapes

`{"origin"?, "tx": {"to", "value"?, "data"? | "call": {"fn","args"}}}`, or `{"typed_data": {"domain","primaryType","message"}}`,
or `{"raw_message": "0x.."}`. Amounts accept `123`, `"123"`, `"MAX"` or `"1.5 tETH"`. `call` is encoded to calldata, then decoded again.

## DB schema (SQLite)

```
users(id PK, username UNIQUE, pw_hash, created_at)
sessions(token_hash PK, user_id FK, csrf, expires_at)     -- only a SHA-256 of the cookie token is stored
policies(user_id PK FK, body)                             -- JSON policy, one per user
analyses(id PK, user_id FK, created_at, verdict, title, result)  -- result = full JSON response, newest 200 kept
```
