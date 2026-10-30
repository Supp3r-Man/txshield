# Threat model

Educational MVP. Simulated data only. Never deployed, never prod-tested.

**Protects:** a simulated wallet user from signing something harmful without understanding it.
**Trusts:** the local machine, the browser, and the fixture files (registry, history, denylist).

| Threat | In scope? | Mitigation / limit |
|---|---|---|
| Unlimited or unverified-spender approvals | yes | unlimited_approval, unverified_contract, spender_mismatch |
| Permit / Permit2 phishing signatures | yes | long-deadline and spender checks on typed data |
| Address poisoning | yes | prefix/suffix lookalike vs contacts and past recipients |
| Blind signing (opaque calldata, eth_sign) | yes | blind_signing; unknown selectors never get a "looks fine" |
| Known-bad destinations | yes | local denylist (blocks by default) |
| Overspending / drained balance | yes | state diff + large_value + spending_limit |
| Social engineering with a normal-looking transfer | no | no on-chain signal; fixtures keep it as a known miss |
| Malicious contract that behaves differently when simulated | no | the simulator models decoded actions, it does not run an EVM |
| State changing between check and signing | no | one-shot check, no re-simulation |
| Compromised host or wallet UI lying to the user | no | compare with the device screen |

**Web app:** argon2 password hashes, random session tokens stored hashed, httpOnly + SameSite=Strict cookie,
CSRF header on every write, CORS and Host locked to localhost, auth rate limit (in memory, per IP),
parameterized SQL only, pydantic/regex validation, 20k input cap, CSP, DOM built with textContent.
**Known gaps:** no HTTPS (localhost only), login has no CSRF token (SameSite covers it), rate limit resets on restart,
registration is open because it is a single-machine toy.
