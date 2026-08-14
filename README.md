# Halo Provable Authority — proof of concept

A small demo showing how a Halo record's **principal authority** can be made
*cryptographically provable* rather than merely *asserted*, using TRAIL
reciprocal binding credentials (`@trailprotocol/core`).

## The gap this addresses

Halo's hash chain proves a record **wasn't edited after it was written**. It does
not prove the record was **true when written** — the `authority_snapshot` /
`principal` is asserted by whoever runs the recorder. Nothing stops an operator
from writing `human_id: acme` into a record for an agent Acme never authorized.
Tampering is caught; authorship of the original authority claim isn't.

So today the chain proves **integrity**. It doesn't yet prove **authority**.

## What this demo does

Attaches a **reciprocal binding credential** to a record's authority, and adds an
independent `verifyAuthority` check on top of the existing chain check:

- The **org** signs "this agent acts under my authority."
- The **agent** signs the reciprocal.
- Neither party can produce the pair alone — forging it needs *both* private keys.

Verification is local signature math (Ed25519 over JCS-canonicalized JSON) — no
network callback, no dependency on anyone's uptime. A witness or auditor verifies
from the bytes they hold.

## Run it

```bash
npm install
npm run demo
```

Output:

```
CASE 1  Valid binding                          -> PASS ✅
CASE 2  Forged authority (asserted, no binding) -> FAIL ❌ (correctly rejected)
CASE 3  Revoked binding                          -> FAIL ❌ (correctly rejected)
```

Valid authority verifies. Forged and revoked authority are caught.
**Asserted → Proven.**

## Trust ladder this enables

| Level | What's proven | Cost to the customer |
|---|---|---|
| **Recorded** | Log intact since written | Nothing — today's behavior |
| **Bound** | + authority cryptographically proven | Issue credentials once per agent |
| **Witnessed** | + external attestation of both | The paid tier |

Existing records stay valid at *Recorded*. The binding is additive; nothing breaks.

## What's real, and what isn't

**Real:** `@trailprotocol/core@0.3.0` is on npm and does the binding create/verify.
The verification here is genuine Ed25519/JCS signature checking, not a mock.

**A prototype:** this is a proof of concept against a Halo-*style* record, not a
production integration into halo-record-ts. It's meant to show the shape is right
and is cheap to throw away if it isn't.

**An honest limitation (written into the TRAIL spec, §5.4.5):** a verified binding
proves both parties *consented* to the relationship. It does **not** prove they are
two distinct real-world entities — one operator holding both keys can produce a
valid pair. Anyone needing "is this org real" needs a separate trust anchor. For
Halo, the binding raises the bar substantially against a *third party* forging
authority; it is not a defense against an operator who controls everything.

---

*Built against `@trailprotocol/core@0.3.0`. TRAIL is a W3C-registered DID method
for AI agents; the reciprocal binding credential is spec §5.4.5.*

---

## Real-agent version (`agent-demo.mjs`)

A step up from the isolated demo: a **real LLM agent** (Groq, free tier) makes
tool calls, and each call is recorded with provable authority into a
tamper-evident chain. In-scope calls execute; out-of-scope actions the agent is
lured into are **caught before running**.

```bash
export GROQ_API_KEY=your_free_key_from_console.groq.com
npm install
node agent-demo.mjs
```

The agent is authorized (via a TRAIL binding) only for read-only tools
(`search_docs`, `get_weather`). When a task tries to lure it into
`delete_database`, the authority check rejects the call — the binding is valid,
but the tool is outside the agent's authorized scope — and it never executes.

The core authority + scope + chain logic is deterministic and tested; only the
agent's tool-choice comes from the live model.
