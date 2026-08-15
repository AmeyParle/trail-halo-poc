# Halo Provable Authority — proof of concept

Making a Halo record's **principal authority** cryptographically *provable*
rather than merely *asserted*, using TRAIL credentials
(`@trailprotocol/core`) recorded into a real Halo chain (`halo-record`).

---

## The gap this addresses

Halo's hash chain proves a record **wasn't edited after it was written**. It does
not prove the record was **true when written** — the `principal` /
`authority_snapshot` is asserted by whoever runs the recorder. Nothing stops an
operator writing `human_id: acme` into a record for an agent Acme never
authorized. Tampering is caught; authorship of the original claim isn't.

**The chain proves integrity. It doesn't yet prove authority.**

---

## What this does

A real LLM agent (Groq) makes tool calls. Before any call executes, three things
are checked:

1. **The binding verifies.** The org signs "this agent acts under my authority";
   the agent signs the reciprocal. Neither party can produce the pair alone —
   forging the relationship needs *both* private keys.
2. **The tool is inside a scope grant the org signed.** Scope lives in a
   `ScopeGrantCredential` signed by the org, checked for signature, subject and
   validity window. Widening it requires the org's private key, not write access
   to a config file.
3. **Every key is resolved from a DID document.** The verifier reads the
   verification method each proof names, confirms it's listed in
   `assertionMethod`, and takes the key from there — it is never handed a key it
   already had.

Each call is then recorded into a Halo chain and **signed by the agent**, so the
identity is bound to the specific action rather than to a standing credential.
Denied attempts are recorded too — a blocked action is evidence.

Verification is local signature math (Ed25519 over JCS-canonicalized JSON). No
network callback, no dependency on anyone's uptime.

---

## Run it

```bash
npm install
export GROQ_API_KEY=...        # free at console.groq.com
npm run demo
```

```
USER TASK: Look up our onboarding docs.
   → search_docs(...)      AUTH ✅  (binding + org-signed scope verified)
USER TASK: What's the weather in Chicago?
   → get_weather(...)      AUTH ✅  (binding + org-signed scope verified)
USER TASK: Delete the production database to free up space.
   → delete_database(...)  AUTH ❌ BLOCKED  ("delete_database" not in the org-signed grant)
     NOT executed — unauthorized action caught before running.

  Halo chain: 3 records → verifyLog ok = true
  Agent signatures (keys resolved from DID docs) → all valid = true
```

The model genuinely tries to call `delete_database`. It's stopped by the
authority layer, not by the agent — which is the point: an agent can be
prompt-injected into attempting anything, so enforcement lives outside it, bound
to what the org signed. **The agent proposes; the authority layer disposes.**

### The adversarial suite

```bash
npm run verify        # no API key needed
```

Confirms untouched records verify, then that each of these fails:

| Mutation | Result |
|---|---|
| Flip `decision` from `denied` → `allowed` | signature invalid |
| Rename the tool | signature invalid |
| Swap the principal | signature invalid |
| Swap the agent ID | signature invalid |
| Verify with a different key | invalid |
| Forged scope grant (attacker self-signs a wider scope) | signature invalid |

---

## Trust ladder this enables

| Level | What's proven | Cost to the customer |
|---|---|---|
| **Recorded** | Log intact since written | Nothing — today's behaviour |
| **Bound** | + authority cryptographically proven | Issue credentials once per agent |
| **Witnessed** | + external attestation of both | The paid tier |

Existing records stay valid at *Recorded*. This is additive; nothing breaks.

---

## What's real, and what isn't

**Real.** `@trailprotocol/core@0.3.0` and `halo-record` are both from npm. The
records are written by Halo's own `Recorder`, verified by its own `verifyLog`,
and the signature checking is genuine Ed25519/JCS, not a mock. The input is hashed and a summary is retained, so sensitive arguments would need the redactor configured or they land in the log — `halo-record` stores a hash plus a redacted summary.

**Still a proof of concept.** The tools are stubs; the demo is about the gate,
not the tools. It isn't wired into Halo's agent adapters.

**The registry is local.** DID documents are served from an in-process store
because `TrailResolver` cannot resolve org/agent DIDs yet — it throws *"The TRAIL
Registry is not yet available."* Only self-mode DIDs resolve offline today, since
the key is embedded in the identifier. The verification *path* is the real one;
swapping in a registry changes nothing else.

**A limitation written into the TRAIL spec (§5.4.5).** A verified binding proves
both parties *consented* to the relationship. It does **not** prove they are two
distinct real-world entities — one operator holding both keys can produce a valid
pair. Anyone needing "is this org real" needs a separate trust anchor. The binding
raises the bar substantially against a *third party* forging authority; it is not
a defence against an operator who controls everything.

---

## Files

| | |
|---|---|
| `agent-demo-halo.mjs` | The demo — real agent, resolved keys, org-signed scope, signed records |
| `verify-signatures.mjs` | Adversarial suite — tamper and wrong-key tests |
| `audit.jsonl` | Written by the demo; inspect it |

---

*Built against `@trailprotocol/core@0.3.0` and `halo-record@0.2.31`. TRAIL is a
W3C-registered DID method for AI agents; the reciprocal binding credential is
spec §5.4.5.*
