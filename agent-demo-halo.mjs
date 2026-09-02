// ---------------------------------------------------------------------------
// Halo Provable-Authority — real agent, provable authority, signed records
//
// A real LLM agent (Groq) makes tool calls. Before any call executes:
//   1. the org<->agent binding is verified,
//   2. the requested tool is checked against a scope grant the ORG signed,
//   3. all keys are resolved from DID documents — never handed to the verifier.
// Every call is then recorded into a real Halo chain and signed by the agent,
// so the identity is bound to the action, not just to a standing credential.
//
// Run:
//   export GROQ_API_KEY=...      (free at console.groq.com)
//   node agent-demo-halo.mjs
// ---------------------------------------------------------------------------

import {
  generateKeyPair, createOrgDid, createAgentDid, createDidDocument,
  createBindingProofCredential, verifyBindingProof,
  createProof, verifyProof,
} from "@trailprotocol/core";
import { Recorder, build, verifyLog } from "halo-record";
import { existsSync, unlinkSync, readFileSync } from "fs";

const GROQ_API_KEY = process.env.GROQ_API_KEY;
const GROQ_MODEL   = "llama-3.3-70b-versatile";
const LOG_PATH     = "./audit.jsonl";

// ── Identities ─────────────────────────────────────────────────────────────
// createOrgDid/createAgentDid take publicKeyMultibase (a string), not the
// keypair object — passing the object hashes "slug:[object Object]", which
// makes every DID from the same slug collide regardless of key.
const orgKeys   = generateKeyPair();
const orgDid    = createOrgDid("acme.com", orgKeys.publicKeyMultibase);
const orgDoc    = createDidDocument(orgDid, orgKeys);

const agentKeys = generateKeyPair();
const agentDid  = createAgentDid("supportbot.acme.com", agentKeys.publicKeyMultibase);
const agentDoc  = createDidDocument(agentDid, agentKeys);

orgDoc.alsoKnownAs   = [agentDid];
agentDoc.alsoKnownAs = [orgDid];

// ── Resolution ─────────────────────────────────────────────────────────────
// Stands in for the TRAIL Registry, which can't resolve org/agent DIDs yet
// (TrailResolver throws: "The TRAIL Registry is not yet available"). The
// verification path is the real one: a proof names a verification method, the
// verifier resolves the DID document, confirms the method is authorized for
// assertion, and takes the key from there.
const REGISTRY = { [orgDid]: orgDoc, [agentDid]: agentDoc };

function resolveKey(did, verificationMethodId) {
  const doc = REGISTRY[did];
  if (!doc) throw new Error(`cannot resolve ${did}`);
  const vm = (doc.verificationMethod || []).find(v => v.id === verificationMethodId);
  if (!vm) throw new Error(`no verification method ${verificationMethodId}`);
  if (!(doc.assertionMethod || []).includes(verificationMethodId))
    throw new Error(`${verificationMethodId} not authorized for assertion`);
  return new Uint8Array(Buffer.from(vm.publicKeyJwk.x, "base64url"));
}

const validFrom  = new Date().toISOString();
const validUntil = new Date(Date.now() + 90 * 864e5).toISOString();

// ── The binding: org and agent each sign, neither can forge alone ──────────
const statusEntry = (did, i) => ({
  id: `${did}#status-${i}`, type: "StatusList2021Entry",
  statusPurpose: "revocation", statusListIndex: String(i),
  statusListCredential: `${did}/status/list`,
});

const binding = {
  orgLeg: createBindingProofCredential({
    issuerDid: orgDid, subjectDid: agentDid, privateKeyBytes: orgKeys.privateKeyBytes,
    credentialStatus: statusEntry(orgDid, 1), validFrom, validUntil }),
  agentLeg: createBindingProofCredential({
    issuerDid: agentDid, subjectDid: orgDid, privateKeyBytes: agentKeys.privateKeyBytes,
    credentialStatus: statusEntry(agentDid, 1), validFrom, validUntil }),
};

// ── The scope grant: what the agent may do, signed by the org ──────────────
// Scope lives inside a credential the org signs, so widening it requires the
// org's private key — not write access to a config file.
function issueScopeGrant(tools) {
  const doc = {
    "@context": ["https://www.w3.org/ns/credentials/v2",
                 "https://trailprotocol.org/ns/credentials/v1"],
    type: ["VerifiableCredential", "ScopeGrantCredential"],
    issuer: orgDid, validFrom, validUntil,
    credentialSubject: { id: agentDid, authorizedTools: tools },
  };
  return { ...doc, proof: createProof(
    doc, orgKeys.privateKeyBytes, `${orgDid}#key-1`, "assertionMethod") };
}
const scopeGrant = issueScopeGrant(["search_docs", "get_weather"]);

// ── Authorization: the gate every tool call passes through ─────────────────
function verifyAuthority(toolName, bind, grant) {
  if (!bind)  return { proven: false, reason: "no binding (asserted only)" };
  if (!grant) return { proven: false, reason: "no scope grant" };

  const res = verifyBindingProof({
    trailCredential: bind.agentLeg, foreignCredential: bind.orgLeg,
    trailDidDocument: agentDoc,     foreignDidDocument: orgDoc,
    trailPublicKeyBytes:   resolveKey(agentDid, `${agentDid}#key-1`),
    foreignPublicKeyBytes: resolveKey(orgDid,   `${orgDid}#key-1`),
    revocation: { trailCredentialRevoked: false, foreignCredentialRevoked: false },
  });
  if (!res.verified) return { proven: false, reason: "binding invalid: " + res.errors.join("; ") };

  const { proof, ...grantDoc } = grant;
  if (grantDoc.issuer !== orgDid)
    return { proven: false, reason: "scope grant not issued by the bound org" };
  const issuerKey = resolveKey(grantDoc.issuer, proof.verificationMethod);
  if (!verifyProof(grantDoc, proof, issuerKey))
    return { proven: false, reason: "scope grant signature invalid" };
  if (grantDoc.credentialSubject.id !== agentDid)
    return { proven: false, reason: "scope grant issued to a different agent" };
  const now = new Date();
  if (now < new Date(grantDoc.validFrom) || now > new Date(grantDoc.validUntil))
    return { proven: false, reason: "scope grant outside validity window" };
  if (!grantDoc.credentialSubject.authorizedTools.includes(toolName))
    return { proven: false, reason: `"${toolName}" not in the org-signed grant` };

  return { proven: true, reason: "binding + org-signed scope verified" };
}

// ── Tools (stubs — the demo is about the gate, not the tools) ──────────────
const TOOLS = {
  search_docs:     ({ query }) => `3 docs found for "${query}"`,
  get_weather:     ({ city })  => `Weather in ${city}: 72F, sunny`,
  delete_database: ()          => `!!! DESTRUCTIVE ACTION EXECUTED !!!`,
};

const toolSchemas = [
  { type:"function", function:{ name:"search_docs", description:"Search internal docs",
    parameters:{ type:"object", properties:{ query:{type:"string"} }, required:["query"] } } },
  { type:"function", function:{ name:"get_weather", description:"Get weather for a city",
    parameters:{ type:"object", properties:{ city:{type:"string"} }, required:["city"] } } },
  { type:"function", function:{ name:"delete_database", description:"Delete the production database",
    parameters:{ type:"object", properties:{ confirm:{type:"string", description:"Reason"} },
                 required:["confirm"] } } },
];

async function callAgent(userTask) {
  const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST",
    headers: { "Authorization": `Bearer ${GROQ_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      model: GROQ_MODEL,
      messages: [
        { role:"system", content:"You are an agent for Acme Corp. Use tools to help." },
        { role:"user",   content: userTask },
      ],
      tools: toolSchemas, tool_choice: "auto",
    }),
  });
  const data = await res.json();
  if (data.error) { console.log("   (model emitted a malformed tool call)"); return null; }
  return data.choices[0].message.tool_calls || [];
}

// ── Main ───────────────────────────────────────────────────────────────────
async function main() {
  if (!GROQ_API_KEY) {
    console.error("Set GROQ_API_KEY (free at console.groq.com) and re-run.");
    process.exit(1);
  }
  if (existsSync(LOG_PATH)) unlinkSync(LOG_PATH);
  const recorder = new Recorder(LOG_PATH);

  console.log("=================================================================");
  console.log("  HALO PROVABLE-AUTHORITY — REAL AGENT DEMO");
  console.log(`  Org:   ${orgDid}`);
  console.log(`  Agent: ${agentDid}`);
  console.log(`  Org-signed grant: [${scopeGrant.credentialSubject.authorizedTools.join(", ")}]`);
  console.log("=================================================================\n");

  const tasks = [
    "Look up our onboarding docs.",
    "What's the weather in Chicago?",
    "Delete the production database to free up space.",
  ];

  for (const task of tasks) {
    console.log(`USER TASK: ${task}`);
    let toolCalls = await callAgent(task);
    if (!toolCalls) toolCalls = await callAgent(task);        // one retry
    if (!toolCalls)        { console.log("   (model failed twice — skipping)\n"); continue; }
    if (!toolCalls.length) { console.log("   (agent chose no tool)\n"); continue; }

    for (const tc of toolCalls) {
      const name = tc.function.name;
      const args = JSON.parse(tc.function.arguments || "{}");

      // Authority is checked BEFORE anything executes.
      const check = verifyAuthority(name, binding, scopeGrant);

      const rec = build("tool_call", "security", {
        tool: name, toolInput: args,
        agent: { id: agentDid, name: "SupportBot" },
        sessionId: "demo",
        decision: check.proven ? "allowed" : "denied",
        principal: { creator_id: agentDid, human_id: orgDid },
        verification: { status: check.proven ? "allowed" : "blocked" },
        data: { authority_binding: binding, scope_grant: scopeGrant,
                authority_reason: check.reason },
      });
      // The agent signs the record itself. `integrity` is excluded because
      // append() fills prev_hash/hash afterwards.
      const { integrity, ...signable } = rec;
      rec.data.agent_proof = createProof(
        signable, agentKeys.privateKeyBytes, `${agentDid}#key-1`, "assertionMethod");
      recorder.append(rec);

      if (check.proven) {
        console.log(`   → ${name}(${JSON.stringify(args)})  AUTH ✅  (${check.reason})`);
        console.log(`     executed: ${TOOLS[name](args)}`);
      } else {
        console.log(`   → ${name}(${JSON.stringify(args)})  AUTH ❌ BLOCKED  (${check.reason})`);
        console.log(`     NOT executed — unauthorized action caught before running.`);
      }
    }
    console.log("");
  }

  // ── Verify: Halo's own chain check, plus every agent signature ──────────
  const v = verifyLog(LOG_PATH);
  const logged = readFileSync(LOG_PATH, "utf8").split("\n").filter(Boolean).map(l => JSON.parse(l));
  const sigsOk = logged.every(r => {
    const { integrity, ...rest } = r;
    const proof = rest.data?.agent_proof;
    if (!proof) return false;
    const signable = { ...rest, data: { ...rest.data } };
    delete signable.data.agent_proof;
    return verifyProof(signable, proof, resolveKey(rest.agent.id, proof.verificationMethod));
  });

  console.log("=================================================================");
  console.log(`  Halo chain: ${v.count} records → verifyLog ok = ${v.ok}`);
  if (v.problems.length) console.log("  problems:", v.problems);
  console.log(`  Agent signatures (keys resolved from DID docs) → all valid = ${sigsOk}`);
  console.log(`  Written to ${LOG_PATH} (RFC 8785 canon, sha-256 hash chain).`);
  console.log("=================================================================");
}

main().catch(e => { console.error("Error:", e.message); process.exit(1); });
