import { generateKeyPair, createOrgDid, createAgentDid, createDidDocument,
         createProof, verifyProof } from "@trailprotocol/core";
import { Recorder, build, verifyLog } from "halo-record";
import { existsSync, unlinkSync, readFileSync } from "fs";

const LOG = "/tmp/trail_test/signed.jsonl";
if (existsSync(LOG)) unlinkSync(LOG);

// --- FIX 1: pass publicKeyMultibase (a string), not the keypair object ---
const orgKeys = generateKeyPair();
const orgDid  = createOrgDid("acme.com", orgKeys.publicKeyMultibase);
const orgDoc  = createDidDocument(orgDid, orgKeys);

const agentKeys = generateKeyPair();
const agentDid  = createAgentDid("supportbot.acme.com", agentKeys.publicKeyMultibase);
const agentDoc  = createDidDocument(agentDid, agentKeys);

console.log("Org DID:  ", orgDid);
console.log("Agent DID:", agentDid);
console.log("distinct suffixes:", orgDid.split("-").pop() !== agentDid.split("-").pop());

const recorder = new Recorder(LOG);
const AGENT_VM = `${agentDid}#key-1`;

// --- FIX 2: agent signs each record; proof rides in data.agent_proof ---
function recordSigned(tool, args, decision, reason) {
  const rec = build("tool_call", "security", {
    tool, toolInput: args,
    agent: { id: agentDid, name: "SupportBot" },
    sessionId: "demo",
    decision,
    principal: { creator_id: agentDid, human_id: orgDid },
    verification: { status: decision === "allowed" ? "allowed" : "blocked" },
    data: { authority_reason: reason },
  });
  // sign everything except `integrity` (append() fills prev_hash/hash after)
  const { integrity, ...signable } = rec;
  const proof = createProof(signable, agentKeys.privateKeyBytes, AGENT_VM, "assertionMethod");
  rec.data.agent_proof = proof;
  return recorder.append(rec);
}

function verifyRecordSignature(logged, publicKeyBytes) {
  const { integrity, ...rest } = logged;
  const proof = rest.data?.agent_proof;
  if (!proof) return { ok:false, why:"no agent proof" };
  const signable = { ...rest, data: { ...rest.data } };
  delete signable.data.agent_proof;
  return { ok: verifyProof(signable, proof, publicKeyBytes), why:"signature check" };
}

recordSigned("search_docs", {query:"onboarding"}, "allowed", "authority proven + in scope");
recordSigned("get_weather", {city:"Chicago"}, "allowed", "authority proven + in scope");
recordSigned("delete_database", {confirm:"space"}, "denied", "outside authorized scope");

console.log("\n--- Halo chain ---");
const v = verifyLog(LOG);
console.log("verifyLog ok =", v.ok, "count =", v.count);

console.log("\n--- Per-record agent signatures ---");
const lines = readFileSync(LOG,"utf8").split("\n").filter(Boolean).map(l=>JSON.parse(l));
for (const rec of lines) {
  const r = verifyRecordSignature(rec, agentKeys.publicKeyBytes);
  console.log(`${String(rec.action?.tool ?? rec.tool ?? "?").padEnd(16)} signature valid: ${r.ok}`);
}

console.log("\n--- TAMPER TEST: flip decision on the blocked record ---");
const tampered = JSON.parse(JSON.stringify(lines[2]));
if (tampered.action?.authorization) tampered.action.authorization.decision = "allowed";
console.log("after tampering, signature valid:", verifyRecordSignature(tampered, agentKeys.publicKeyBytes).ok);

console.log("\n--- WRONG KEY TEST ---");
const other = generateKeyPair();
console.log("verified with a different key:", verifyRecordSignature(lines[0], other.publicKeyBytes).ok);
